// Copyright 2024 Stellar-K8s Contributors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Ingestion Worker Pool
//!
//! Producer-consumer worker pool that drains the [`LedgerRingBuffer`] in
//! parallel, processing raw XDR ledger entries in configurable batch sizes.
//!
//! ## Architecture
//!
//! ```text
//!  LedgerRingBuffer
//!       │
//!       ├─► Worker 0 ──► process_batch() ──► operator state
//!       ├─► Worker 1 ──► process_batch() ──► operator state
//!       └─► Worker N ──► process_batch() ──► operator state
//! ```
//!
//! Each worker loop:
//! 1. Collects up to `batch_size` entries from the ring buffer.
//! 2. Hands the batch to the user-supplied [`BatchProcessor`] trait object.
//! 3. Emits structured metrics (throughput, latency, error count).
//!
//! Workers run until the ring buffer is closed and fully drained, then exit
//! cleanly.  The supervisor ([`WorkerPool`]) joins all workers before
//! returning, guaranteeing no ledger entry is silently lost.
//!
//! ## Memory bound
//!
//! Each worker holds at most `batch_size` entries in memory simultaneously.
//! With `workers=4` and `batch_size=64` the pool adds ~1 MiB overhead beyond
//! the ring buffer itself.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use super::buffer::{LedgerEntry, LedgerRingBuffer};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced during batch processing.
#[derive(Debug, Error)]
pub enum WorkerError {
    /// The batch processor returned an application-level error.
    #[error("batch processing failed: {0}")]
    ProcessingFailed(String),

    /// A worker task panicked.
    #[error("worker task panicked")]
    WorkerPanic,
}

// ---------------------------------------------------------------------------
// Batch processor trait
// ---------------------------------------------------------------------------

/// Processes a batch of ledger entries.
///
/// Implementors perform the actual parsing, state updates, and downstream
/// notification.  The trait is `async` so processors can perform I/O
/// (e.g., writing to the operator's database) without blocking the runtime.
#[async_trait]
pub trait BatchProcessor: Send + Sync {
    /// Process `batch` of raw ledger entries.
    ///
    /// Returns `Ok(processed_count)` on success, or an error that will be
    /// logged and counted against the worker's error metric.
    async fn process(&self, batch: Vec<LedgerEntry>) -> Result<usize, WorkerError>;
}

/// No-op processor that simply discards entries (useful for benchmarking
/// ring buffer throughput without processing overhead).
pub struct NullProcessor;

#[async_trait]
impl BatchProcessor for NullProcessor {
    async fn process(&self, batch: Vec<LedgerEntry>) -> Result<usize, WorkerError> {
        Ok(batch.len())
    }
}

/// Recording processor that collects processed entries for test assertions.
pub struct RecordingProcessor {
    pub processed: tokio::sync::Mutex<Vec<LedgerEntry>>,
}

impl RecordingProcessor {
    pub fn new() -> Self {
        Self {
            processed: tokio::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Default for RecordingProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BatchProcessor for RecordingProcessor {
    async fn process(&self, batch: Vec<LedgerEntry>) -> Result<usize, WorkerError> {
        let count = batch.len();
        self.processed.lock().await.extend(batch);
        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Worker configuration
// ---------------------------------------------------------------------------

/// Configuration for a [`WorkerPool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerPoolConfig {
    /// Number of concurrent consumer workers.
    pub worker_count: usize,
    /// Maximum number of entries consumed per worker per iteration.
    pub batch_size: usize,
    /// How long a worker waits for new entries before polling again.
    /// Prevents tight spin-loops when the buffer is momentarily empty.
    pub idle_poll_interval: Duration,
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        Self {
            worker_count: 4,
            batch_size: 64,
            idle_poll_interval: Duration::from_millis(10),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-worker metrics
// ---------------------------------------------------------------------------

/// Cumulative metrics for a single worker.
#[derive(Debug, Clone, Default)]
pub struct WorkerMetrics {
    pub worker_id: usize,
    pub batches_processed: u64,
    pub entries_processed: u64,
    pub errors: u64,
    pub total_processing_time_ms: u64,
}

impl WorkerMetrics {
    /// Average batch processing time in milliseconds.
    pub fn avg_batch_time_ms(&self) -> f64 {
        if self.batches_processed == 0 {
            return 0.0;
        }
        self.total_processing_time_ms as f64 / self.batches_processed as f64
    }
}

// ---------------------------------------------------------------------------
// Worker pool
// ---------------------------------------------------------------------------

/// Supervisor that spawns and joins a pool of consumer workers.
pub struct WorkerPool {
    config: WorkerPoolConfig,
    buffer: LedgerRingBuffer,
    processor: Arc<dyn BatchProcessor>,
}

impl WorkerPool {
    /// Create a new pool.
    pub fn new(
        config: WorkerPoolConfig,
        buffer: LedgerRingBuffer,
        processor: Arc<dyn BatchProcessor>,
    ) -> Self {
        Self {
            config,
            buffer,
            processor,
        }
    }

    /// Spawn all workers and return their [`JoinHandle`]s.
    ///
    /// Workers run until the ring buffer is closed and empty.
    pub fn spawn(&self) -> Vec<JoinHandle<WorkerMetrics>> {
        info!(
            worker_count = self.config.worker_count,
            batch_size = self.config.batch_size,
            "Starting ingestion worker pool"
        );

        (0..self.config.worker_count)
            .map(|id| {
                let buffer = self.buffer.clone();
                let processor = self.processor.clone();
                let config = self.config.clone();

                tokio::spawn(async move { run_worker(id, buffer, processor, config).await })
            })
            .collect()
    }

    /// Spawn all workers and await them all to completion.
    ///
    /// Returns per-worker metrics.
    pub async fn run_to_completion(self) -> Vec<WorkerMetrics> {
        let handles = self.spawn();
        let mut metrics = Vec::with_capacity(handles.len());

        for handle in handles {
            match handle.await {
                Ok(m) => metrics.push(m),
                Err(_) => {
                    error!("Worker task panicked");
                    metrics.push(WorkerMetrics::default());
                }
            }
        }

        metrics
    }
}

// ---------------------------------------------------------------------------
// Worker loop
// ---------------------------------------------------------------------------

async fn run_worker(
    id: usize,
    buffer: LedgerRingBuffer,
    processor: Arc<dyn BatchProcessor>,
    config: WorkerPoolConfig,
) -> WorkerMetrics {
    let mut metrics = WorkerMetrics {
        worker_id: id,
        ..Default::default()
    };

    info!(worker_id = id, "Ingestion worker started");

    loop {
        // Collect a batch.
        let mut batch = Vec::with_capacity(config.batch_size);

        // First pop: block until an entry or buffer close.
        match buffer.pop().await {
            Some(entry) => batch.push(entry),
            None => {
                // Buffer closed and drained.
                info!(worker_id = id, "Buffer closed; worker exiting");
                break;
            }
        }

        // Drain up to batch_size - 1 additional entries without waiting.
        while batch.len() < config.batch_size {
            if buffer.is_empty().await {
                break;
            }
            // Non-blocking best-effort drain.
            match tokio::time::timeout(Duration::from_nanos(1), buffer.pop()).await {
                Ok(Some(e)) => batch.push(e),
                _ => break,
            }
        }

        if batch.is_empty() {
            tokio::time::sleep(config.idle_poll_interval).await;
            continue;
        }

        debug!(worker_id = id, batch_len = batch.len(), "Processing ledger batch");

        let start = Instant::now();
        match processor.process(batch).await {
            Ok(count) => {
                let elapsed = start.elapsed().as_millis() as u64;
                metrics.batches_processed += 1;
                metrics.entries_processed += count as u64;
                metrics.total_processing_time_ms += elapsed;
            }
            Err(e) => {
                metrics.errors += 1;
                warn!(worker_id = id, error = %e, "Batch processing error");
            }
        }
    }

    info!(
        worker_id = id,
        entries_processed = metrics.entries_processed,
        batches_processed = metrics.batches_processed,
        errors = metrics.errors,
        "Ingestion worker finished"
    );
    metrics
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::ingestion::buffer::{BackpressureStrategy, RingBufferConfig};

    fn make_entry(seq: u64) -> LedgerEntry {
        LedgerEntry::new(seq, vec![0u8; 64])
    }

    fn make_pool(
        worker_count: usize,
        batch_size: usize,
        buffer: LedgerRingBuffer,
        processor: Arc<dyn BatchProcessor>,
    ) -> WorkerPool {
        WorkerPool::new(
            WorkerPoolConfig {
                worker_count,
                batch_size,
                idle_poll_interval: Duration::from_millis(1),
            },
            buffer,
            processor,
        )
    }

    #[test]
    fn test_worker_metrics_avg_batch_time_zero_when_no_batches() {
        let m = WorkerMetrics::default();
        assert_eq!(m.avg_batch_time_ms(), 0.0);
    }

    #[test]
    fn test_worker_pool_config_defaults() {
        let cfg = WorkerPoolConfig::default();
        assert_eq!(cfg.worker_count, 4);
        assert_eq!(cfg.batch_size, 64);
    }

    #[tokio::test]
    async fn test_null_processor_processes_all_entries() {
        let buf = LedgerRingBuffer::new(RingBufferConfig {
            capacity: 100,
            backpressure: BackpressureStrategy::DropOldest,
            ..Default::default()
        });

        for i in 1u64..=20 {
            buf.push(make_entry(i)).await.unwrap();
        }
        buf.close().await;

        let pool = make_pool(2, 8, buf, Arc::new(NullProcessor));
        let metrics = pool.run_to_completion().await;

        let total: u64 = metrics.iter().map(|m| m.entries_processed).sum();
        assert_eq!(total, 20, "all 20 entries must be processed");
    }

    #[tokio::test]
    async fn test_recording_processor_captures_all_entries() {
        let buf = LedgerRingBuffer::new(RingBufferConfig {
            capacity: 100,
            backpressure: BackpressureStrategy::DropOldest,
            ..Default::default()
        });

        for i in 1u64..=10 {
            buf.push(make_entry(i)).await.unwrap();
        }
        buf.close().await;

        let rec = Arc::new(RecordingProcessor::new());
        let pool = make_pool(1, 4, buf, rec.clone());
        pool.run_to_completion().await;

        let processed = rec.processed.lock().await;
        assert_eq!(processed.len(), 10, "all 10 entries should be recorded");

        let mut seqs: Vec<u64> = processed.iter().map(|e| e.sequence).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, (1u64..=10).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn test_multiple_workers_share_load() {
        let buf = LedgerRingBuffer::new(RingBufferConfig {
            capacity: 200,
            backpressure: BackpressureStrategy::DropOldest,
            ..Default::default()
        });

        for i in 1u64..=100 {
            buf.push(make_entry(i)).await.unwrap();
        }
        buf.close().await;

        let pool = make_pool(4, 10, buf, Arc::new(NullProcessor));
        let metrics = pool.run_to_completion().await;

        let total: u64 = metrics.iter().map(|m| m.entries_processed).sum();
        assert_eq!(total, 100);
        // All 4 workers should have been instantiated.
        assert_eq!(metrics.len(), 4);
    }

    #[tokio::test]
    async fn test_worker_exits_cleanly_on_empty_closed_buffer() {
        let buf = LedgerRingBuffer::new(RingBufferConfig {
            capacity: 10,
            backpressure: BackpressureStrategy::Error,
            ..Default::default()
        });
        buf.close().await;

        let pool = make_pool(2, 8, buf, Arc::new(NullProcessor));
        let metrics = pool.run_to_completion().await;
        // No entries; each worker should have processed 0.
        for m in &metrics {
            assert_eq!(m.entries_processed, 0);
        }
    }
}
