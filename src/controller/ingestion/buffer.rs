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

//! # XDR Ledger Stream Ring Buffer
//!
//! High-performance, bounded ring buffer that decouples Stellar Core XDR
//! ingestion from the operator reconciliation thread.
//!
//! ## Design
//!
//! ```text
//!  Stellar Core ──XDR──► [producer] ──► RingBuffer ──► [consumer pool]
//!                                           │
//!                                  capacity limit
//!                                  backpressure strategy
//! ```
//!
//! The ring buffer holds raw [`LedgerEntry`] frames.  When the buffer is full
//! the configured [`BackpressureStrategy`] decides whether to block the
//! producer, drop the oldest entry (circular overwrite), or error out.
//!
//! ## Memory bound
//!
//! `capacity * avg_entry_size_bytes` is the worst-case RSS contribution.
//! The default capacity of 8 192 entries × ~4 KiB each ≈ 32 MiB, well within
//! a typical Stellar node pod's memory budget and safe during historical
//! catch-up when ledger bursts arrive faster than workers can process them.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default ring buffer capacity (number of ledger entries).
pub const DEFAULT_BUFFER_CAPACITY: usize = 8_192;

/// Default producer block timeout when the buffer is full and strategy is
/// [`BackpressureStrategy::Block`].
pub const DEFAULT_BLOCK_TIMEOUT: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced by ring buffer operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BufferError {
    /// Buffer is full and the backpressure strategy is `Error`.
    #[error("ring buffer full at capacity {capacity}")]
    BufferFull { capacity: usize },

    /// Producer timed out waiting for space while strategy is `Block`.
    #[error("producer timed out waiting for buffer space after {millis}ms")]
    ProducerTimeout { millis: u64 },

    /// Buffer has been closed; no further writes are accepted.
    #[error("ring buffer is closed")]
    Closed,
}

// ---------------------------------------------------------------------------
// Backpressure strategy
// ---------------------------------------------------------------------------

/// Governs what happens when the ring buffer reaches its capacity limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackpressureStrategy {
    /// Block the producer until a consumer drains at least one slot.
    /// A configurable timeout prevents indefinite stalls.
    Block,
    /// Drop the oldest (head) entry and overwrite with the new one.
    /// Useful for real-time ingestion where stale ledgers are less
    /// valuable than current ones.
    DropOldest,
    /// Return [`BufferError::BufferFull`] immediately so the caller can
    /// apply its own flow-control logic.
    Error,
}

// ---------------------------------------------------------------------------
// Ledger entry
// ---------------------------------------------------------------------------

/// Raw XDR ledger entry as received from Stellar Core.
///
/// In production, `xdr_bytes` is the wire-format XDR blob; downstream workers
/// parse it into typed structures.  Keeping the buffer at the raw-bytes layer
/// means deserialization cost is distributed across the worker pool rather
/// than serialised on the ingestion path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Stellar ledger sequence number.
    pub sequence: u64,
    /// Raw XDR-encoded ledger close meta bytes.
    pub xdr_bytes: Vec<u8>,
    /// Approximate byte size of this entry (used for memory metrics).
    pub byte_size: usize,
}

impl LedgerEntry {
    /// Construct a new entry, automatically computing `byte_size`.
    pub fn new(sequence: u64, xdr_bytes: Vec<u8>) -> Self {
        let byte_size = xdr_bytes.len();
        Self {
            sequence,
            xdr_bytes,
            byte_size,
        }
    }
}

// ---------------------------------------------------------------------------
// Ring buffer metrics
// ---------------------------------------------------------------------------

/// Snapshot of ring buffer metrics at a point in time.
#[derive(Debug, Clone, Default)]
pub struct BufferMetrics {
    /// Current number of entries in the buffer.
    pub current_len: usize,
    /// Buffer capacity.
    pub capacity: usize,
    /// Total entries produced since creation.
    pub total_produced: u64,
    /// Total entries consumed since creation.
    pub total_consumed: u64,
    /// Total entries dropped (DropOldest strategy) since creation.
    pub total_dropped: u64,
    /// Total bytes currently buffered.
    pub buffered_bytes: usize,
}

impl BufferMetrics {
    /// Fill percentage as a float in [0.0, 1.0].
    pub fn fill_ratio(&self) -> f64 {
        if self.capacity == 0 {
            return 0.0;
        }
        self.current_len as f64 / self.capacity as f64
    }
}

// ---------------------------------------------------------------------------
// Ring buffer inner state
// ---------------------------------------------------------------------------

struct BufferInner {
    queue: VecDeque<LedgerEntry>,
    capacity: usize,
    closed: bool,
    total_produced: u64,
    total_consumed: u64,
    total_dropped: u64,
    buffered_bytes: usize,
}

impl BufferInner {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
            closed: false,
            total_produced: 0,
            total_consumed: 0,
            total_dropped: 0,
            buffered_bytes: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.queue.len() >= self.capacity
    }

    fn push(&mut self, entry: LedgerEntry) -> Result<(), BufferError> {
        if self.closed {
            return Err(BufferError::Closed);
        }
        if self.is_full() {
            // Handled by caller based on strategy; this path is for DropOldest.
            if let Some(evicted) = self.queue.pop_front() {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(evicted.byte_size);
                self.total_dropped += 1;
                warn!(
                    evicted_seq = evicted.sequence,
                    "Ring buffer full; dropping oldest entry"
                );
            }
        }
        self.buffered_bytes += entry.byte_size;
        self.queue.push_back(entry);
        self.total_produced += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<LedgerEntry> {
        let entry = self.queue.pop_front()?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(entry.byte_size);
        self.total_consumed += 1;
        Some(entry)
    }

    fn metrics(&self) -> BufferMetrics {
        BufferMetrics {
            current_len: self.queue.len(),
            capacity: self.capacity,
            total_produced: self.total_produced,
            total_consumed: self.total_consumed,
            total_dropped: self.total_dropped,
            buffered_bytes: self.buffered_bytes,
        }
    }
}

// ---------------------------------------------------------------------------
// Public ring buffer handle
// ---------------------------------------------------------------------------

/// Configuration for [`LedgerRingBuffer`].
#[derive(Debug, Clone)]
pub struct RingBufferConfig {
    /// Maximum number of [`LedgerEntry`] items held in memory.
    pub capacity: usize,
    /// What to do when the buffer is full.
    pub backpressure: BackpressureStrategy,
    /// Timeout for the [`BackpressureStrategy::Block`] strategy.
    pub block_timeout: Duration,
}

impl Default for RingBufferConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_BUFFER_CAPACITY,
            backpressure: BackpressureStrategy::DropOldest,
            block_timeout: DEFAULT_BLOCK_TIMEOUT,
        }
    }
}

/// Bounded, async ring buffer for raw XDR ledger entries.
///
/// Clone-able handle — all clones share the same underlying buffer.
#[derive(Clone)]
pub struct LedgerRingBuffer {
    inner: Arc<Mutex<BufferInner>>,
    /// Notifies consumers when a new entry is available.
    consumer_notify: Arc<Notify>,
    /// Notifies producers when a slot becomes free (Block strategy).
    producer_notify: Arc<Notify>,
    config: RingBufferConfig,
}

impl LedgerRingBuffer {
    /// Create a new buffer with the given configuration.
    pub fn new(config: RingBufferConfig) -> Self {
        let inner = BufferInner::new(config.capacity);
        Self {
            inner: Arc::new(Mutex::new(inner)),
            consumer_notify: Arc::new(Notify::new()),
            producer_notify: Arc::new(Notify::new()),
            config,
        }
    }

    /// Create a buffer with default settings.
    pub fn with_defaults() -> Self {
        Self::new(RingBufferConfig::default())
    }

    /// Push a [`LedgerEntry`] into the buffer.
    ///
    /// Behaviour when full depends on [`RingBufferConfig::backpressure`]:
    /// - `DropOldest`: evicts head entry, always succeeds.
    /// - `Block`: awaits a free slot up to `block_timeout`.
    /// - `Error`: returns [`BufferError::BufferFull`] immediately.
    pub async fn push(&self, entry: LedgerEntry) -> Result<(), BufferError> {
        match self.config.backpressure {
            BackpressureStrategy::DropOldest => {
                let mut inner = self.inner.lock().await;
                inner.push(entry)?;
                self.consumer_notify.notify_one();
                Ok(())
            }
            BackpressureStrategy::Error => {
                let mut inner = self.inner.lock().await;
                if inner.is_full() {
                    return Err(BufferError::BufferFull {
                        capacity: self.config.capacity,
                    });
                }
                inner.push(entry)?;
                self.consumer_notify.notify_one();
                Ok(())
            }
            BackpressureStrategy::Block => {
                let deadline = self.config.block_timeout;
                let result = timeout(deadline, self.push_blocking(entry)).await;
                match result {
                    Ok(inner_result) => inner_result,
                    Err(_elapsed) => Err(BufferError::ProducerTimeout {
                        millis: deadline.as_millis() as u64,
                    }),
                }
            }
        }
    }

    /// Pop the next [`LedgerEntry`] from the buffer, waiting until one is
    /// available or the buffer is closed.
    ///
    /// Returns `None` when the buffer is closed and drained.
    pub async fn pop(&self) -> Option<LedgerEntry> {
        loop {
            {
                let mut inner = self.inner.lock().await;
                if let Some(entry) = inner.pop() {
                    self.producer_notify.notify_one();
                    debug!(seq = entry.sequence, "Consumed ledger entry from ring buffer");
                    return Some(entry);
                }
                if inner.closed {
                    return None;
                }
            }
            // Wait for a notification from a producer.
            self.consumer_notify.notified().await;
        }
    }

    /// Signal that no more entries will be produced.
    ///
    /// Consumers will drain remaining entries then see `None` from [`pop`].
    pub async fn close(&self) {
        let mut inner = self.inner.lock().await;
        inner.closed = true;
        // Wake all waiting consumers so they can observe the closed state.
        self.consumer_notify.notify_waiters();
    }

    /// Return a metrics snapshot without blocking the buffer.
    pub async fn metrics(&self) -> BufferMetrics {
        self.inner.lock().await.metrics()
    }

    /// Current number of buffered entries.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.queue.len()
    }

    /// True if the buffer contains no entries.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.queue.is_empty()
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    /// Block-strategy push: spin-wait on producer_notify until a free slot.
    async fn push_blocking(&self, entry: LedgerEntry) -> Result<(), BufferError> {
        loop {
            let mut inner = self.inner.lock().await;
            if inner.closed {
                return Err(BufferError::Closed);
            }
            if !inner.is_full() {
                inner.push(entry)?;
                self.consumer_notify.notify_one();
                return Ok(());
            }
            drop(inner);
            self.producer_notify.notified().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u64) -> LedgerEntry {
        LedgerEntry::new(seq, vec![seq as u8; 128])
    }

    // --- LedgerEntry ---

    #[test]
    fn test_ledger_entry_byte_size_auto_computed() {
        let e = LedgerEntry::new(42, vec![0u8; 256]);
        assert_eq!(e.byte_size, 256);
        assert_eq!(e.sequence, 42);
    }

    // --- DropOldest strategy ---

    #[tokio::test]
    async fn test_drop_oldest_evicts_head_when_full() {
        let buf = LedgerRingBuffer::new(RingBufferConfig {
            capacity: 3,
            backpressure: BackpressureStrategy::DropOldest,
            ..Default::default()
        });

        buf.push(entry(1)).await.unwrap();
        buf.push(entry(2)).await.unwrap();
        buf.push(entry(3)).await.unwrap();
        // Buffer full → entry(1) evicted.
        buf.push(entry(4)).await.unwrap();

        let m = buf.metrics().await;
        assert_eq!(m.current_len, 3);
        assert_eq!(m.total_dropped, 1);

        let first_out = buf.pop().await.unwrap();
        assert_eq!(first_out.sequence, 2, "oldest surviving entry should be seq=2");
    }

    // --- Error strategy ---

    #[tokio::test]
    async fn test_error_strategy_returns_full_error() {
        let buf = LedgerRingBuffer::new(RingBufferConfig {
            capacity: 2,
            backpressure: BackpressureStrategy::Error,
            ..Default::default()
        });

        buf.push(entry(1)).await.unwrap();
        buf.push(entry(2)).await.unwrap();
        let err = buf.push(entry(3)).await.unwrap_err();
        assert_eq!(err, BufferError::BufferFull { capacity: 2 });
    }

    // --- Block strategy ---

    #[tokio::test]
    async fn test_block_strategy_times_out_when_full_and_no_consumer() {
        let buf = LedgerRingBuffer::new(RingBufferConfig {
            capacity: 1,
            backpressure: BackpressureStrategy::Block,
            block_timeout: Duration::from_millis(50),
        });

        buf.push(entry(1)).await.unwrap();
        let err = buf.push(entry(2)).await.unwrap_err();
        assert!(matches!(err, BufferError::ProducerTimeout { .. }));
    }

    #[tokio::test]
    async fn test_block_strategy_unblocks_when_consumer_pops() {
        let buf = LedgerRingBuffer::new(RingBufferConfig {
            capacity: 1,
            backpressure: BackpressureStrategy::Block,
            block_timeout: Duration::from_millis(500),
        });

        buf.push(entry(1)).await.unwrap();

        let buf_clone = buf.clone();
        let producer = tokio::spawn(async move {
            buf_clone.push(entry(2)).await
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        // Consumer pops, freeing a slot for the blocked producer.
        let popped = buf.pop().await.unwrap();
        assert_eq!(popped.sequence, 1);

        producer.await.unwrap().unwrap();
    }

    // --- Close ---

    #[tokio::test]
    async fn test_pop_returns_none_after_close_and_drain() {
        let buf = LedgerRingBuffer::with_defaults();
        buf.push(entry(1)).await.unwrap();
        buf.close().await;

        // Drain remaining entry.
        let e = buf.pop().await;
        assert_eq!(e.unwrap().sequence, 1);
        // Buffer is closed and empty → None.
        assert!(buf.pop().await.is_none());
    }

    // --- Metrics ---

    #[tokio::test]
    async fn test_metrics_track_produce_consume_counts() {
        let buf = LedgerRingBuffer::new(RingBufferConfig {
            capacity: 10,
            backpressure: BackpressureStrategy::DropOldest,
            ..Default::default()
        });

        for i in 1u64..=5 {
            buf.push(entry(i)).await.unwrap();
        }
        buf.pop().await;
        buf.pop().await;

        let m = buf.metrics().await;
        assert_eq!(m.total_produced, 5);
        assert_eq!(m.total_consumed, 2);
        assert_eq!(m.current_len, 3);
        assert_eq!(m.total_dropped, 0);
    }

    #[tokio::test]
    async fn test_fill_ratio_is_correct() {
        let buf = LedgerRingBuffer::new(RingBufferConfig {
            capacity: 4,
            backpressure: BackpressureStrategy::Error,
            ..Default::default()
        });
        buf.push(entry(1)).await.unwrap();
        buf.push(entry(2)).await.unwrap();
        let m = buf.metrics().await;
        assert!((m.fill_ratio() - 0.5).abs() < f64::EPSILON);
    }
}
