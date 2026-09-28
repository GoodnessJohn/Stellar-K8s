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

//! # Stellar Core Ingestion — Ring Buffer & Stream Manager
//!
//! Async ingestion subsystem that decouples raw XDR ledger stream parsing from
//! operator state reconciliation.
//!
//! ## Modules
//!
//! - [`buffer`] — bounded ring buffer with configurable backpressure strategies.
//! - [`worker`] — producer-consumer worker pool that processes batches from the buffer.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use stellar_k8s::controller::ingestion::{
//!     buffer::{LedgerRingBuffer, RingBufferConfig, BackpressureStrategy},
//!     worker::{WorkerPool, WorkerPoolConfig, NullProcessor},
//! };
//!
//! let buf = LedgerRingBuffer::new(RingBufferConfig {
//!     capacity: 8_192,
//!     backpressure: BackpressureStrategy::DropOldest,
//!     ..Default::default()
//! });
//!
//! // Spawn workers.
//! let pool = WorkerPool::new(
//!     WorkerPoolConfig::default(),
//!     buf.clone(),
//!     Arc::new(NullProcessor),
//! );
//! tokio::spawn(pool.run_to_completion());
//!
//! // Push ledger entries from the Stellar Core XDR stream.
//! buf.push(LedgerEntry::new(1, xdr_bytes)).await?;
//! ```

pub mod buffer;
pub mod worker;

pub use buffer::{
    BackpressureStrategy, BufferError, BufferMetrics, LedgerEntry, LedgerRingBuffer,
    RingBufferConfig, DEFAULT_BUFFER_CAPACITY,
};
pub use worker::{
    BatchProcessor, NullProcessor, RecordingProcessor, WorkerError, WorkerMetrics, WorkerPool,
    WorkerPoolConfig,
};
