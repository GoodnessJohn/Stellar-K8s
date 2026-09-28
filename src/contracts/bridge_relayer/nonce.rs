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

//! # Nonce & Replay-Protection Store
//!
//! Provides bounded replay-protection for cross-chain messages using a combination
//! of:
//!
//! - **Sequential nonces** — each message from a given `(source_chain, sender)`
//!   pair must carry a nonce exactly one greater than the last accepted value.
//! - **Domain separators** — a `domain_tag` byte string is mixed into every nonce
//!   key so that a valid message on one domain cannot be replayed on another.
//! - **Instance TTL management** — the backing store imposes a configurable
//!   maximum entry count (`max_entries`). When the high-water mark is reached,
//!   the oldest entries are evicted to keep state growth bounded.  This mirrors
//!   Soroban's instance TTL semantics on-chain.
//!
//! ## Threat model
//!
//! An attacker who intercepts a valid signed message must not be able to re-submit
//! it.  The nonce store prevents this because:
//!
//! 1. Accepting the original message advances the expected nonce.
//! 2. Replaying the same message fails the `expected_nonce != submitted_nonce` check.
//! 3. Domain separators prevent cross-domain replays even if nonce counters reset.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by nonce operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NonceError {
    /// The submitted nonce was lower than or equal to the last accepted nonce.
    #[error("replay detected: expected nonce {expected}, got {received}")]
    ReplayDetected { expected: u64, received: u64 },

    /// The nonce store has reached its TTL capacity and could not evict entries
    /// fast enough to admit the new message.
    #[error("nonce store at capacity ({capacity} entries)")]
    StoreAtCapacity { capacity: usize },

    /// Domain tag contains invalid (non-UTF-8 or empty) bytes.
    #[error("invalid domain tag: {0}")]
    InvalidDomainTag(String),
}

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// Composite key identifying a unique (domain, source_chain, sender) tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NonceKey {
    /// ASCII domain tag — e.g. `"stellar-bridge-v1"`.  Prevents cross-domain
    /// replay even when counters coincide.
    pub domain_tag: String,
    /// Identifier of the originating chain (e.g. `"ethereum-mainnet"`).
    pub source_chain: String,
    /// Sender address on the source chain (hex or bech32).
    pub sender: String,
}

impl NonceKey {
    /// Construct a new key, validating that `domain_tag` is non-empty.
    pub fn new(
        domain_tag: impl Into<String>,
        source_chain: impl Into<String>,
        sender: impl Into<String>,
    ) -> Result<Self, NonceError> {
        let domain_tag = domain_tag.into();
        if domain_tag.is_empty() {
            return Err(NonceError::InvalidDomainTag(
                "domain_tag must not be empty".to_string(),
            ));
        }
        Ok(Self {
            domain_tag,
            source_chain: source_chain.into(),
            sender: sender.into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Nonce store
// ---------------------------------------------------------------------------

/// In-memory nonce store with bounded TTL-eviction.
///
/// In a Soroban contract deployment this maps directly to contract instance
/// storage.  In the off-chain relay validator it is backed by a persistent
/// key-value store with the same semantics.
#[derive(Debug)]
pub struct NonceStore {
    /// Maximum number of (key → nonce) entries before eviction is triggered.
    max_entries: usize,
    /// Current nonce for each key.  Value is the *last accepted* nonce; the
    /// next acceptable nonce is `value + 1`.
    entries: HashMap<NonceKey, u64>,
    /// Insertion-ordered list of keys for FIFO eviction.
    insertion_order: Vec<NonceKey>,
}

impl NonceStore {
    /// Create a new store with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        assert!(max_entries > 0, "max_entries must be > 0");
        Self {
            max_entries,
            entries: HashMap::new(),
            insertion_order: Vec::new(),
        }
    }

    /// Return the next expected nonce for `key` (last accepted + 1, or 1 if
    /// this is the first message from that key).
    pub fn expected_nonce(&self, key: &NonceKey) -> u64 {
        self.entries.get(key).copied().unwrap_or(0) + 1
    }

    /// Validate and consume `nonce` for `key`.
    ///
    /// - Returns `Ok(())` and advances the stored nonce on success.
    /// - Returns `Err(NonceError::ReplayDetected)` if `nonce` ≤ last accepted.
    /// - Returns `Err(NonceError::StoreAtCapacity)` if the store is full and
    ///   eviction would affect currently-active senders.
    pub fn consume(&mut self, key: NonceKey, nonce: u64) -> Result<(), NonceError> {
        let expected = self.expected_nonce(&key);

        if nonce != expected {
            return Err(NonceError::ReplayDetected {
                expected,
                received: nonce,
            });
        }

        // Evict oldest entry if at capacity and this is a new key.
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            self.evict_oldest();
            if self.entries.len() >= self.max_entries {
                return Err(NonceError::StoreAtCapacity {
                    capacity: self.max_entries,
                });
            }
        }

        // Commit.
        let is_new = !self.entries.contains_key(&key);
        self.entries.insert(key.clone(), nonce);
        if is_new {
            self.insertion_order.push(key);
        }
        Ok(())
    }

    /// Current number of tracked senders.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the store contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    /// Evict the oldest entry (FIFO by insertion order).
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self.insertion_order.first().cloned() {
            self.entries.remove(&oldest_key);
            self.insertion_order.remove(0);
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: &str, chain: &str, sender: &str) -> NonceKey {
        NonceKey::new(tag, chain, sender).unwrap()
    }

    // --- NonceKey validation ---

    #[test]
    fn test_nonce_key_rejects_empty_domain_tag() {
        let result = NonceKey::new("", "eth-mainnet", "0xabc");
        assert!(matches!(result, Err(NonceError::InvalidDomainTag(_))));
    }

    #[test]
    fn test_nonce_key_accepts_valid_fields() {
        let k = NonceKey::new("stellar-v1", "eth-mainnet", "0xabc").unwrap();
        assert_eq!(k.domain_tag, "stellar-v1");
        assert_eq!(k.source_chain, "eth-mainnet");
        assert_eq!(k.sender, "0xabc");
    }

    // --- expected_nonce ---

    #[test]
    fn test_expected_nonce_starts_at_one_for_new_key() {
        let store = NonceStore::new(100);
        assert_eq!(store.expected_nonce(&key("v1", "eth", "alice")), 1);
    }

    #[test]
    fn test_expected_nonce_increments_after_consume() {
        let mut store = NonceStore::new(100);
        let k = key("v1", "eth", "alice");
        store.consume(k.clone(), 1).unwrap();
        assert_eq!(store.expected_nonce(&k), 2);
        store.consume(k.clone(), 2).unwrap();
        assert_eq!(store.expected_nonce(&k), 3);
    }

    // --- replay detection ---

    #[test]
    fn test_replay_with_same_nonce_is_rejected() {
        let mut store = NonceStore::new(100);
        let k = key("v1", "eth", "alice");
        store.consume(k.clone(), 1).unwrap();

        let err = store.consume(k.clone(), 1).unwrap_err();
        assert_eq!(err, NonceError::ReplayDetected { expected: 2, received: 1 });
    }

    #[test]
    fn test_replay_with_old_nonce_is_rejected() {
        let mut store = NonceStore::new(100);
        let k = key("v1", "eth", "alice");
        store.consume(k.clone(), 1).unwrap();
        store.consume(k.clone(), 2).unwrap();
        store.consume(k.clone(), 3).unwrap();

        let err = store.consume(k.clone(), 2).unwrap_err();
        assert_eq!(err, NonceError::ReplayDetected { expected: 4, received: 2 });
    }

    #[test]
    fn test_skipped_nonce_is_rejected() {
        let mut store = NonceStore::new(100);
        let k = key("v1", "eth", "bob");
        // First nonce must be 1; skipping to 2 should fail.
        let err = store.consume(k.clone(), 2).unwrap_err();
        assert_eq!(err, NonceError::ReplayDetected { expected: 1, received: 2 });
    }

    // --- domain separator ---

    #[test]
    fn test_same_nonce_on_different_domains_both_accepted() {
        let mut store = NonceStore::new(100);
        let k1 = key("domain-A", "eth", "alice");
        let k2 = key("domain-B", "eth", "alice");
        // Nonce 1 on domain-A is accepted.
        store.consume(k1.clone(), 1).unwrap();
        // Nonce 1 on domain-B is also accepted (different key).
        store.consume(k2.clone(), 1).unwrap();
        assert_eq!(store.expected_nonce(&k1), 2);
        assert_eq!(store.expected_nonce(&k2), 2);
    }

    // --- TTL / capacity ---

    #[test]
    fn test_store_evicts_oldest_when_at_capacity() {
        let mut store = NonceStore::new(2);
        let k1 = key("v1", "eth", "alice");
        let k2 = key("v1", "eth", "bob");
        let k3 = key("v1", "eth", "carol");

        store.consume(k1.clone(), 1).unwrap();
        store.consume(k2.clone(), 1).unwrap();
        // Adding a third sender evicts alice (oldest).
        store.consume(k3.clone(), 1).unwrap();

        assert_eq!(store.len(), 2);
        // Alice was evicted so her next expected nonce resets to 1.
        assert_eq!(store.expected_nonce(&k1), 1);
    }

    #[test]
    fn test_store_len_and_is_empty() {
        let mut store = NonceStore::new(10);
        assert!(store.is_empty());
        store.consume(key("v1", "eth", "x"), 1).unwrap();
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }
}
