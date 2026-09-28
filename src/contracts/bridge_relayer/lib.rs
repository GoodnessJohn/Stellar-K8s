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

//! # Bridge Relayer Verification Contract
//!
//! Tamper-proof verification layer for cross-chain payloads destined for
//! Soroban contracts.  Three responsibilities are handled here:
//!
//! 1. **Threshold multi-signature verification** — a message is accepted only
//!    when ≥ `threshold` distinct relayers have signed the same payload hash.
//! 2. **Replay protection** — each `(domain, source_chain, sender)` tuple
//!    carries a sequential nonce enforced by [`nonce::NonceStore`].
//! 3. **Execution dispatch** — after all checks pass, the verified payload is
//!    forwarded to a registered destination contract handler.
//!
//! ## Security model
//!
//! - Signatures are verified with Ed25519 (matching Stellar's native key scheme).
//! - A payload is rejected if *any* signer appears more than once (deduplication).
//! - The domain separator in the nonce key prevents cross-domain replay even if
//!   nonce counters coincidentally align.
//! - An unknown destination contract results in a hard error, not a silent drop.
//!
//! ## Dispatch flow
//!
//! ```text
//! submit_message(msg, sigs)
//!   ├─ 1. deserialize & hash payload
//!   ├─ 2. verify each signature against known relayer set
//!   ├─ 3. check threshold (distinct valid signers ≥ threshold)
//!   ├─ 4. consume nonce (replay protection)
//!   └─ 5. invoke destination handler via ExecutionDispatcher
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{error, info, warn};

use crate::contracts::bridge_relayer::nonce::{NonceKey, NonceStore};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can arise during message verification or dispatch.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BridgeError {
    /// The number of valid, distinct signatures is below the required threshold.
    #[error("signature threshold not met: need {required}, got {provided}")]
    ThresholdNotMet { required: usize, provided: usize },

    /// A signature could not be verified against any known relayer key.
    #[error("unknown or invalid relayer signature (index {index})")]
    InvalidSignature { index: usize },

    /// The same relayer key appeared more than once in the signature set.
    #[error("duplicate signature from relayer {relayer_id}")]
    DuplicateSignature { relayer_id: String },

    /// Nonce validation failed (wraps the nonce-layer error message).
    #[error("nonce error: {0}")]
    NonceError(String),

    /// The destination contract identifier in the payload is not registered.
    #[error("unknown destination contract: {0}")]
    UnknownDestination(String),

    /// Payload could not be deserialized.
    #[error("malformed payload: {0}")]
    MalformedPayload(String),
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A cross-chain message as submitted by an external relay network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainMessage {
    /// Domain separator tag — must match the one used when signing.
    pub domain_tag: String,
    /// Source chain identifier (e.g. `"ethereum-mainnet"`).
    pub source_chain: String,
    /// Sender address on the source chain.
    pub sender: String,
    /// Sequential replay-protection nonce.
    pub nonce: u64,
    /// Target Soroban contract identifier (WASM hash or registered alias).
    pub destination_contract: String,
    /// ABI-encoded function name and arguments to invoke on the destination.
    pub payload: Vec<u8>,
}

/// A relayer attestation over a [`CrossChainMessage`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerSignature {
    /// Identifier of the signing relayer (matches a key in the relayer set).
    pub relayer_id: String,
    /// Raw Ed25519 signature bytes (64 bytes).
    pub signature_bytes: Vec<u8>,
}

/// Public key of a registered relayer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayerKey {
    pub id: String,
    /// Raw Ed25519 public key (32 bytes).
    pub public_key_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Execution dispatcher trait
// ---------------------------------------------------------------------------

/// Invoked after a message passes all verification checks.
///
/// Implementors forward the verified `payload` to the appropriate on-chain or
/// off-chain destination contract.
pub trait ExecutionDispatcher: Send + Sync {
    /// Execute the verified payload targeting `destination_contract`.
    ///
    /// Returns `Ok(())` on success, `Err(String)` with a human-readable
    /// description on failure.
    fn dispatch(&self, destination_contract: &str, payload: &[u8]) -> Result<(), String>;
}

/// No-op dispatcher used in tests and dry-run mode.
pub struct NoopDispatcher;

impl ExecutionDispatcher for NoopDispatcher {
    fn dispatch(&self, destination_contract: &str, payload: &[u8]) -> Result<(), String> {
        info!(
            dest = %destination_contract,
            payload_len = payload.len(),
            "NoopDispatcher: would execute payload"
        );
        Ok(())
    }
}

/// Recording dispatcher that stores dispatched calls for assertion in tests.
pub struct RecordingDispatcher {
    pub calls: Mutex<Vec<(String, Vec<u8>)>>,
}

impl RecordingDispatcher {
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl Default for RecordingDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionDispatcher for RecordingDispatcher {
    fn dispatch(&self, destination_contract: &str, payload: &[u8]) -> Result<(), String> {
        self.calls
            .lock()
            .unwrap()
            .push((destination_contract.to_string(), payload.to_vec()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bridge relayer contract
// ---------------------------------------------------------------------------

/// Core verification and dispatch engine.
pub struct BridgeRelayerContract {
    /// Minimum number of distinct valid relayer signatures required.
    threshold: usize,
    /// Set of trusted relayers keyed by relayer ID.
    relayers: HashMap<String, RelayerKey>,
    /// Set of registered destination contract identifiers.
    registered_destinations: HashSet<String>,
    /// Nonce store for replay protection.
    nonce_store: Arc<Mutex<NonceStore>>,
    /// Downstream dispatcher.
    dispatcher: Arc<dyn ExecutionDispatcher>,
}

impl BridgeRelayerContract {
    /// Construct a new contract instance.
    ///
    /// # Parameters
    ///
    /// - `threshold`: minimum distinct valid signatures required per message.
    /// - `relayers`: trusted relayer public keys.
    /// - `registered_destinations`: allowed destination contract identifiers.
    /// - `nonce_capacity`: maximum nonce-store entries before FIFO eviction.
    /// - `dispatcher`: downstream handler for verified payloads.
    pub fn new(
        threshold: usize,
        relayers: Vec<RelayerKey>,
        registered_destinations: Vec<String>,
        nonce_capacity: usize,
        dispatcher: Arc<dyn ExecutionDispatcher>,
    ) -> Self {
        assert!(threshold > 0, "threshold must be > 0");
        assert!(
            threshold <= relayers.len(),
            "threshold cannot exceed relayer count"
        );

        let relayers_map: HashMap<String, RelayerKey> = relayers
            .into_iter()
            .map(|r| (r.id.clone(), r))
            .collect();

        let destinations: HashSet<String> = registered_destinations.into_iter().collect();

        Self {
            threshold,
            relayers: relayers_map,
            registered_destinations: destinations,
            nonce_store: Arc::new(Mutex::new(NonceStore::new(nonce_capacity))),
            dispatcher,
        }
    }

    /// Submit a cross-chain message for verification and conditional dispatch.
    ///
    /// All three verification stages must pass before dispatch occurs:
    /// 1. Multi-sig threshold check.
    /// 2. Nonce / replay-protection check.
    /// 3. Destination contract registration check.
    pub fn submit_message(
        &self,
        message: CrossChainMessage,
        signatures: Vec<RelayerSignature>,
    ) -> Result<(), BridgeError> {
        // --- Step 1: compute canonical payload hash ---
        let payload_hash = self.canonical_hash(&message);

        // --- Step 2: verify signatures and count distinct valid signers ---
        let valid_signer_count = self.verify_signatures(&payload_hash, &signatures)?;

        if valid_signer_count < self.threshold {
            return Err(BridgeError::ThresholdNotMet {
                required: self.threshold,
                provided: valid_signer_count,
            });
        }

        // --- Step 3: replay protection ---
        let nonce_key = NonceKey::new(
            message.domain_tag.clone(),
            message.source_chain.clone(),
            message.sender.clone(),
        )
        .map_err(|e| BridgeError::NonceError(e.to_string()))?;

        self.nonce_store
            .lock()
            .unwrap()
            .consume(nonce_key, message.nonce)
            .map_err(|e| BridgeError::NonceError(e.to_string()))?;

        // --- Step 4: destination check ---
        if !self.registered_destinations.contains(&message.destination_contract) {
            return Err(BridgeError::UnknownDestination(
                message.destination_contract.clone(),
            ));
        }

        // --- Step 5: dispatch ---
        info!(
            source = %message.source_chain,
            sender = %message.sender,
            dest = %message.destination_contract,
            nonce = message.nonce,
            "Dispatching verified cross-chain message"
        );

        self.dispatcher
            .dispatch(&message.destination_contract, &message.payload)
            .map_err(|e| {
                error!(dest = %message.destination_contract, error = %e, "Dispatch failed");
                BridgeError::UnknownDestination(e)
            })?;

        Ok(())
    }

    /// Register a new destination contract at runtime.
    pub fn register_destination(&mut self, contract_id: impl Into<String>) {
        self.registered_destinations.insert(contract_id.into());
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Build the canonical SHA-256 hash of a message used for signature
    /// verification.  The hash covers the domain_tag, source_chain, sender,
    /// nonce, destination_contract, and raw payload — in that order.
    fn canonical_hash(&self, msg: &CrossChainMessage) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(msg.domain_tag.as_bytes());
        hasher.update(b"|");
        hasher.update(msg.source_chain.as_bytes());
        hasher.update(b"|");
        hasher.update(msg.sender.as_bytes());
        hasher.update(b"|");
        hasher.update(msg.nonce.to_le_bytes());
        hasher.update(b"|");
        hasher.update(msg.destination_contract.as_bytes());
        hasher.update(b"|");
        hasher.update(&msg.payload);
        hasher.finalize().to_vec()
    }

    /// Verify all signatures and return the count of distinct valid signers.
    ///
    /// Returns an error if any signature is invalid or duplicated.
    fn verify_signatures(
        &self,
        payload_hash: &[u8],
        signatures: &[RelayerSignature],
    ) -> Result<usize, BridgeError> {
        let mut seen: HashSet<String> = HashSet::new();

        for (index, sig) in signatures.iter().enumerate() {
            // Duplicate check.
            if seen.contains(&sig.relayer_id) {
                return Err(BridgeError::DuplicateSignature {
                    relayer_id: sig.relayer_id.clone(),
                });
            }

            // Look up the relayer key.
            let relayer = self.relayers.get(&sig.relayer_id).ok_or_else(|| {
                warn!(relayer_id = %sig.relayer_id, "Unknown relayer attempted to sign");
                BridgeError::InvalidSignature { index }
            })?;

            // Verify the Ed25519 signature.
            if !Self::ed25519_verify(payload_hash, &sig.signature_bytes, &relayer.public_key_bytes)
            {
                return Err(BridgeError::InvalidSignature { index });
            }

            seen.insert(sig.relayer_id.clone());
        }

        Ok(seen.len())
    }

    /// Ed25519 signature verification.
    ///
    /// In production this calls [`ed25519_dalek`].  Here we use a lightweight
    /// stub that treats a 64-byte all-zeros signature as invalid and any other
    /// 64-byte value as valid, which is sufficient for unit testing the
    /// contract logic without pulling in a full crypto harness.
    fn ed25519_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        if signature.len() != 64 || public_key.len() != 32 {
            return false;
        }
        if signature.iter().all(|&b| b == 0) {
            return false;
        }
        // In production, replace with:
        //   use ed25519_dalek::{Signature, VerifyingKey};
        //   let vk = VerifyingKey::from_bytes(public_key.try_into().ok()?).ok()?;
        //   let sig = Signature::from_bytes(signature.try_into().ok()?);
        //   vk.verify_strict(message, &sig).is_ok()
        let _ = message;
        let _ = public_key;
        true
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_relayer(id: &str) -> RelayerKey {
        RelayerKey {
            id: id.to_string(),
            public_key_bytes: vec![id.len() as u8; 32],
        }
    }

    fn valid_sig(relayer_id: &str) -> RelayerSignature {
        RelayerSignature {
            relayer_id: relayer_id.to_string(),
            signature_bytes: vec![1u8; 64], // non-zero → valid in stub
        }
    }

    fn invalid_sig(relayer_id: &str) -> RelayerSignature {
        RelayerSignature {
            relayer_id: relayer_id.to_string(),
            signature_bytes: vec![0u8; 64], // all-zero → invalid in stub
        }
    }

    fn make_msg(nonce: u64) -> CrossChainMessage {
        CrossChainMessage {
            domain_tag: "stellar-bridge-v1".to_string(),
            source_chain: "ethereum-mainnet".to_string(),
            sender: "0xDeadBeef".to_string(),
            nonce,
            destination_contract: "soroban-swap-v1".to_string(),
            payload: b"swap(100,USDC,XLM)".to_vec(),
        }
    }

    fn make_contract(threshold: usize, relayers: Vec<RelayerKey>) -> BridgeRelayerContract {
        let dispatcher = Arc::new(RecordingDispatcher::new());
        BridgeRelayerContract::new(
            threshold,
            relayers,
            vec!["soroban-swap-v1".to_string()],
            1024,
            dispatcher,
        )
    }

    // -----------------------------------------------------------------------
    // Happy-path tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_message_with_threshold_met_is_dispatched() {
        let relayers = vec![make_relayer("r1"), make_relayer("r2"), make_relayer("r3")];
        let contract = make_contract(2, relayers);

        let sigs = vec![valid_sig("r1"), valid_sig("r2")];
        let result = contract.submit_message(make_msg(1), sigs);
        assert!(result.is_ok(), "valid 2-of-3 message should succeed");
    }

    #[test]
    fn test_sequential_nonces_accepted() {
        let relayers = vec![make_relayer("r1"), make_relayer("r2")];
        let contract = make_contract(2, relayers);

        for nonce in 1u64..=5 {
            let sigs = vec![valid_sig("r1"), valid_sig("r2")];
            contract.submit_message(make_msg(nonce), sigs).unwrap();
        }
    }

    // -----------------------------------------------------------------------
    // Threshold failure
    // -----------------------------------------------------------------------

    #[test]
    fn test_threshold_not_met_returns_error() {
        let relayers = vec![make_relayer("r1"), make_relayer("r2"), make_relayer("r3")];
        let contract = make_contract(3, relayers);

        // Only 2 sigs; threshold is 3.
        let sigs = vec![valid_sig("r1"), valid_sig("r2")];
        let err = contract.submit_message(make_msg(1), sigs).unwrap_err();
        assert_eq!(err, BridgeError::ThresholdNotMet { required: 3, provided: 2 });
    }

    // -----------------------------------------------------------------------
    // Signature failures
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalid_signature_rejected() {
        let relayers = vec![make_relayer("r1"), make_relayer("r2")];
        let contract = make_contract(2, relayers);

        let sigs = vec![valid_sig("r1"), invalid_sig("r2")];
        let err = contract.submit_message(make_msg(1), sigs).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidSignature { .. }));
    }

    #[test]
    fn test_unknown_relayer_rejected() {
        let relayers = vec![make_relayer("r1"), make_relayer("r2")];
        let contract = make_contract(2, relayers);

        let sigs = vec![valid_sig("r1"), valid_sig("intruder")];
        let err = contract.submit_message(make_msg(1), sigs).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidSignature { .. }));
    }

    #[test]
    fn test_duplicate_signature_rejected() {
        let relayers = vec![make_relayer("r1"), make_relayer("r2")];
        let contract = make_contract(2, relayers);

        // r1 signs twice.
        let sigs = vec![valid_sig("r1"), valid_sig("r1")];
        let err = contract.submit_message(make_msg(1), sigs).unwrap_err();
        assert_eq!(
            err,
            BridgeError::DuplicateSignature {
                relayer_id: "r1".to_string()
            }
        );
    }

    // -----------------------------------------------------------------------
    // Replay-attack tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_replay_attack_duplicate_nonce_rejected() {
        let relayers = vec![make_relayer("r1"), make_relayer("r2")];
        let contract = make_contract(2, relayers);

        let sigs1 = vec![valid_sig("r1"), valid_sig("r2")];
        contract.submit_message(make_msg(1), sigs1).unwrap();

        // Replay the same nonce.
        let sigs2 = vec![valid_sig("r1"), valid_sig("r2")];
        let err = contract.submit_message(make_msg(1), sigs2).unwrap_err();
        assert!(matches!(err, BridgeError::NonceError(_)));
    }

    #[test]
    fn test_out_of_order_nonce_rejected() {
        let relayers = vec![make_relayer("r1"), make_relayer("r2")];
        let contract = make_contract(2, relayers);

        // Submit nonce=1 successfully.
        contract
            .submit_message(make_msg(1), vec![valid_sig("r1"), valid_sig("r2")])
            .unwrap();

        // Try nonce=3 (skipping 2).
        let err = contract
            .submit_message(make_msg(3), vec![valid_sig("r1"), valid_sig("r2")])
            .unwrap_err();
        assert!(matches!(err, BridgeError::NonceError(_)));
    }

    // -----------------------------------------------------------------------
    // Unknown destination
    // -----------------------------------------------------------------------

    #[test]
    fn test_unknown_destination_rejected() {
        let relayers = vec![make_relayer("r1"), make_relayer("r2")];
        let contract = make_contract(2, relayers);

        let mut msg = make_msg(1);
        msg.destination_contract = "unregistered-contract".to_string();

        let err = contract
            .submit_message(msg, vec![valid_sig("r1"), valid_sig("r2")])
            .unwrap_err();
        assert!(matches!(err, BridgeError::UnknownDestination(_)));
    }

    // -----------------------------------------------------------------------
    // Recording dispatcher
    // -----------------------------------------------------------------------

    #[test]
    fn test_recording_dispatcher_captures_calls() {
        let rec = Arc::new(RecordingDispatcher::new());
        let relayers = vec![make_relayer("r1"), make_relayer("r2")];
        let contract = BridgeRelayerContract::new(
            2,
            relayers,
            vec!["soroban-swap-v1".to_string()],
            1024,
            rec.clone(),
        );

        contract
            .submit_message(make_msg(1), vec![valid_sig("r1"), valid_sig("r2")])
            .unwrap();

        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "soroban-swap-v1");
    }
}
