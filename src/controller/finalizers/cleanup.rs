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

//! # Finalizer Cleanup Recovery Controller
//!
//! Background garbage-collection reconciler that identifies StellarNode resources
//! stuck in `Terminating` state due to stale finalizers left behind when the
//! controller process was interrupted mid-deletion.
//!
//! ## Safety contract
//!
//! A finalizer is **never** stripped unless [`cloud_verify`] has confirmed that
//! the underlying cloud storage volume has fully detached. This prevents data
//! leaks or corruption on AWS EBS and GCP Persistent Disk.
//!
//! ## Flow
//!
//! ```text
//! watch StellarNode list
//!   └─ filter: deletionTimestamp != nil && finalizer present
//!       └─ for each stuck resource
//!           ├─ query CloudVerifier for volume attachment status
//!           ├─ if DETACHED → strip finalizer → resource deleted by k8s gc
//!           └─ if ATTACHED / UNKNOWN → requeue after back-off interval
//! ```

use std::sync::Arc;
use std::time::Duration;

use kube::{
    api::{Api, ListParams, Patch, PatchParams},
    Client, ResourceExt,
};
use serde_json::json;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::crd::StellarNode;
use crate::error::Result;

use super::cloud_verify::{CloudVerifier, VolumeAttachmentStatus};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How often the recovery loop polls for stuck resources.
const RECOVERY_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Back-off applied when a volume is still attached; prevents hot loops.
const REQUEUE_BACKOFF: Duration = Duration::from_secs(60);

/// Maximum consecutive cloud-verify failures before the loop logs an alert and
/// skips the resource for this cycle.
const MAX_VERIFY_FAILURES: u32 = 5;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Outcome of a single recovery attempt on one stuck resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// Finalizer removed; Kubernetes will proceed with deletion.
    FinalizerStripped,
    /// Volume is still attached — requeue required.
    Requeued,
    /// Cloud verification returned ambiguous / error state; skipped safely.
    Skipped,
}

/// Shared configuration for the recovery controller.
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Override for the default poll interval (useful in tests).
    pub poll_interval: Duration,
    /// Override for the requeue back-off.
    pub requeue_backoff: Duration,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            poll_interval: RECOVERY_POLL_INTERVAL,
            requeue_backoff: REQUEUE_BACKOFF,
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery controller
// ---------------------------------------------------------------------------

/// Entry-point: run the finalizer cleanup recovery loop forever.
///
/// This function is intended to be spawned as a background `tokio` task:
///
/// ```rust,ignore
/// tokio::spawn(run_finalizer_recovery_controller(client, verifier, cfg));
/// ```
pub async fn run_finalizer_recovery_controller(
    client: Client,
    verifier: Arc<dyn CloudVerifier>,
    config: RecoveryConfig,
) {
    info!("Finalizer recovery controller started");
    loop {
        if let Err(e) = recovery_tick(client.clone(), verifier.clone()).await {
            error!("Finalizer recovery tick failed: {e}");
        }
        sleep(config.poll_interval).await;
    }
}

/// One reconciliation pass: find all stuck StellarNodes and attempt recovery.
async fn recovery_tick(client: Client, verifier: Arc<dyn CloudVerifier>) -> Result<()> {
    let nodes: Api<StellarNode> = Api::all(client.clone());
    let lp = ListParams::default();
    let node_list = nodes.list(&lp).await?;

    for node in node_list.items {
        if !is_stuck_terminating(&node) {
            continue;
        }

        let name = node.name_any();
        let namespace = node.namespace().unwrap_or_else(|| "default".to_string());

        info!(
            node = %name,
            namespace = %namespace,
            "Found stuck StellarNode — beginning recovery"
        );

        match attempt_recovery(client.clone(), verifier.clone(), &node, &namespace).await {
            Ok(RecoveryOutcome::FinalizerStripped) => {
                info!(node = %name, "Finalizer stripped; resource will be GC'd");
            }
            Ok(RecoveryOutcome::Requeued) => {
                warn!(node = %name, "Volume still attached; will retry after back-off");
            }
            Ok(RecoveryOutcome::Skipped) => {
                warn!(node = %name, "Recovery skipped due to ambiguous cloud state");
            }
            Err(e) => {
                error!(node = %name, error = %e, "Recovery attempt errored");
            }
        }
    }

    Ok(())
}

/// Core recovery logic for a single node.
async fn attempt_recovery(
    client: Client,
    verifier: Arc<dyn CloudVerifier>,
    node: &StellarNode,
    namespace: &str,
) -> Result<RecoveryOutcome> {
    let name = node.name_any();
    let pvc_name = derive_pvc_name(&name);

    // Step 1: query cloud provider to check volume attachment status.
    let mut failures = 0u32;
    let status = loop {
        match verifier.check_volume_attachment(&pvc_name, namespace).await {
            Ok(s) => break s,
            Err(e) => {
                failures += 1;
                warn!(
                    pvc = %pvc_name,
                    attempt = failures,
                    error = %e,
                    "Cloud verify attempt failed"
                );
                if failures >= MAX_VERIFY_FAILURES {
                    return Ok(RecoveryOutcome::Skipped);
                }
                sleep(Duration::from_secs(2u64.pow(failures))).await;
            }
        }
    };

    match status {
        VolumeAttachmentStatus::Detached => {
            // Safe to strip the finalizer — cloud storage is gone.
            strip_finalizer(client, node, namespace).await?;
            Ok(RecoveryOutcome::FinalizerStripped)
        }
        VolumeAttachmentStatus::Attached => {
            // Still attached; let the regular cleanup complete.
            sleep(REQUEUE_BACKOFF).await;
            Ok(RecoveryOutcome::Requeued)
        }
        VolumeAttachmentStatus::Unknown => {
            warn!(
                node = %name,
                pvc = %pvc_name,
                "Volume attachment status is unknown; skipping to avoid data loss"
            );
            Ok(RecoveryOutcome::Skipped)
        }
    }
}

/// Strip the Stellar operator finalizer from a node.
///
/// # Safety
///
/// This must only be called after [`cloud_verify`] has confirmed the volume
/// is `Detached`. Calling it before risks removing the deletion guard while
/// cloud resources still exist.
async fn strip_finalizer(client: Client, node: &StellarNode, namespace: &str) -> Result<()> {
    let api: Api<StellarNode> = Api::namespaced(client, namespace);
    let name = node.name_any();

    let remaining: Vec<String> = node
        .finalizers()
        .iter()
        .filter(|f| f.as_str() != crate::controller::finalizers::STELLAR_NODE_FINALIZER)
        .cloned()
        .collect();

    let patch = json!({ "metadata": { "finalizers": remaining } });
    api.patch(&name, &PatchParams::apply("stellar-operator"), &Patch::Merge(&patch))
        .await?;

    info!(node = %name, "Finalizer stripped after verified volume detachment");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A resource is "stuck terminating" if it has a deletion timestamp and still
/// carries the Stellar operator finalizer.
fn is_stuck_terminating(node: &StellarNode) -> bool {
    node.metadata.deletion_timestamp.is_some()
        && node
            .finalizers()
            .iter()
            .any(|f| f == crate::controller::finalizers::STELLAR_NODE_FINALIZER)
}

/// Derive the PVC name from the node name using the operator naming convention.
fn derive_pvc_name(node_name: &str) -> String {
    format!("data-{node_name}-0")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_pvc_name() {
        assert_eq!(derive_pvc_name("validator-prod-0"), "data-validator-prod-0-0");
        assert_eq!(derive_pvc_name("stellar-node"), "data-stellar-node-0");
    }

    #[test]
    fn test_recovery_config_defaults() {
        let cfg = RecoveryConfig::default();
        assert_eq!(cfg.poll_interval, RECOVERY_POLL_INTERVAL);
        assert_eq!(cfg.requeue_backoff, REQUEUE_BACKOFF);
    }

    #[test]
    fn test_recovery_outcome_variants_are_distinct() {
        assert_ne!(RecoveryOutcome::FinalizerStripped, RecoveryOutcome::Requeued);
        assert_ne!(RecoveryOutcome::Requeued, RecoveryOutcome::Skipped);
        assert_ne!(RecoveryOutcome::FinalizerStripped, RecoveryOutcome::Skipped);
    }
}
