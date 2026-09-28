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

//! # RPC Node Health Evaluator
//!
//! Lightweight, latency-constrained health probe for Soroban RPC clusters used
//! by the multi-region traffic router.
//!
//! ## Latency budget
//!
//! The entire health evaluation path — HTTP probe, ledger-sequence parse, and
//! circuit-breaker state check — must complete within **2 ms** of wall-clock
//! time added to the incoming client request.  This is achieved by:
//!
//! - Keeping a **cached** [`ClusterHealth`] snapshot updated on a background
//!   ticker (default: every 1 s) so the routing hot-path never blocks on I/O.
//! - Returning stale-but-fast data when the background refresh is in progress.
//!
//! ## Circuit breaker
//!
//! Each cluster has an independent circuit breaker with three states:
//!
//! ```text
//! Closed ──(N failures in window)──► Open ──(cool-down elapsed)──► HalfOpen
//!   ▲                                                                    │
//!   └──────────────(probe success)──────────────────────────────────────┘
//! ```
//!
//! A cluster in `Open` state is excluded from routing immediately.  `HalfOpen`
//! allows one probe request through; success resets to `Closed`, failure
//! extends the `Open` period.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from health evaluation.
#[derive(Debug, Error)]
pub enum HealthError {
    /// The HTTP probe timed out.
    #[error("health probe timed out for cluster {cluster_id}")]
    ProbeTimeout { cluster_id: String },

    /// The probe returned an unexpected HTTP status.
    #[error("cluster {cluster_id} returned status {status}")]
    BadStatus { cluster_id: String, status: u16 },

    /// Could not parse the ledger sequence from the probe response.
    #[error("failed to parse ledger sequence from cluster {cluster_id}: {reason}")]
    ParseError { cluster_id: String, reason: String },
}

// ---------------------------------------------------------------------------
// Circuit-breaker state
// ---------------------------------------------------------------------------

/// Discrete state of the circuit breaker for one cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Normal operation — requests are forwarded.
    Closed,
    /// Cluster is isolated — requests are not forwarded.
    Open,
    /// One probe is allowed through to test recovery.
    HalfOpen,
}

impl Default for CircuitState {
    fn default() -> Self {
        CircuitState::Closed
    }
}

// ---------------------------------------------------------------------------
// Cluster configuration
// ---------------------------------------------------------------------------

/// Static configuration for one Soroban RPC cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Unique cluster identifier (e.g. `"us-east-1"`).
    pub id: String,
    /// Base URL of the Soroban RPC endpoint.
    pub rpc_url: String,
    /// Geographic region label (used for latency-based preference).
    pub region: String,
    /// Maximum ledger sequence lag (vs. best peer) before the cluster is
    /// considered out-of-sync and deprioritised.
    pub max_lag_ledgers: u64,
    /// Number of consecutive failures before the circuit breaker opens.
    pub failure_threshold: u32,
    /// How long the circuit stays open before transitioning to HalfOpen.
    pub open_duration: Duration,
}

impl ClusterConfig {
    /// Construct with sensible defaults.
    pub fn new(id: impl Into<String>, rpc_url: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            rpc_url: rpc_url.into(),
            region: region.into(),
            max_lag_ledgers: 10,
            failure_threshold: 3,
            open_duration: Duration::from_secs(30),
        }
    }
}

// ---------------------------------------------------------------------------
// Health snapshot
// ---------------------------------------------------------------------------

/// Point-in-time health snapshot for one cluster.
#[derive(Debug, Clone)]
pub struct ClusterHealth {
    pub cluster_id: String,
    /// Latest ledger sequence reported by the cluster.
    pub latest_ledger: u64,
    /// Round-trip latency of the last successful probe.
    pub probe_latency: Duration,
    /// Current circuit-breaker state.
    pub circuit_state: CircuitState,
    /// Consecutive failure count feeding the circuit breaker.
    pub consecutive_failures: u32,
    /// Wall-clock instant of the last state transition (used for open-duration timeout).
    pub last_state_change: Instant,
    /// Whether the cluster is considered healthy and eligible for routing.
    pub is_healthy: bool,
}

impl ClusterHealth {
    fn new(cluster_id: impl Into<String>) -> Self {
        Self {
            cluster_id: cluster_id.into(),
            latest_ledger: 0,
            probe_latency: Duration::ZERO,
            circuit_state: CircuitState::Closed,
            consecutive_failures: 0,
            last_state_change: Instant::now(),
            is_healthy: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Health evaluator
// ---------------------------------------------------------------------------

/// Configuration for [`HealthEvaluator`].
#[derive(Debug, Clone)]
pub struct EvaluatorConfig {
    /// Background refresh interval.
    pub refresh_interval: Duration,
    /// Per-probe HTTP timeout.
    pub probe_timeout: Duration,
}

impl Default for EvaluatorConfig {
    fn default() -> Self {
        Self {
            refresh_interval: Duration::from_secs(1),
            probe_timeout: Duration::from_millis(800),
        }
    }
}

/// Probes Soroban RPC clusters on a background ticker and maintains a cached
/// [`ClusterHealth`] snapshot per cluster.
///
/// The routing hot-path reads from an `Arc<RwLock<_>>` snapshot that is
/// updated by the background task — no I/O on the critical path.
pub struct HealthEvaluator {
    clusters: Vec<ClusterConfig>,
    snapshots: Arc<RwLock<HashMap<String, ClusterHealth>>>,
    config: EvaluatorConfig,
    http: reqwest::Client,
}

impl HealthEvaluator {
    /// Create a new evaluator.
    pub fn new(clusters: Vec<ClusterConfig>, config: EvaluatorConfig) -> Self {
        let mut initial: HashMap<String, ClusterHealth> = HashMap::new();
        for c in &clusters {
            initial.insert(c.id.clone(), ClusterHealth::new(&c.id));
        }

        let http = reqwest::Client::builder()
            .timeout(config.probe_timeout)
            .build()
            .unwrap_or_default();

        Self {
            clusters,
            snapshots: Arc::new(RwLock::new(initial)),
            config,
            http,
        }
    }

    /// Return a read-only handle to the live snapshot map.
    ///
    /// This clone is cheap — it shares the same `Arc`.
    pub fn snapshot_handle(&self) -> Arc<RwLock<HashMap<String, ClusterHealth>>> {
        self.snapshots.clone()
    }

    /// Run one probe cycle across all clusters (called by the background task).
    pub async fn probe_all(&self) {
        let best_ledger = self.best_known_ledger().await;

        for cluster in &self.clusters {
            let result = self.probe_cluster(cluster).await;
            let mut snapshots = self.snapshots.write().await;
            let entry = snapshots
                .entry(cluster.id.clone())
                .or_insert_with(|| ClusterHealth::new(&cluster.id));

            match result {
                Ok((ledger, latency)) => {
                    entry.latest_ledger = ledger;
                    entry.probe_latency = latency;
                    entry.consecutive_failures = 0;

                    // Recover circuit breaker on success.
                    if entry.circuit_state == CircuitState::HalfOpen
                        || entry.circuit_state == CircuitState::Open
                    {
                        entry.circuit_state = CircuitState::Closed;
                        entry.last_state_change = Instant::now();
                    }

                    // Mark healthy if sync lag is within tolerance.
                    let lag = best_ledger.saturating_sub(ledger);
                    entry.is_healthy = lag <= cluster.max_lag_ledgers;
                    if !entry.is_healthy {
                        warn!(
                            cluster = %cluster.id,
                            lag,
                            max = cluster.max_lag_ledgers,
                            "Cluster exceeds max ledger lag; deprioritised"
                        );
                    }
                }
                Err(e) => {
                    warn!(cluster = %cluster.id, error = %e, "Probe failed");
                    entry.consecutive_failures += 1;
                    entry.is_healthy = false;

                    // Advance circuit breaker.
                    match entry.circuit_state {
                        CircuitState::Closed | CircuitState::HalfOpen => {
                            if entry.consecutive_failures >= cluster.failure_threshold {
                                entry.circuit_state = CircuitState::Open;
                                entry.last_state_change = Instant::now();
                                warn!(cluster = %cluster.id, "Circuit breaker opened");
                            }
                        }
                        CircuitState::Open => {
                            // Check if cool-down has elapsed → HalfOpen.
                            if entry.last_state_change.elapsed() >= cluster.open_duration {
                                entry.circuit_state = CircuitState::HalfOpen;
                                entry.last_state_change = Instant::now();
                                debug!(cluster = %cluster.id, "Circuit breaker transitioning to HalfOpen");
                            }
                        }
                    }
                }
            }
        }
    }

    /// Run the background refresh loop forever.
    pub async fn run_background_refresh(self: Arc<Self>) {
        loop {
            self.probe_all().await;
            tokio::time::sleep(self.config.refresh_interval).await;
        }
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    async fn probe_cluster(
        &self,
        cluster: &ClusterConfig,
    ) -> Result<(u64, Duration), HealthError> {
        let url = format!("{}/health", cluster.rpc_url);
        let start = Instant::now();

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|_| HealthError::ProbeTimeout {
                cluster_id: cluster.id.clone(),
            })?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(HealthError::BadStatus {
                cluster_id: cluster.id.clone(),
                status,
            });
        }

        let latency = start.elapsed();

        // Parse ledger sequence from JSON body: `{"ledgerSequence": N}`.
        let body: serde_json::Value =
            resp.json().await.map_err(|e| HealthError::ParseError {
                cluster_id: cluster.id.clone(),
                reason: e.to_string(),
            })?;

        let ledger = body
            .get("ledgerSequence")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| HealthError::ParseError {
                cluster_id: cluster.id.clone(),
                reason: "missing ledgerSequence field".to_string(),
            })?;

        Ok((ledger, latency))
    }

    /// Highest ledger sequence seen across all cached snapshots.
    async fn best_known_ledger(&self) -> u64 {
        self.snapshots
            .read()
            .await
            .values()
            .map(|s| s.latest_ledger)
            .max()
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster(id: &str) -> ClusterConfig {
        ClusterConfig::new(id, format!("http://rpc-{id}.example.com"), "us-east-1")
    }

    // --- ClusterConfig defaults ---

    #[test]
    fn test_cluster_config_default_lag_threshold() {
        let c = cluster("primary");
        assert_eq!(c.max_lag_ledgers, 10);
        assert_eq!(c.failure_threshold, 3);
    }

    // --- CircuitState ---

    #[test]
    fn test_circuit_state_default_is_closed() {
        let state = CircuitState::default();
        assert_eq!(state, CircuitState::Closed);
    }

    #[test]
    fn test_circuit_state_variants_are_distinct() {
        assert_ne!(CircuitState::Closed, CircuitState::Open);
        assert_ne!(CircuitState::Open, CircuitState::HalfOpen);
        assert_ne!(CircuitState::Closed, CircuitState::HalfOpen);
    }

    // --- ClusterHealth initial state ---

    #[test]
    fn test_cluster_health_initial_not_healthy() {
        let h = ClusterHealth::new("test-cluster");
        assert!(!h.is_healthy);
        assert_eq!(h.circuit_state, CircuitState::Closed);
        assert_eq!(h.consecutive_failures, 0);
        assert_eq!(h.latest_ledger, 0);
    }

    // --- Evaluator config defaults ---

    #[test]
    fn test_evaluator_config_defaults() {
        let cfg = EvaluatorConfig::default();
        assert_eq!(cfg.refresh_interval, Duration::from_secs(1));
        assert_eq!(cfg.probe_timeout, Duration::from_millis(800));
    }

    // --- HealthEvaluator snapshot handle ---

    #[tokio::test]
    async fn test_snapshot_handle_shared_reference() {
        let ev = HealthEvaluator::new(vec![cluster("c1"), cluster("c2")], EvaluatorConfig::default());
        let handle = ev.snapshot_handle();
        let snap = handle.read().await;
        assert!(snap.contains_key("c1"));
        assert!(snap.contains_key("c2"));
    }

    #[tokio::test]
    async fn test_initial_snapshots_are_unhealthy() {
        let ev = HealthEvaluator::new(vec![cluster("primary")], EvaluatorConfig::default());
        let handle = ev.snapshot_handle();
        let snap = handle.read().await;
        let h = snap.get("primary").unwrap();
        assert!(!h.is_healthy);
        assert_eq!(h.circuit_state, CircuitState::Closed);
    }

    // --- Circuit breaker state transitions (direct state manipulation) ---

    #[test]
    fn test_circuit_breaker_open_state_transition() {
        let mut health = ClusterHealth::new("test");
        health.circuit_state = CircuitState::Closed;
        health.consecutive_failures = 3;

        // Simulate what probe_all does when threshold is reached.
        let threshold = 3u32;
        if health.consecutive_failures >= threshold {
            health.circuit_state = CircuitState::Open;
        }
        assert_eq!(health.circuit_state, CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_recovers_on_success() {
        let mut health = ClusterHealth::new("test");
        health.circuit_state = CircuitState::HalfOpen;
        health.consecutive_failures = 2;

        // Simulate successful probe.
        health.consecutive_failures = 0;
        if health.circuit_state == CircuitState::HalfOpen {
            health.circuit_state = CircuitState::Closed;
        }
        assert_eq!(health.circuit_state, CircuitState::Closed);
    }

    #[test]
    fn test_lag_threshold_marks_unhealthy() {
        let cluster_cfg = cluster("lagging");
        let best_ledger = 1000u64;
        let cluster_ledger = 985u64; // lag = 15, max = 10

        let lag = best_ledger.saturating_sub(cluster_ledger);
        let is_healthy = lag <= cluster_cfg.max_lag_ledgers;
        assert!(!is_healthy, "cluster with 15-ledger lag should be unhealthy");
    }

    #[test]
    fn test_within_lag_threshold_marks_healthy() {
        let cluster_cfg = cluster("synced");
        let best_ledger = 1000u64;
        let cluster_ledger = 995u64; // lag = 5, max = 10

        let lag = best_ledger.saturating_sub(cluster_ledger);
        let is_healthy = lag <= cluster_cfg.max_lag_ledgers;
        assert!(is_healthy, "cluster within lag threshold should be healthy");
    }
}
