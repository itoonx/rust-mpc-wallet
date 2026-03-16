//! Shared UTXO transaction simulation — dust, fee, and risk checks.
//!
//! Used by Bitcoin, Litecoin, Dogecoin, Zcash.

use crate::provider::{SimulationResult, TransactionParams};

/// Simulation configuration for UTXO chains.
#[derive(Debug, Clone)]
pub struct UtxoSimulationConfig {
    /// Maximum fee rate in sat/vB before flagging as high-fee.
    pub max_fee_rate_sat_vb: u64,
    /// Maximum total fee in base units (satoshis/litoshis/etc).
    pub max_total_fee: u64,
    /// Minimum output value (dust threshold) in base units.
    pub dust_threshold: u64,
}

impl Default for UtxoSimulationConfig {
    fn default() -> Self {
        Self {
            max_fee_rate_sat_vb: 500,
            max_total_fee: 1_000_000,
            dust_threshold: 546,
        }
    }
}

/// Run UTXO simulation checks: dust, fee rate, total fee, RBF, multi-output.
pub fn simulate_utxo(
    params: &TransactionParams,
    config: &UtxoSimulationConfig,
) -> SimulationResult {
    let mut risk_flags = Vec::new();
    let mut risk_score: u8 = 0;

    let value: u64 = params.value.parse().unwrap_or(0);

    // Dust check
    if value > 0 && value < config.dust_threshold {
        risk_flags.push("dust_output".into());
        risk_score = risk_score.saturating_add(40);
    }

    if let Some(extra) = &params.extra {
        // Fee rate check
        if let Some(fee_rate) = extra.get("fee_rate_sat_vb").and_then(|v| v.as_u64()) {
            if fee_rate > config.max_fee_rate_sat_vb {
                risk_flags.push("high_fee_rate".into());
                risk_score = risk_score.saturating_add(50);
            }
        }

        // Total fee check
        if let Some(total_fee) = extra.get("fee_sat").and_then(|v| v.as_u64()) {
            if total_fee > config.max_total_fee {
                risk_flags.push("excessive_fee".into());
                risk_score = risk_score.saturating_add(60);
            }
        }

        // RBF flag
        if extra.get("rbf").and_then(|v| v.as_bool()).unwrap_or(false) {
            risk_flags.push("rbf_enabled".into());
            risk_score = risk_score.saturating_add(10);
        }

        // Multi-output check
        if let Some(outputs) = extra.get("output_count").and_then(|v| v.as_u64()) {
            if outputs > 5 {
                risk_flags.push("many_outputs".into());
                risk_score = risk_score.saturating_add(20);
            }
        }
    }

    SimulationResult {
        success: true,
        gas_used: 0,
        return_data: Vec::new(),
        risk_flags,
        risk_score,
    }
}
