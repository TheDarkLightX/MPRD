//! Policy Algebra CLI helpers.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use mprd_core::policy_algebra::{decode_policy_v1, emit_tau_gate_v1, PolicyLimits};

const MAX_POLICY_ALGEBRA_BYTES: usize = 1 * 1024 * 1024;

pub fn emit_tau(policy: PathBuf, output_name: String, out: Option<PathBuf>) -> Result<()> {
    let bytes = fs::read(&policy)
        .with_context(|| format!("Failed to read policy algebra file: {}", policy.display()))?;

    if bytes.len() > MAX_POLICY_ALGEBRA_BYTES {
        anyhow::bail!(
            "Policy algebra file too large ({} > {} bytes)",
            bytes.len(),
            MAX_POLICY_ALGEBRA_BYTES
        );
    }

    let limits = PolicyLimits::DEFAULT;
    let expr = decode_policy_v1(&bytes, limits).context("Failed to decode policy algebra v1")?;
    let tau = emit_tau_gate_v1(&expr, &output_name, limits).context("Failed to emit Tau gate")?;

    match out {
        Some(path) => {
            fs::write(&path, tau.as_bytes())
                .with_context(|| format!("Failed to write Tau gate: {}", path.display()))?;
            println!("Wrote Tau gate to {}", path.display());
        }
        None => {
            print!("{tau}");
        }
    }

    Ok(())
}
