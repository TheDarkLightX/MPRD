//! Fee router helpers (settlement receipt commitments).

use anyhow::{Context, Result};

use mprd_core::{fee_router, Hash32};

fn parse_hash32_hex(hex_str: &str) -> Result<Hash32> {
    let bytes = hex::decode(hex_str).context("invalid hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Hash32(out))
}

pub fn settlement_receipt_hash(
    tau_tx_id_hex: String,
    tau_block_ref_hex: String,
    fee_payer_hex: String,
    fee_amount_u128_dec: String,
    batch_id_hex: String,
) -> Result<()> {
    let tau_tx_id = parse_hash32_hex(&tau_tx_id_hex)?;
    let tau_block_ref = parse_hash32_hex(&tau_block_ref_hex)?;
    let fee_payer = parse_hash32_hex(&fee_payer_hex)?;
    let fee_amount: u128 = fee_amount_u128_dec
        .parse()
        .context("invalid fee_amount_u128_dec")?;
    let batch_id = parse_hash32_hex(&batch_id_hex)?;

    let h = fee_router::settlement_receipt_hash_v1(
        tau_tx_id,
        tau_block_ref,
        fee_payer,
        fee_amount,
        batch_id,
    );
    println!("{}", hex::encode(h.0));
    Ok(())
}
