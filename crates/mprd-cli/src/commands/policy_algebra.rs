//! Policy Algebra CLI helpers.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use mprd_core::policy_algebra::{
    compile_allow_robdd, decode_policy_v1, emit_tau_gate_v2, parse_emitted_tau_gate_allow_expr_v1,
    policy_equiv_robdd, policy_equiv_robdd_policy_vs_tau_bits, policy_menu_canonical_v1,
    policy_menu_entries_v1, policy_semantic_hash_robdd_v1, PolicyLimits,
};

const MAX_POLICY_ALGEBRA_BYTES: usize = 1 * 1024 * 1024;

pub fn menu_list(format: String) -> Result<()> {
    let limits = PolicyLimits::DEFAULT;

    if format == "json" {
        #[derive(serde::Serialize)]
        struct Row<'a> {
            id: &'a str,
            category: &'a str,
            title: &'a str,
            description: &'a str,
            suggested_output_name: &'a str,
            policy_hash_v1: String,
            robdd_sem_hash_v1: String,
            nodes: usize,
            atoms: Vec<String>,
            deny_if_atoms: Vec<String>,
        }

        let mut rows = Vec::new();
        for e in policy_menu_entries_v1() {
            let canon = e
                .canonical(limits)
                .context("Failed to build canonical menu policy")?;
            let sem = policy_semantic_hash_robdd_v1(canon.expr(), limits)
                .context("Failed to ROBDD-hash")?;
            let atoms = canon
                .expr()
                .atoms()
                .into_iter()
                .map(|a| a.as_str().to_string())
                .collect::<Vec<_>>();
            let deny_if_atoms = canon
                .expr()
                .deny_if_atoms()
                .into_iter()
                .map(|a| a.as_str().to_string())
                .collect::<Vec<_>>();
            rows.push(Row {
                id: e.id,
                category: e.category,
                title: e.title,
                description: e.description,
                suggested_output_name: e.suggested_output_name,
                policy_hash_v1: hex::encode(canon.hash_v1().0),
                robdd_sem_hash_v1: hex::encode(sem.0 .0),
                nodes: canon.expr().node_count(),
                atoms,
                deny_if_atoms,
            });
        }

        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    // Default: simple tabular output, deterministic order.
    println!("id\tcategory\tpolicy_hash_v1\trobdd_sem_hash_v1\tnodes\tsuggested_output\ttitle");
    for e in policy_menu_entries_v1() {
        let canon = e
            .canonical(limits)
            .context("Failed to build canonical menu policy")?;
        let sem =
            policy_semantic_hash_robdd_v1(canon.expr(), limits).context("Failed to ROBDD-hash")?;
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            e.id,
            e.category,
            hex::encode(canon.hash_v1().0),
            hex::encode(sem.0 .0),
            canon.expr().node_count(),
            e.suggested_output_name,
            e.title
        );
    }
    Ok(())
}

pub fn menu_emit_tau(id: String, output_name: Option<String>, out: Option<PathBuf>) -> Result<()> {
    let limits = PolicyLimits::DEFAULT;
    let canon = policy_menu_canonical_v1(&id, limits).context("Failed to build menu policy")?;
    let output_name = output_name.unwrap_or_else(|| {
        policy_menu_entries_v1()
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.suggested_output_name.to_string())
            .unwrap_or_else(|| "allow".to_string())
    });
    let tau =
        emit_tau_gate_v2(canon.expr(), &output_name, limits).context("Failed to emit Tau gate")?;

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

pub fn menu_write_policy(id: String, out: PathBuf) -> Result<()> {
    let limits = PolicyLimits::DEFAULT;
    let canon = policy_menu_canonical_v1(&id, limits).context("Failed to build menu policy")?;
    fs::write(&out, canon.bytes_v1())
        .with_context(|| format!("Failed to write policy algebra bytes: {}", out.display()))?;
    println!("Wrote policy algebra v1 bytes to {}", out.display());
    Ok(())
}

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
    let tau = emit_tau_gate_v2(&expr, &output_name, limits).context("Failed to emit Tau gate")?;

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

pub fn bdd_hash(policy: PathBuf) -> Result<()> {
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
    let bdd = compile_allow_robdd(&expr, limits).context("Failed to compile ROBDD")?;

    println!("robdd_hash_v1: {}", hex::encode(bdd.hash_v1().0));
    Ok(())
}

pub fn diff(a: PathBuf, b: PathBuf) -> Result<()> {
    let a_bytes = fs::read(&a).with_context(|| format!("Failed to read: {}", a.display()))?;
    let b_bytes = fs::read(&b).with_context(|| format!("Failed to read: {}", b.display()))?;

    if a_bytes.len() > MAX_POLICY_ALGEBRA_BYTES {
        anyhow::bail!(
            "Policy algebra file A too large ({} > {} bytes)",
            a_bytes.len(),
            MAX_POLICY_ALGEBRA_BYTES
        );
    }
    if b_bytes.len() > MAX_POLICY_ALGEBRA_BYTES {
        anyhow::bail!(
            "Policy algebra file B too large ({} > {} bytes)",
            b_bytes.len(),
            MAX_POLICY_ALGEBRA_BYTES
        );
    }

    let limits = PolicyLimits::DEFAULT;
    let a_expr = decode_policy_v1(&a_bytes, limits).context("Failed to decode policy A")?;
    let b_expr = decode_policy_v1(&b_bytes, limits).context("Failed to decode policy B")?;

    let r = policy_equiv_robdd(&a_expr, &b_expr, limits).context("Failed to check equivalence")?;

    if r.equivalent {
        println!("equivalent: true");
        return Ok(());
    }

    println!("equivalent: false");
    if let Some(ce) = r.counterexample {
        // Simple stable print for copy/paste.
        for (k, v) in ce {
            match v {
                None => println!("  {k} = missing"),
                Some(true) => println!("  {k} = true"),
                Some(false) => println!("  {k} = false"),
            }
        }
    }

    Ok(())
}

pub fn certify_tau(policy: PathBuf, tau: PathBuf, output_name: String) -> Result<()> {
    let policy_bytes = fs::read(&policy)
        .with_context(|| format!("Failed to read policy algebra file: {}", policy.display()))?;
    let tau_src = fs::read_to_string(&tau)
        .with_context(|| format!("Failed to read Tau gate: {}", tau.display()))?;

    if policy_bytes.len() > MAX_POLICY_ALGEBRA_BYTES {
        anyhow::bail!(
            "Policy algebra file too large ({} > {} bytes)",
            policy_bytes.len(),
            MAX_POLICY_ALGEBRA_BYTES
        );
    }
    if tau_src.len() > MAX_POLICY_ALGEBRA_BYTES {
        anyhow::bail!(
            "Tau gate file too large ({} > {} bytes)",
            tau_src.len(),
            MAX_POLICY_ALGEBRA_BYTES
        );
    }

    let limits = PolicyLimits::DEFAULT;
    let policy_expr =
        decode_policy_v1(&policy_bytes, limits).context("Failed to decode policy algebra v1")?;
    let tau_expr = parse_emitted_tau_gate_allow_expr_v1(&tau_src, &output_name, limits)
        .context("Failed to parse emitted Tau gate allow expression")?;

    let r = policy_equiv_robdd_policy_vs_tau_bits(&policy_expr, &tau_expr, limits)
        .context("Failed to check semantic equivalence")?;

    if r.equivalent {
        println!("equivalent: true");
        return Ok(());
    }

    println!("equivalent: false");
    if let Some(ce) = r.counterexample {
        for (k, v) in ce {
            match v {
                None => println!("  {k} = missing"),
                Some(true) => println!("  {k} = true"),
                Some(false) => println!("  {k} = false"),
            }
        }
    }

    Ok(())
}
