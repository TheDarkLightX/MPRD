//! `mprd init` command implementation

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

use super::MprdConfigFile;

#[derive(Debug, Error, PartialEq, Eq)]
enum InitCommandError {
    #[error(
        "Refusing to initialize `local` mode without explicit acknowledgement. Re-run with `--insecure-demo` to generate an operator-trusted local config."
    )]
    LocalInsecureDemoRequired,
}

pub fn run(output: PathBuf, mode: String, insecure_demo: bool) -> Result<()> {
    if mode == "local" && !insecure_demo {
        return Err(InitCommandError::LocalInsecureDemoRequired.into());
    }

    println!("🔧 Initializing MPRD configuration...");

    // Create directory structure
    let mprd_dir = output.join(".mprd");
    fs::create_dir_all(&mprd_dir).context("Failed to create .mprd directory")?;

    fs::create_dir_all(mprd_dir.join("policies")).context("Failed to create policies directory")?;

    // Create config based on mode
    let config = match mode.as_str() {
        "local" => MprdConfigFile {
            mode: "local".into(),
            ..Default::default()
        },
        "trustless" => MprdConfigFile {
            mode: "trustless".into(),
            risc0_image_id: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            ..Default::default()
        },
        "private" => MprdConfigFile {
            mode: "private".into(),
            risc0_image_id: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            ..Default::default()
        },
        _ => {
            anyhow::bail!("Unknown mode: {}. Use local, trustless, or private.", mode);
        }
    };

    // Write config
    let config_path = mprd_dir.join("config.json");
    let config_json = serde_json::to_string_pretty(&config)?;
    fs::write(&config_path, config_json).context("Failed to write config file")?;

    println!("✅ Created configuration at {}", config_path.display());
    println!();
    println!("📁 Directory structure:");
    println!("   .mprd/");
    println!("   ├── config.json");
    println!("   └── policies/");
    println!();
    println!("🚀 Next steps:");
    println!("   1. Add a policy: mprd policy add --file my-policy.tau");
    println!("   2. Run pipeline:  mprd run --policy <hash> --state state.json --candidates candidates.json");

    if mode == "trustless" {
        println!();
        println!("⚠️  Trustless mode requires:");
        println!("   - Risc0 zkVM installed");
        println!("   - Guest program compiled and image ID set in config");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_fails_closed_for_local_without_insecure_demo() {
        let err = run(PathBuf::from("."), "local".into(), false)
            .expect_err("should refuse local init without insecure_demo");
        assert_eq!(
            err.downcast_ref::<InitCommandError>(),
            Some(&InitCommandError::LocalInsecureDemoRequired)
        );
    }
}
