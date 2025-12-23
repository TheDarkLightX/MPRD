//! `mprd status` command implementation

use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;

use super::load_config;

pub fn run(check_tau: bool, check_ipfs: bool, config_path: Option<PathBuf>) -> Result<()> {
    let config = load_config(config_path)?;

    println!("📊 MPRD Status");
    println!();

    // Mode
    println!("⚙️  Configuration");
    println!("   Mode: {}", config.mode);
    println!("   Policy storage: {}", config.policy_storage.storage_type);
    if let Some(ref dir) = config.policy_storage.local_dir {
        println!("   Storage dir: {}", dir.display());
    }
    println!();

    // Check Tau
    if check_tau {
        println!("🔧 Tau Language");
        let tau_binary = config.tau_binary.as_deref().unwrap_or("tau");

        match Command::new(tau_binary).arg("--version").output() {
            Ok(output) => {
                if output.status.success() {
                    let version = String::from_utf8_lossy(&output.stdout);
                    println!("   Status: ✅ Available");
                    println!("   Binary: {}", tau_binary);
                    println!("   Version: {}", version.trim());
                } else {
                    println!("   Status: ⚠️ Binary found but returned error");
                    println!("   Binary: {}", tau_binary);
                }
            }
            Err(_) => {
                println!("   Status: ❌ Not available");
                println!("   Binary: {} (not found)", tau_binary);
                println!();
                println!("   To use Tau-based policies, install the Tau language:");
                println!("   https://github.com/IDNI/tau-lang");
            }
        }
        println!();
    }

    // Check IPFS
    if check_ipfs {
        println!("🌐 IPFS");
        let ipfs_url = config
            .policy_storage
            .ipfs_url
            .as_deref()
            .unwrap_or("http://localhost:5001");

        if let Err(e) = mprd_adapters::egress::validate_outbound_url(ipfs_url) {
            println!("   Status: ❌ Invalid IPFS URL");
            println!("   URL: {}", ipfs_url);
            println!("   Error: {}", e);
            println!();
        } else {
            let client = reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .build()?;

            let version_url = format!("{}/api/v0/version", ipfs_url);

            match client.post(&version_url).send() {
                Ok(response) => {
                    if response.status().is_success() {
                        #[derive(serde::Deserialize)]
                        struct VersionResponse {
                            #[serde(rename = "Version")]
                            version: String,
                        }

                        if let Ok(ver) = response.json::<VersionResponse>() {
                            println!("   Status: ✅ Available");
                            println!("   URL: {}", ipfs_url);
                            println!("   Version: {}", ver.version);
                        } else {
                            println!("   Status: ⚠️ Connected but couldn't parse version");
                        }
                    } else {
                        println!("   Status: ⚠️ Connected but returned error");
                    }
                }
                Err(_) => {
                    println!("   Status: ❌ Not available");
                    println!("   URL: {}", ipfs_url);
                    println!();
                    println!("   To use IPFS storage, start an IPFS daemon:");
                    println!("   ipfs daemon");
                }
            }
            println!();
        }
    }

    // Risc0 status
    println!("🔐 Risc0 ZK");
    if let Some(ref image_id) = config.risc0_image_id {
        if image_id == "0000000000000000000000000000000000000000000000000000000000000000" {
            println!("   Status: ⚠️ Placeholder image ID (not production ready)");
        } else {
            println!("   Status: ✅ Configured");
            println!("   Image ID: {}...", &image_id[..16]);
        }
    } else {
        println!("   Status: ❌ Not configured");
        println!("   Mode {} requires risc0_image_id in config", config.mode);
    }
    println!();

    // Summary
    let all_good = !check_tau && !check_ipfs; // Simplistic check
    if all_good {
        println!("✅ MPRD is ready for {} mode", config.mode);
    } else {
        println!("⚠️ Some components may need configuration");
    }

    Ok(())
}
