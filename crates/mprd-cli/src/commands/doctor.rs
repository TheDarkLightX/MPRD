//! `mprd doctor` command - comprehensive preflight validation.
//!
//! Checks all components needed for MPRD to run correctly:
//! - Tau language binary
//! - IPFS daemon
//! - Risc0 configuration
//! - Anti-replay storage
//! - Policy directory structure
//! - Configuration sanity checks

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;

use super::{load_config, MprdConfigFile};

/// Diagnostic check result.
#[derive(Debug, Clone)]
pub enum CheckResult {
    Pass { message: String },
    Warn { message: String, suggestion: String },
    Fail { message: String, suggestion: String },
}

impl CheckResult {
    fn is_failure(&self) -> bool {
        matches!(self, CheckResult::Fail { .. })
    }
    
    fn is_warning(&self) -> bool {
        matches!(self, CheckResult::Warn { .. })
    }
}

/// Run all diagnostic checks.
pub fn run(config_path: Option<PathBuf>, verbose: bool) -> Result<()> {
    println!("🩺 MPRD Doctor - System Diagnostics\n");
    
    let config = load_config(config_path.clone())?;
    
    let mut results: Vec<(&str, CheckResult)> = Vec::new();
    
    // 1. Config file check
    results.push(("Config file", check_config_file(&config_path)));
    
    // 2. Tau binary check
    results.push(("Tau language", check_tau_binary(&config)));
    
    // 3. IPFS check (if configured)
    if config.policy_storage.storage_type == "ipfs" {
        results.push(("IPFS daemon", check_ipfs(&config)));
    }
    
    // 4. Risc0 configuration
    results.push(("Risc0 ZK", check_risc0(&config)));
    
    // 5. Policy storage directory
    results.push(("Policy storage", check_policy_storage(&config)));
    
    // 6. Execution configuration
    results.push(("Executor", check_executor(&config)));
    
    // 7. Anti-replay configuration
    results.push(("Anti-replay", check_anti_replay(&config)));
    
    // Print results
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let mut failures = 0;
    let mut warnings = 0;
    
    for (name, result) in &results {
        match result {
            CheckResult::Pass { message } => {
                println!("✅ {}: {}", name, message);
                if verbose {
                    println!();
                }
            }
            CheckResult::Warn { message, suggestion } => {
                warnings += 1;
                println!("⚠️  {}: {}", name, message);
                println!("   💡 {}", suggestion);
                println!();
            }
            CheckResult::Fail { message, suggestion } => {
                failures += 1;
                println!("❌ {}: {}", name, message);
                println!("   💡 {}", suggestion);
                println!();
            }
        }
    }
    
    // Summary
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    if failures > 0 {
        println!("❌ {} check(s) failed, {} warning(s)", failures, warnings);
        println!("\n   Fix the issues above before running MPRD in production.");
        std::process::exit(1);
    } else if warnings > 0 {
        println!("⚠️  All required checks passed, {} warning(s)", warnings);
        println!("\n   MPRD can run, but review the warnings above.");
    } else {
        println!("✅ All checks passed!");
        println!("\n   MPRD is ready for mode: {}", config.mode);
    }
    
    Ok(())
}

fn check_config_file(path: &Option<PathBuf>) -> CheckResult {
    let default_path = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mprd")
        .join("config.json");
    
    let check_path = path.as_ref().unwrap_or(&default_path);
    
    if check_path.exists() {
        CheckResult::Pass {
            message: format!("Found at {}", check_path.display()),
        }
    } else {
        CheckResult::Warn {
            message: format!("Not found at {}", check_path.display()),
            suggestion: "Run 'mprd init' to create a default config".into(),
        }
    }
}

fn check_tau_binary(config: &MprdConfigFile) -> CheckResult {
    let tau_binary = config.tau_binary.as_deref().unwrap_or("tau");
    
    match Command::new(tau_binary).arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            CheckResult::Pass {
                message: format!("{} ({})", tau_binary, version.trim()),
            }
        }
        Ok(_) => CheckResult::Fail {
            message: format!("Binary '{}' found but returned error", tau_binary),
            suggestion: "Ensure Tau is correctly installed: https://github.com/IDNI/tau-lang".into(),
        },
        Err(_) => CheckResult::Fail {
            message: format!("Binary '{}' not found", tau_binary),
            suggestion: "Install Tau: https://github.com/IDNI/tau-lang".into(),
        },
    }
}

fn check_ipfs(config: &MprdConfigFile) -> CheckResult {
    let ipfs_url = config
        .policy_storage
        .ipfs_url
        .as_deref()
        .unwrap_or("http://localhost:5001");
    
    // Validate URL first
    if let Err(e) = mprd_adapters::egress::validate_outbound_url(ipfs_url) {
        return CheckResult::Fail {
            message: format!("Invalid IPFS URL: {}", e),
            suggestion: "Use a valid URL like http://localhost:5001".into(),
        };
    }
    
    let client = match reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return CheckResult::Fail {
                message: format!("Could not create HTTP client: {}", e),
                suggestion: "Check your network configuration".into(),
            };
        }
    };
    
    let version_url = format!("{}/api/v0/version", ipfs_url);
    
    match client.post(&version_url).send() {
        Ok(response) if response.status().is_success() => CheckResult::Pass {
            message: format!("Connected to {}", ipfs_url),
        },
        Ok(response) => CheckResult::Fail {
            message: format!("IPFS returned status {}", response.status()),
            suggestion: "Ensure IPFS daemon is running: ipfs daemon".into(),
        },
        Err(_) => CheckResult::Fail {
            message: format!("Cannot connect to {}", ipfs_url),
            suggestion: "Start IPFS daemon: ipfs daemon".into(),
        },
    }
}

fn check_risc0(config: &MprdConfigFile) -> CheckResult {
    match &config.risc0_image_id {
        Some(id) if id.chars().all(|c| c == '0') => CheckResult::Warn {
            message: "Placeholder image ID (all zeros)".into(),
            suggestion: "For production, build and set the real RISC0_IMAGE_ID".into(),
        },
        Some(id) if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) => {
            CheckResult::Pass {
                message: format!("Image ID: {}...", &id[..16]),
            }
        }
        Some(id) => CheckResult::Fail {
            message: format!("Invalid image ID format: {}...", &id[..id.len().min(16)]),
            suggestion: "Image ID must be 64 hex characters".into(),
        },
        None => CheckResult::Fail {
            message: "No risc0_image_id configured".into(),
            suggestion: "Add risc0_image_id to config for trustless mode".into(),
        },
    }
}

fn check_policy_storage(config: &MprdConfigFile) -> CheckResult {
    match config.policy_storage.storage_type.as_str() {
        "local" => {
            if let Some(ref dir) = config.policy_storage.local_dir {
                if dir.exists() && dir.is_dir() {
                    CheckResult::Pass {
                        message: format!("Local directory: {}", dir.display()),
                    }
                } else {
                    CheckResult::Warn {
                        message: format!("Directory does not exist: {}", dir.display()),
                        suggestion: "Run 'mprd init' or create the directory manually".into(),
                    }
                }
            } else {
                CheckResult::Fail {
                    message: "local_dir not configured".into(),
                    suggestion: "Add local_dir to policy_storage config".into(),
                }
            }
        }
        "ipfs" => CheckResult::Pass {
            message: "Using IPFS storage".into(),
        },
        other => CheckResult::Warn {
            message: format!("Unknown storage type: {}", other),
            suggestion: "Use 'local' or 'ipfs'".into(),
        },
    }
}

fn check_executor(config: &MprdConfigFile) -> CheckResult {
    match config.execution.executor_type.as_str() {
        "noop" => CheckResult::Pass {
            message: "NoOp executor (no side effects)".into(),
        },
        "http" => {
            if let Some(ref url) = config.execution.http_url {
                if let Err(e) = mprd_adapters::egress::validate_outbound_url(url) {
                    CheckResult::Fail {
                        message: format!("Invalid HTTP URL: {}", e),
                        suggestion: "Use a valid URL".into(),
                    }
                } else {
                    CheckResult::Pass {
                        message: format!("HTTP executor: {}", url),
                    }
                }
            } else {
                CheckResult::Fail {
                    message: "http_url not configured".into(),
                    suggestion: "Add http_url to execution config".into(),
                }
            }
        }
        "file" => {
            if let Some(ref path) = config.execution.audit_file {
                CheckResult::Pass {
                    message: format!("File executor: {}", path.display()),
                }
            } else {
                CheckResult::Fail {
                    message: "audit_file not configured".into(),
                    suggestion: "Add audit_file to execution config".into(),
                }
            }
        }
        other => CheckResult::Warn {
            message: format!("Unknown executor type: {}", other),
            suggestion: "Use 'noop', 'http', or 'file'".into(),
        },
    }
}

fn check_anti_replay(config: &MprdConfigFile) -> CheckResult {
    // Check if anti-replay storage can be created
    let anti_replay_dir = config
        .anti_replay
        .as_ref()
        .and_then(|cfg| cfg.nonce_store_dir.as_ref())
        .cloned()
        .unwrap_or_else(|| PathBuf::from(".mprd/anti_replay"));
    
    if anti_replay_dir.exists() {
        CheckResult::Pass {
            message: format!("Directory exists: {}", anti_replay_dir.display()),
        }
    } else {
        // Try to create it
        match std::fs::create_dir_all(&anti_replay_dir) {
            Ok(_) => {
                // Clean up
                let _ = std::fs::remove_dir(&anti_replay_dir);
                CheckResult::Pass {
                    message: "Can create anti-replay storage".into(),
                }
            }
            Err(e) => CheckResult::Warn {
                message: format!("Cannot create anti-replay dir: {}", e),
                suggestion: "Ensure write permissions for .mprd/ directory".into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_is_failure() {
        let pass = CheckResult::Pass { message: "ok".into() };
        let warn = CheckResult::Warn { 
            message: "warn".into(), 
            suggestion: "fix".into() 
        };
        let fail = CheckResult::Fail { 
            message: "fail".into(), 
            suggestion: "fix".into() 
        };
        
        assert!(!pass.is_failure());
        assert!(!warn.is_failure());
        assert!(fail.is_failure());
    }
}
