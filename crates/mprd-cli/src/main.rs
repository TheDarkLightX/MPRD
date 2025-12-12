//! MPRD CLI - Model Proposes, Rules Decide
//!
//! Command-line interface for managing MPRD pipelines, policies, and proofs.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;

/// MPRD: Model Proposes, Rules Decide
///
/// A trustless AI alignment architecture where models propose actions
/// and deterministic rules decide which are executed.
#[derive(Parser)]
#[command(name = "mprd")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
    
    /// Config file path
    #[arg(short, long, global = true, env = "MPRD_CONFIG")]
    config: Option<PathBuf>,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new MPRD configuration
    Init {
        /// Output directory for config
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        
        /// Deployment mode (local, trustless, private)
        #[arg(short, long, default_value = "local")]
        mode: String,
    },
    
    /// Manage policies
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },
    
    /// Run the MPRD pipeline
    Run {
        /// Policy hash to use
        #[arg(short, long)]
        policy: String,
        
        /// State file (JSON)
        #[arg(short, long)]
        state: PathBuf,
        
        /// Candidates file (JSON)
        #[arg(short, long)]
        candidates: PathBuf,
        
        /// Execute the selected action (otherwise dry run)
        #[arg(short, long)]
        execute: bool,
        
        /// Output format (json, human)
        #[arg(short, long, default_value = "human")]
        format: String,
    },
    
    /// Verify a proof bundle
    Verify {
        /// Proof bundle file (JSON)
        #[arg(short, long)]
        proof: PathBuf,
        
        /// Token file (JSON)
        #[arg(short, long)]
        token: PathBuf,
        
        /// Expected image ID for Risc0 verification
        #[arg(short, long)]
        image_id: Option<String>,
    },
    
    /// Generate a proof for a decision
    Prove {
        /// Decision file (JSON)
        #[arg(short, long)]
        decision: PathBuf,
        
        /// State file (JSON)
        #[arg(short, long)]
        state: PathBuf,
        
        /// Candidates file (JSON)
        #[arg(short, long)]
        candidates: PathBuf,
        
        /// Output proof file
        #[arg(short, long)]
        output: PathBuf,
    },
    
    /// Show system status
    Status {
        /// Check Tau binary availability
        #[arg(long)]
        check_tau: bool,
        
        /// Check IPFS availability
        #[arg(long)]
        check_ipfs: bool,
    },
    
    /// Serve MPRD as an HTTP API
    Serve {
        /// Bind address
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        bind: String,
        
        /// Policy storage directory
        #[arg(short, long)]
        policy_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Add a new policy
    Add {
        /// Policy file (Tau specification)
        #[arg(short, long)]
        file: PathBuf,
        
        /// Policy name/description
        #[arg(short, long)]
        name: Option<String>,
    },
    
    /// List all policies
    List {
        /// Output format (json, table)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    
    /// Get policy details
    Get {
        /// Policy hash (hex)
        hash: String,
        
        /// Output format (json, raw)
        #[arg(short, long, default_value = "json")]
        format: String,
    },
    
    /// Validate a policy file
    Validate {
        /// Policy file to validate
        #[arg(short, long)]
        file: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
    
    match cli.command {
        Commands::Init { output, mode } => {
            commands::init::run(output, mode)
        }
        Commands::Policy { action } => {
            match action {
                PolicyCommands::Add { file, name } => {
                    commands::policy::add(file, name, cli.config)
                }
                PolicyCommands::List { format } => {
                    commands::policy::list(format, cli.config)
                }
                PolicyCommands::Get { hash, format } => {
                    commands::policy::get(hash, format, cli.config)
                }
                PolicyCommands::Validate { file } => {
                    commands::policy::validate(file)
                }
            }
        }
        Commands::Run { policy, state, candidates, execute, format } => {
            commands::run::run(policy, state, candidates, execute, format, cli.config)
        }
        Commands::Verify { proof, token, image_id } => {
            commands::verify::run(proof, token, image_id)
        }
        Commands::Prove { decision, state, candidates, output } => {
            commands::prove::run(decision, state, candidates, output, cli.config)
        }
        Commands::Status { check_tau, check_ipfs } => {
            commands::status::run(check_tau, check_ipfs, cli.config)
        }
        Commands::Serve { bind, policy_dir } => {
            commands::serve::run(bind, policy_dir, cli.config)
        }
    }
}
