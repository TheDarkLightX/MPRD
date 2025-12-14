//! MPRD CLI - Model Proposes, Rules Decide
//!
//! Command-line interface for managing MPRD pipelines, policies, and proofs.

use anyhow::Result;
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
        #[arg(short, long, default_value = "trustless")]
        mode: String,

        /// Allow insecure demo configuration.
        ///
        /// Required to generate a `local` config, since local mode implies an operator-trusted
        /// deployment that may use stubbed verification/attestation.
        #[arg(long, default_value_t = false)]
        insecure_demo: bool,
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

        /// Allow insecure demo behavior (allow-all policy evaluation and placeholder execution).
        ///
        /// This flag is required until production policy evaluation + verification are wired.
        #[arg(long, default_value_t = false)]
        insecure_demo: bool,
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

        /// Allow insecure demo behavior.
        ///
        /// This flag is required because `mprd prove` currently fabricates an allow-all
        /// `RuleVerdict` (i.e., it does not perform real policy evaluation).
        #[arg(long, default_value_t = false)]
        insecure_demo: bool,
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

        /// Allow insecure demo HTTP endpoints.
        ///
        /// This is required because the current server uses an allow-all policy engine and
        /// stub ZK components.
        #[arg(long, default_value_t = false)]
        insecure_demo: bool,
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
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match cli.command {
        Commands::Init {
            output,
            mode,
            insecure_demo,
        } => commands::init::run(output, mode, insecure_demo),
        Commands::Policy { action } => match action {
            PolicyCommands::Add { file, name } => commands::policy::add(file, name, cli.config),
            PolicyCommands::List { format } => commands::policy::list(format, cli.config),
            PolicyCommands::Get { hash, format } => commands::policy::get(hash, format, cli.config),
            PolicyCommands::Validate { file } => commands::policy::validate(file),
        },
        Commands::Run {
            policy,
            state,
            candidates,
            execute,
            format,
            insecure_demo,
        } => commands::run::run(
            policy,
            state,
            candidates,
            execute,
            format,
            insecure_demo,
            cli.config,
        ),
        Commands::Verify {
            proof,
            token,
            image_id,
        } => commands::verify::run(proof, token, image_id),
        Commands::Prove {
            decision,
            state,
            candidates,
            output,
            insecure_demo,
        } => commands::prove::run(
            decision,
            state,
            candidates,
            output,
            insecure_demo,
            cli.config,
        ),
        Commands::Status {
            check_tau,
            check_ipfs,
        } => commands::status::run(check_tau, check_ipfs, cli.config),
        Commands::Serve {
            bind,
            policy_dir,
            insecure_demo,
        } => commands::serve::run(bind, policy_dir, insecure_demo, cli.config),
    }
}
