//! MPRD CLI - Model Proposes, Rules Decide
//!
//! Command-line interface for managing MPRD pipelines, policies, and proofs.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod operator;

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

        /// Output decision JSON file (for chaining to `mprd prove`)
        #[arg(long)]
        decision_out: Option<PathBuf>,

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

        /// Expected image ID for Risc0 verification (dev-only).
        #[arg(short, long)]
        image_id: Option<String>,

        /// Signed registry checkpoint (JSON) for production, fail-closed verification.
        ///
        /// When provided, `mprd verify` routes the expected ImageID from the registry state and
        /// enforces policy authorization at `(policy_epoch, registry_root)` (recommended).
        #[arg(long)]
        registry_state: Option<PathBuf>,

        /// Verifying key (hex, 32 bytes) for `--registry-state`.
        #[arg(long, requires = "registry_state")]
        registry_key_hex: Option<String>,

        /// Manifest verifying key (hex, 32 bytes) for `--registry-state`.
        ///
        /// If omitted, defaults to `--registry-key-hex` (legacy single-key deployments).
        #[arg(long, requires = "registry_state")]
        manifest_key_hex: Option<String>,

        /// Allow dev-only verification without registry-state authorization.
        ///
        /// This accepts a receipt verified only against an explicit `--image-id` (no registry
        /// authorization context).
        #[arg(long, default_value_t = false)]
        insecure_demo: bool,
    },

    /// Production deployment wiring utilities (bundle validation)
    Deploy {
        #[command(subcommand)]
        action: DeployCommands,
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

        /// Output token file (JSON). Defaults to `<output>.token.json`.
        #[arg(long)]
        token_output: Option<PathBuf>,

        // --- Production wiring (recommended) ---
        /// Signed registry checkpoint (JSON) for production proving.
        #[arg(long)]
        registry_state: Option<PathBuf>,

        /// Registry checkpoint verifying key (hex, 32 bytes) for `--registry-state`.
        #[arg(long, requires = "registry_state")]
        registry_key_hex: Option<String>,

        /// Manifest verifying key (hex, 32 bytes) for `--registry-state`.
        ///
        /// If omitted, defaults to `--registry-key-hex`.
        #[arg(long, requires = "registry_state")]
        manifest_key_hex: Option<String>,

        /// Directory containing policy artifact files named `<hex(policy_hash)>`.
        #[arg(long, requires = "registry_state")]
        policy_artifacts_dir: Option<PathBuf>,

        /// Token signing key seed (hex, 32 bytes).
        #[arg(long, requires = "registry_state")]
        token_signing_key_hex: Option<String>,

        /// Nonce / tx hash (hex, 32 bytes). Must come from the triggering request/chain tx.
        #[arg(long, requires = "registry_state")]
        nonce_or_tx_hash_hex: Option<String>,

        /// Optional timestamp override (milliseconds since epoch). Defaults to local clock.
        #[arg(long, requires = "registry_state")]
        timestamp_ms: Option<i64>,

        /// State provenance: source id (hex, 32 bytes).
        #[arg(long, requires = "registry_state")]
        state_source_id_hex: Option<String>,

        /// State provenance: epoch (u64).
        #[arg(long, requires = "registry_state")]
        state_epoch: Option<u64>,

        /// State provenance: attestation hash (hex, 32 bytes).
        #[arg(long, requires = "registry_state")]
        state_attestation_hash_hex: Option<String>,

        /// Allow insecure demo behavior (no registry-state anchoring).
        ///
        /// Use this only for local experimentation. Production proving should supply
        /// `--registry-state` + keys + policy artifacts and should not require this flag.
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

    /// Run comprehensive system diagnostics (preflight checks)
    Doctor {
        /// Show verbose output for passing checks
        #[arg(long)]
        verbose: bool,
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

    /// Operator control panel (retro, high-signal)
    Panel {
        /// Refresh interval in milliseconds (watch mode).
        #[arg(long)]
        watch_ms: Option<u64>,

        /// Render width (characters).
        #[arg(long, default_value_t = 96)]
        width: usize,

        /// Operator store directory (defaults to `MPRD_OPERATOR_STORE_DIR` or `.mprd/operator`).
        #[arg(long)]
        store_dir: Option<PathBuf>,

        /// Policy directory (defaults to `.mprd/policies`).
        #[arg(long)]
        policy_dir: Option<PathBuf>,
    },

    /// Fee router utilities (settlement receipt commitments)
    FeeRouter {
        #[command(subcommand)]
        action: FeeRouterCommands,
    },

    /// Models market utilities (sign/verify/checkpoint)
    ModelsMarket {
        #[command(subcommand)]
        action: ModelsMarketCommands,
    },

    /// Agoras Staking Discount Engine (ASDE) utilities (epoch runner, checkpoints)
    Asde {
        #[command(subcommand)]
        action: AsdeCommands,
    },

    /// Tokenomics utilities (v6)
    Tokenomics {
        #[command(subcommand)]
        action: TokenomicsCommands,
    },
}

#[derive(Subcommand)]
enum FeeRouterCommands {
    /// Compute a Tau settlement receipt commitment hash.
    SettlementReceiptHash {
        /// Tau settlement transaction id (32-byte hex).
        #[arg(long)]
        tau_tx_id_hex: String,
        /// Tau block reference (32-byte hex; deployment-defined).
        #[arg(long)]
        tau_block_ref_hex: String,
        /// Fee payer identity (32-byte hex; deployment-defined).
        #[arg(long)]
        fee_payer_hex: String,
        /// Fee amount (u128 decimal).
        #[arg(long)]
        fee_amount_u128_dec: String,
        /// L2 batch id (32-byte hex).
        #[arg(long)]
        batch_id_hex: String,
    },
}

#[derive(Subcommand)]
enum DeployCommands {
    /// Validate a production bundle (registry checkpoint + manifest + policy artifacts).
    ///
    /// This is a fail-closed check intended to catch "prove something that will never verify"
    /// deployments before you go live.
    CheckBundle {
        /// Signed registry checkpoint (JSON).
        #[arg(long)]
        registry_state: PathBuf,

        /// Registry checkpoint verifying key (hex, 32 bytes).
        #[arg(long)]
        registry_key_hex: String,

        /// Manifest verifying key (hex, 32 bytes).
        ///
        /// If omitted, defaults to `--registry-key-hex`.
        #[arg(long)]
        manifest_key_hex: Option<String>,

        /// Directory containing policy artifact files named `<hex(policy_hash)>`.
        #[arg(long)]
        policy_artifacts_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum ModelsMarketCommands {
    /// Build an unsigned models market snapshot from an epoch input file (JSON).
    BuildSnapshot {
        /// Epoch input JSON file (miners + validator reports).
        #[arg(short, long)]
        input: PathBuf,
        /// Output unsigned snapshot JSON file.
        #[arg(short, long)]
        output: PathBuf,
        /// Optional trim parameter override in basis points (0..=4900).
        #[arg(long)]
        trim_bps: Option<u16>,
    },

    /// Build and sign a snapshot + checkpoint for one epoch (off-chain runner).
    StepEpoch {
        /// Epoch input JSON file (miners + validator reports).
        #[arg(short, long)]
        input: PathBuf,
        /// Output signed snapshot JSON file.
        #[arg(long)]
        signed_snapshot_out: PathBuf,
        /// Output signed checkpoint JSON file.
        #[arg(long)]
        signed_checkpoint_out: PathBuf,
        /// Previous checkpoint hash hex (32 bytes). Use 64 zeros for genesis.
        #[arg(long)]
        prev_checkpoint_hash_hex: String,
        /// Signing key seed hex (32 bytes, 64 hex chars).
        #[arg(long)]
        signing_key_hex: String,
        /// Optional trim parameter override in basis points (0..=4900).
        #[arg(long)]
        trim_bps: Option<u16>,
    },

    /// Sign an unsigned models market snapshot (JSON) to produce a signed snapshot (JSON).
    SignSnapshot {
        /// Unsigned snapshot JSON file.
        #[arg(short, long)]
        input: PathBuf,
        /// Output signed snapshot JSON file.
        #[arg(short, long)]
        output: PathBuf,
        /// Signing key seed hex (32 bytes, 64 hex chars).
        #[arg(long)]
        signing_key_hex: String,
    },

    /// Verify a signed models market snapshot (JSON).
    VerifySnapshot {
        /// Signed snapshot JSON file.
        #[arg(short, long)]
        input: PathBuf,
        /// Expected verifying key hex (32 bytes, 64 hex chars).
        #[arg(long)]
        verifying_key_hex: String,
    },

    /// Create and sign a models market checkpoint for a signed snapshot.
    SignCheckpoint {
        /// Signed snapshot JSON file.
        #[arg(short, long)]
        snapshot: PathBuf,
        /// Output signed checkpoint JSON file.
        #[arg(short, long)]
        output: PathBuf,
        /// Signing key seed hex (32 bytes, 64 hex chars).
        #[arg(long)]
        signing_key_hex: String,
        /// Previous checkpoint hash hex (32 bytes, 64 hex chars), or all-zeroes for genesis.
        #[arg(long)]
        prev_checkpoint_hash_hex: String,
    },

    /// Verify a signed models market checkpoint (JSON).
    VerifyCheckpoint {
        /// Signed checkpoint JSON file.
        #[arg(short, long)]
        input: PathBuf,
        /// Expected verifying key hex (32 bytes, 64 hex chars).
        #[arg(long)]
        verifying_key_hex: String,
        /// Optional expected previous checkpoint hash hex (32 bytes).
        #[arg(long)]
        expected_prev_checkpoint_hash_hex: Option<String>,
    },
}

#[derive(Subcommand)]
enum AsdeCommands {
    /// Compute an ASDE epoch from JSON inputs and produce a signed checkpoint + updated state.
    StepEpoch {
        /// Epoch id being computed.
        #[arg(long)]
        epoch_id: u64,
        /// Positions state JSON file (read); if missing and `--allow_empty_state` is set, starts empty.
        #[arg(long)]
        state_in: PathBuf,
        /// Updated positions state JSON file (write).
        #[arg(long)]
        state_out: PathBuf,
        /// Stake events JSON file (list of `StakeEventV1`) for this epoch.
        #[arg(long)]
        stake_events: PathBuf,
        /// Fee events JSON file (list of `FeeEventV1`) for this epoch.
        #[arg(long)]
        fee_events: PathBuf,
        /// DF table JSON file: list of u64 Q32.32 values, indexed by day (must include day 0).
        #[arg(long)]
        df_table: PathBuf,
        /// ASDE params JSON file (deployment-specific).
        #[arg(long)]
        params: PathBuf,
        /// Current difficulty (u128, Q32.32) as decimal.
        #[arg(long)]
        difficulty_e_q32_32: String,
        /// Output epoch summary JSON file.
        #[arg(long)]
        epoch_summary_out: PathBuf,
        /// Output voucher grants JSON file (list of `VoucherGrantV1`).
        #[arg(long)]
        voucher_grants_out: PathBuf,
        /// Previous ASDE checkpoint hash hex (32 bytes), or all-zeroes for genesis.
        #[arg(long)]
        prev_checkpoint_hash_hex: String,
        /// Output signed checkpoint JSON file.
        #[arg(long)]
        checkpoint_out: PathBuf,
        /// Signing key seed hex (32 bytes, 64 hex chars).
        #[arg(long)]
        signing_key_hex: String,
        /// Allow starting from an empty state when `--state-in` does not exist.
        #[arg(long, default_value_t = false)]
        allow_empty_state: bool,
    },

    /// Verify a signed ASDE checkpoint (JSON) against an expected verifying key.
    VerifyCheckpoint {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        verifying_key_hex: String,
    },

    /// Compute net service fee after applying unexpired ASDE voucher grants for a user.
    ComputeServiceFeeDiscount {
        /// Service fee amount in SFA (u128 decimal).
        #[arg(long)]
        service_fee_sfa: String,
        /// Voucher grants JSON file (list of `VoucherGrantV1`).
        #[arg(long)]
        voucher_grants: PathBuf,
        /// Voucher spends JSON file (list of `VoucherSpendV1`).
        ///
        /// When omitted, all unexpired grants are treated as available (pre-testnet convenience).
        #[arg(long)]
        voucher_spends: Option<PathBuf>,
        /// User pubkey hex (32 bytes).
        #[arg(long)]
        user_pubkey_hex: String,
        /// Current epoch id (used to filter expired grants).
        #[arg(long)]
        epoch_id: u64,
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

    /// Verify a policy WFF and optional test cases
    Verify {
        /// Policy file to verify
        #[arg(short, long)]
        file: PathBuf,

        /// Optional JSON test cases file
        #[arg(long)]
        cases: Option<PathBuf>,
    },

    /// Test a policy against JSON test cases
    Test {
        /// Policy artifact file (mpb-v1)
        #[arg(long)]
        policy: PathBuf,

        /// JSON test cases file
        #[arg(long)]
        tests: PathBuf,
    },

    /// Emit a canonical Tau gate from a Policy Algebra v1 binary.
    ///
    /// This is primarily an audit / interoperability utility: it lets you author a boolean
    /// gate as a Policy Algebra AST, then emit an sbf-only Tau spec that enforces the same
    /// allow/deny predicate.
    AlgebraEmitTau {
        /// Policy Algebra v1 bytes (binary file).
        #[arg(long)]
        policy: PathBuf,

        /// Output name (controls `o_<name>` and `outputs/<name>.out`).
        #[arg(long, default_value = "allow")]
        output_name: String,

        /// Write to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Certify a Tau gate against a Policy Algebra v1 binary (ROBDD-based).
    ///
    /// This parses the sbf-only allow predicate from the Tau gate and proves semantic
    /// equivalence against the policy algebra input by ROBDD comparison (with counterexample).
    AlgebraCertifyTau {
        /// Policy Algebra v1 bytes (binary file).
        #[arg(long)]
        policy: PathBuf,

        /// Tau gate file emitted by `mprd policy algebra-emit-tau` (or equivalent).
        #[arg(long)]
        tau: PathBuf,

        /// Output name (controls `o_<name>[t] = ...` line to extract).
        #[arg(long, default_value = "allow")]
        output_name: String,
    },

    /// Compute a semantic ROBDD hash for a Policy Algebra v1 binary.
    ///
    /// This hash commits to the *boolean function* (given canonical atom order) and is stable
    /// across benign refactors that preserve semantics.
    AlgebraBddHash {
        /// Policy Algebra v1 bytes (binary file).
        #[arg(long)]
        policy: PathBuf,
    },

    /// Compare two Policy Algebra v1 binaries for semantic equivalence (ROBDD-based).
    ///
    /// If not equivalent, prints a concrete counterexample assignment.
    AlgebraDiff {
        /// Policy Algebra v1 bytes (binary file).
        #[arg(long)]
        a: PathBuf,

        /// Policy Algebra v1 bytes (binary file).
        #[arg(long)]
        b: PathBuf,
    },
}

#[derive(Subcommand)]
enum TokenomicsCommands {
    /// Propose a v6 PID parameter update (bounded, deterministic).
    ///
    /// This is a local helper to compute a candidate update that should then be
    /// verified by Tau (`mprd_tokenomics_v6_pid_update_gate.tau`) before being applied.
    PidProposeV6 {
        #[arg(long)]
        cur_burn_surplus_bps: u16,
        #[arg(long)]
        cur_auction_surplus_bps: u16,
        #[arg(long)]
        cur_drip_rate_bps: u16,

        #[arg(long)]
        burn_setpoint_bps: u16,
        #[arg(long)]
        burn_measured_bps: u16,

        #[arg(long)]
        auction_setpoint_bps: u16,
        #[arg(long)]
        auction_measured_bps: u16,

        #[arg(long)]
        drip_setpoint_bps: u16,
        #[arg(long)]
        drip_measured_bps: u16,

        #[arg(long, default_value = "human")]
        format: String,
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
            PolicyCommands::Verify { file, cases } => {
                commands::policy_verify::run(file, cases, cli.config)
            }
            PolicyCommands::Test { policy, tests } => commands::policy_test::run(policy, tests),
            PolicyCommands::AlgebraEmitTau {
                policy,
                output_name,
                out,
            } => commands::policy_algebra::emit_tau(policy, output_name, out),
            PolicyCommands::AlgebraCertifyTau {
                policy,
                tau,
                output_name,
            } => commands::policy_algebra::certify_tau(policy, tau, output_name),
            PolicyCommands::AlgebraBddHash { policy } => commands::policy_algebra::bdd_hash(policy),
            PolicyCommands::AlgebraDiff { a, b } => commands::policy_algebra::diff(a, b),
        },
        Commands::Run {
            policy,
            state,
            candidates,
            execute,
            format,
            decision_out,
            insecure_demo,
        } => commands::run::run(
            policy,
            state,
            candidates,
            execute,
            format,
            decision_out,
            insecure_demo,
            cli.config,
        ),
        Commands::Verify {
            proof,
            token,
            image_id,
            registry_state,
            registry_key_hex,
            manifest_key_hex,
            insecure_demo,
        } => commands::verify::run(
            proof,
            token,
            image_id,
            registry_state,
            registry_key_hex,
            manifest_key_hex,
            insecure_demo,
        ),
        Commands::Deploy { action } => match action {
            DeployCommands::CheckBundle {
                registry_state,
                registry_key_hex,
                manifest_key_hex,
                policy_artifacts_dir,
            } => commands::deploy::check_bundle(
                registry_state,
                registry_key_hex,
                manifest_key_hex,
                policy_artifacts_dir,
            ),
        },
        Commands::Prove {
            decision,
            state,
            candidates,
            output,
            token_output,
            registry_state,
            registry_key_hex,
            manifest_key_hex,
            policy_artifacts_dir,
            token_signing_key_hex,
            nonce_or_tx_hash_hex,
            timestamp_ms,
            state_source_id_hex,
            state_epoch,
            state_attestation_hash_hex,
            insecure_demo,
        } => {
            let production =
                registry_state.map(|registry_state_path| commands::prove::ProveProductionArgs {
                    registry_state_path,
                    registry_key_hex,
                    manifest_key_hex,
                    policy_artifacts_dir,
                    token_signing_key_hex,
                    nonce_or_tx_hash_hex,
                    timestamp_ms,
                    state_source_id_hex,
                    state_epoch,
                    state_attestation_hash_hex,
                });

            commands::prove::run(commands::prove::ProveCommand {
                decision_path: decision,
                state_path: state,
                candidates_path: candidates,
                output_path: output,
                token_output,
                production,
                insecure_demo,
                config_path: cli.config,
            })
        }
        Commands::Status {
            check_tau,
            check_ipfs,
        } => commands::status::run(check_tau, check_ipfs, cli.config.clone()),
        Commands::Doctor { verbose } => commands::doctor::run(cli.config, verbose),
        Commands::Serve {
            bind,
            policy_dir,
            insecure_demo,
        } => commands::serve::run(bind, policy_dir, insecure_demo, cli.config),
        Commands::Panel {
            watch_ms,
            width,
            store_dir,
            policy_dir,
        } => commands::panel::run(watch_ms, width, policy_dir, store_dir),
        Commands::FeeRouter { action } => match action {
            FeeRouterCommands::SettlementReceiptHash {
                tau_tx_id_hex,
                tau_block_ref_hex,
                fee_payer_hex,
                fee_amount_u128_dec,
                batch_id_hex,
            } => commands::fees::settlement_receipt_hash(
                tau_tx_id_hex,
                tau_block_ref_hex,
                fee_payer_hex,
                fee_amount_u128_dec,
                batch_id_hex,
            ),
        },
        Commands::ModelsMarket { action } => match action {
            ModelsMarketCommands::BuildSnapshot {
                input,
                output,
                trim_bps,
            } => commands::markets::build_snapshot(input, output, trim_bps),
            ModelsMarketCommands::StepEpoch {
                input,
                signed_snapshot_out,
                signed_checkpoint_out,
                prev_checkpoint_hash_hex,
                signing_key_hex,
                trim_bps,
            } => commands::markets::step_epoch(
                input,
                signed_snapshot_out,
                signed_checkpoint_out,
                prev_checkpoint_hash_hex,
                signing_key_hex,
                trim_bps,
            ),
            ModelsMarketCommands::SignSnapshot {
                input,
                output,
                signing_key_hex,
            } => commands::markets::sign_snapshot(input, output, signing_key_hex),
            ModelsMarketCommands::VerifySnapshot {
                input,
                verifying_key_hex,
            } => commands::markets::verify_snapshot(input, verifying_key_hex),
            ModelsMarketCommands::SignCheckpoint {
                snapshot,
                output,
                signing_key_hex,
                prev_checkpoint_hash_hex,
            } => commands::markets::sign_checkpoint(
                snapshot,
                output,
                signing_key_hex,
                prev_checkpoint_hash_hex,
            ),
            ModelsMarketCommands::VerifyCheckpoint {
                input,
                verifying_key_hex,
                expected_prev_checkpoint_hash_hex,
            } => commands::markets::verify_checkpoint(
                input,
                verifying_key_hex,
                expected_prev_checkpoint_hash_hex,
            ),
        },
        Commands::Asde { action } => match action {
            AsdeCommands::StepEpoch {
                epoch_id,
                state_in,
                state_out,
                stake_events,
                fee_events,
                df_table,
                params,
                difficulty_e_q32_32,
                epoch_summary_out,
                voucher_grants_out,
                prev_checkpoint_hash_hex,
                checkpoint_out,
                signing_key_hex,
                allow_empty_state,
            } => commands::staking::step_epoch(commands::staking::StepEpochArgs {
                epoch_id,
                state_in,
                state_out,
                stake_events_path: stake_events,
                fee_events_path: fee_events,
                df_table_path: df_table,
                params_path: params,
                difficulty_e_q32_32_dec: difficulty_e_q32_32,
                epoch_summary_out,
                voucher_grants_out,
                prev_checkpoint_hash_hex,
                checkpoint_out,
                signing_key_hex,
                allow_empty_state,
            }),
            AsdeCommands::VerifyCheckpoint {
                checkpoint,
                verifying_key_hex,
            } => commands::staking::verify_checkpoint(checkpoint, verifying_key_hex),
            AsdeCommands::ComputeServiceFeeDiscount {
                service_fee_sfa,
                voucher_grants,
                voucher_spends,
                user_pubkey_hex,
                epoch_id,
            } => commands::staking::compute_service_fee_discount(
                service_fee_sfa,
                voucher_grants,
                voucher_spends,
                user_pubkey_hex,
                epoch_id,
            ),
        },
        Commands::Tokenomics { action } => match action {
            TokenomicsCommands::PidProposeV6 {
                cur_burn_surplus_bps,
                cur_auction_surplus_bps,
                cur_drip_rate_bps,
                burn_setpoint_bps,
                burn_measured_bps,
                auction_setpoint_bps,
                auction_measured_bps,
                drip_setpoint_bps,
                drip_measured_bps,
                format,
            } => commands::tokenomics::pid_propose_v6(
                cur_burn_surplus_bps,
                cur_auction_surplus_bps,
                cur_drip_rate_bps,
                burn_setpoint_bps,
                burn_measured_bps,
                auction_setpoint_bps,
                auction_measured_bps,
                drip_setpoint_bps,
                drip_measured_bps,
                format,
            ),
        },
    }
}
