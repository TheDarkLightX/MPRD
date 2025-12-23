//! Tau-MPRD Compiler CLI
//!
//! Compiles Tau-MPRD policy source to TCV circuit format.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use mprd_risc0_shared::{
    domains, id, limits_hash, policy_exec_kind_tau_compiled_id_v1, policy_exec_version_id_v1,
    policy_source_kind_tau_id_v1, tcv_key_hash_v1,
};
use tau_mprd_compiler::{compile, compile_v2, CompilationOutput, CompilationOutputV2};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    match run(&args) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let config = parse_args(args)?;
    
    // Read source
    let source = match &config.input {
        Input::File(path) => {
            fs::read_to_string(path)
                .map_err(|e| format!("failed to read input file: {}", e))?
        }
        Input::Stdin => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)
                .map_err(|e| format!("failed to read stdin: {}", e))?;
            buf
        }
    };
    
    if config.v2 {
        let output = compile_v2(&source).map_err(|e| format!("v2 compilation failed: {}", e))?;

        match config.output_format {
            OutputFormat::Binary => write_binary_v2(&config.output, &output)?,
            OutputFormat::Json => write_json_v2(&config.output, &output)?,
            OutputFormat::Hashes => print_hashes_v2(&output),
            OutputFormat::BundleJson => write_bundle_json_v2(&config.output, &source, &output)?,
            OutputFormat::SchemaJson => write_schema_json_v2(&config.output, &output)?,
            OutputFormat::RegistryEntryJson => write_registry_entry_json_v2(&config.output, &output)?,
        }

        if config.verbose {
            eprintln!("Compilation successful (v2):");
            eprintln!("  policy_source_hash: {}", hex(&output.policy_source_hash));
            eprintln!("  policy_hash:        {}", hex(&output.policy_hash));
            eprintln!("  artifact_size:      {} bytes", output.artifact_bytes.len());
            eprintln!("  nodes:              {}", output.artifact.nodes.len());
            eprintln!("  temporal_fields:    {}", output.artifact.temporal_fields.len());
        }
    } else {
        // Compile v1
        let output = compile(&source).map_err(|e| format!("compilation failed: {}", e))?;

        match config.output_format {
            OutputFormat::Binary => write_binary(&config.output, &output)?,
            OutputFormat::Json => write_json(&config.output, &output)?,
            OutputFormat::Hashes => print_hashes(&output),
            OutputFormat::BundleJson => write_bundle_json(&config.output, &output)?,
            OutputFormat::SchemaJson => write_schema_json(&config.output, &output)?,
            OutputFormat::RegistryEntryJson => {
                write_registry_entry_json(&config.output, &output)?
            }
        }

        if config.verbose {
            eprintln!("Compilation successful (v1):");
            eprintln!("  policy_source_hash: {}", hex(&output.policy_source_hash));
            eprintln!("  policy_hash:        {}", hex(&output.policy_hash));
            eprintln!("  artifact_size:      {} bytes", output.artifact_bytes.len());
            eprintln!("  predicates:         {}", output.artifact.predicates.len());
            eprintln!("  gates:              {}", output.artifact.gates.len());
            eprintln!("  temporal_fields:    {}", output.artifact.temporal_fields.len());
        }
    }
    
    Ok(())
}

enum Input {
    File(PathBuf),
    Stdin,
}

enum Output {
    File(PathBuf),
    Stdout,
}

enum OutputFormat {
    Binary,
    Json,
    Hashes,
    BundleJson,
    SchemaJson,
    RegistryEntryJson,
}

struct Config {
    input: Input,
    output: Output,
    output_format: OutputFormat,
    verbose: bool,
    v2: bool,
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut input: Option<Input> = None;
    let mut output = Output::Stdout;
    let mut output_format = OutputFormat::Binary;
    let mut verbose = false;
    let mut v2 = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-i" | "--input" => {
                i += 1;
                if i >= args.len() {
                    return Err("--input requires a file path".to_string());
                }
                input = Some(Input::File(PathBuf::from(&args[i])));
            }
            "-o" | "--output" => {
                i += 1;
                if i >= args.len() {
                    return Err("--output requires a file path".to_string());
                }
                output = Output::File(PathBuf::from(&args[i]));
            }
            "--json" => {
                output_format = OutputFormat::Json;
            }
            "--bundle" => {
                output_format = OutputFormat::BundleJson;
            }
            "--schema" => {
                output_format = OutputFormat::SchemaJson;
            }
            "--registry-entry" => {
                output_format = OutputFormat::RegistryEntryJson;
            }
            "--hashes" => {
                output_format = OutputFormat::Hashes;
            }
            "--v2" => {
                v2 = true;
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            arg if !arg.starts_with('-') => {
                // Positional argument = input file
                input = Some(Input::File(PathBuf::from(arg)));
            }
            _ => {
                return Err(format!("unknown argument: {}", args[i]));
            }
        }
        i += 1;
    }
    
    let input = input.unwrap_or(Input::Stdin);
    
    Ok(Config {
        input,
        output,
        output_format,
        verbose,
        v2,
    })
}

fn print_help() {
    println!(r#"tau-mprd-compile - Compile Tau-MPRD policy to TCV circuit format

USAGE:
    tau-mprd-compile [OPTIONS] [INPUT]

ARGS:
    [INPUT]    Input file (reads from stdin if not specified)

OPTIONS:
    -i, --input <FILE>     Input file path
    -o, --output <FILE>    Output file path (writes to stdout if not specified)
    --json                 Output as JSON (default: binary)
    --bundle               Output a policy bundle JSON for MPRD wiring
    --schema               Output required key schema JSON (state/candidate keys + key hashes)
    --registry-entry       Output an AuthorizedPolicyV1 JSON snippet (for registry_state)
    --hashes               Output only policy_source_hash and policy_hash
    --v2                   Compile using Tau-MPRD v2 (arithmetic DAG artifact)
    -v, --verbose          Print compilation statistics
    -h, --help             Print help

EXAMPLES:
    # Compile policy and output binary artifact
    tau-mprd-compile policy.tau -o policy.tcv

    # Compile and get hashes only
    tau-mprd-compile policy.tau --hashes

    # Compile from stdin
    echo "always (state.x >= 0)" | tau-mprd-compile --json

OUTPUT:
    Binary format: canonical artifact bytes (policy_hash = H(DOMAIN || bytes))
    JSON format: {{ policy_source_hash, policy_hash, artifact_bytes (hex) }}
    Bundle format: policy bundle JSON containing hashes, IDs, schema, and artifact bytes (hex)
    Schema format: required keys and key hashes, suitable for generating state/candidate templates
    Registry entry: AuthorizedPolicyV1 snippet (arrays) for insertion into registry_state JSON
"#);
}

fn policy_exec_version_id_v2() -> [u8; 32] {
    id(domains::ID, b"v2")
}

fn write_binary(output: &Output, compilation: &CompilationOutput) -> Result<(), String> {
    match output {
        Output::File(path) => {
            fs::write(path, &compilation.artifact_bytes)
                .map_err(|e| format!("failed to write output file: {}", e))?;
        }
        Output::Stdout => {
            io::stdout().write_all(&compilation.artifact_bytes)
                .map_err(|e| format!("failed to write stdout: {}", e))?;
        }
    }
    Ok(())
}

fn write_json(output: &Output, compilation: &CompilationOutput) -> Result<(), String> {
    let json = serde_json::json!({
        "policy_source_hash": hex(&compilation.policy_source_hash),
        "policy_hash": hex(&compilation.policy_hash),
        "artifact_bytes": hex(&compilation.artifact_bytes),
        "artifact": {
            "version": compilation.artifact.version,
            "predicate_count": compilation.artifact.predicates.len(),
            "gate_count": compilation.artifact.gates.len(),
            "output_wire": compilation.artifact.output_wire,
            "temporal_field_count": compilation.artifact.temporal_fields.len(),
        }
    });
    
    let json_str = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("failed to serialize JSON: {}", e))?;
    
    match output {
        Output::File(path) => {
            fs::write(path, json_str)
                .map_err(|e| format!("failed to write output file: {}", e))?;
        }
        Output::Stdout => {
            println!("{}", json_str);
        }
    }
    Ok(())
}

fn write_binary_v2(output: &Output, compilation: &CompilationOutputV2) -> Result<(), String> {
    match output {
        Output::File(path) => fs::write(path, &compilation.artifact_bytes)
            .map_err(|e| format!("failed to write output file: {}", e))?,
        Output::Stdout => io::stdout()
            .write_all(&compilation.artifact_bytes)
            .map_err(|e| format!("failed to write stdout: {}", e))?,
    }
    Ok(())
}

fn write_json_v2(output: &Output, compilation: &CompilationOutputV2) -> Result<(), String> {
    let state_key_hashes: serde_json::Map<String, serde_json::Value> = compilation
        .state_keys
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(hex(v))))
        .collect();
    let candidate_key_hashes: serde_json::Map<String, serde_json::Value> = compilation
        .candidate_keys
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(hex(v))))
        .collect();

    let json = serde_json::json!({
        "version": 2,
        "policy_source_hash": hex(&compilation.policy_source_hash),
        "policy_hash": hex(&compilation.policy_hash),
        "artifact_bytes": hex(&compilation.artifact_bytes),
        "artifact_size_bytes": compilation.artifact_bytes.len(),
        "node_count": compilation.artifact.nodes.len(),
        "temporal_field_count": compilation.artifact.temporal_fields.len(),
        "state_key_hashes": state_key_hashes,
        "candidate_key_hashes": candidate_key_hashes,
    });

    let json_str = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("failed to serialize JSON: {}", e))?;

    match output {
        Output::File(path) => fs::write(path, json_str)
            .map_err(|e| format!("failed to write output file: {}", e))?,
        Output::Stdout => println!("{}", json_str),
    }
    Ok(())
}

fn write_schema_json(output: &Output, compilation: &CompilationOutput) -> Result<(), String> {
    let mut state_key_hashes = serde_json::Map::new();
    for k in &compilation.required_state_keys {
        state_key_hashes.insert(k.clone(), serde_json::Value::String(hex(&tcv_key_hash_v1(k.as_bytes()))));
    }

    let mut candidate_key_hashes = serde_json::Map::new();
    for k in &compilation.required_candidate_keys {
        candidate_key_hashes.insert(k.clone(), serde_json::Value::String(hex(&tcv_key_hash_v1(k.as_bytes()))));
    }

    let json = serde_json::json!({
        "version": 1,
        "state_fields": compilation.state_fields,
        "candidate_fields": compilation.candidate_fields,
        "required_state_keys": compilation.required_state_keys,
        "required_candidate_keys": compilation.required_candidate_keys,
        "state_key_hashes": state_key_hashes,
        "candidate_key_hashes": candidate_key_hashes,
    });

    let json_str = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("failed to serialize JSON: {}", e))?;

    match output {
        Output::File(path) => fs::write(path, json_str)
            .map_err(|e| format!("failed to write output file: {}", e))?,
        Output::Stdout => println!("{}", json_str),
    }
    Ok(())
}

fn write_registry_entry_json(output: &Output, compilation: &CompilationOutput) -> Result<(), String> {
    let exec_kind = policy_exec_kind_tau_compiled_id_v1();
    let exec_version = policy_exec_version_id_v1();
    let source_kind = policy_source_kind_tau_id_v1();

    let json = serde_json::json!({
        "policy_hash": compilation.policy_hash,
        "policy_exec_kind_id": exec_kind,
        "policy_exec_version_id": exec_version,
        "policy_source_kind_id": source_kind,
        "policy_source_hash": compilation.policy_source_hash,
        "policy_hash_hex": hex(&compilation.policy_hash),
        "policy_exec_kind_id_hex": hex(&exec_kind),
        "policy_exec_version_id_hex": hex(&exec_version),
        "policy_source_kind_id_hex": hex(&source_kind),
        "policy_source_hash_hex": hex(&compilation.policy_source_hash),
    });

    let json_str = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("failed to serialize JSON: {}", e))?;

    match output {
        Output::File(path) => fs::write(path, json_str)
            .map_err(|e| format!("failed to write output file: {}", e))?,
        Output::Stdout => println!("{}", json_str),
    }
    Ok(())
}

fn write_schema_json_v2(output: &Output, compilation: &CompilationOutputV2) -> Result<(), String> {
    let mut required_state_keys: Vec<String> = compilation.state_keys.keys().cloned().collect();
    required_state_keys.sort();
    required_state_keys.dedup();

    let mut required_candidate_keys: Vec<String> = compilation.candidate_keys.keys().cloned().collect();
    required_candidate_keys.sort();
    required_candidate_keys.dedup();

    let state_key_hashes: serde_json::Map<String, serde_json::Value> = compilation
        .state_keys
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(hex(v))))
        .collect();
    let candidate_key_hashes: serde_json::Map<String, serde_json::Value> = compilation
        .candidate_keys
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(hex(v))))
        .collect();

    let temporal_fields: Vec<serde_json::Value> = compilation
        .artifact
        .temporal_fields
        .iter()
        .map(|tf| {
            let derived_keys: Vec<String> = (1..=tf.max_lookback)
                .map(|i| format!("{}_t_{}", tf.field_name, i))
                .collect();
            serde_json::json!({
                "field_name": tf.field_name,
                "max_lookback": tf.max_lookback,
                "derived_keys": derived_keys,
            })
        })
        .collect();

    let json = serde_json::json!({
        "version": 2,
        "required_state_keys": required_state_keys,
        "required_candidate_keys": required_candidate_keys,
        "state_key_hashes": state_key_hashes,
        "candidate_key_hashes": candidate_key_hashes,
        "temporal_fields": temporal_fields,
    });

    let json_str = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("failed to serialize JSON: {}", e))?;

    match output {
        Output::File(path) => fs::write(path, json_str)
            .map_err(|e| format!("failed to write output file: {}", e))?,
        Output::Stdout => println!("{}", json_str),
    }
    Ok(())
}

fn write_registry_entry_json_v2(
    output: &Output,
    compilation: &CompilationOutputV2,
) -> Result<(), String> {
    let exec_kind = policy_exec_kind_tau_compiled_id_v1();
    let exec_version = policy_exec_version_id_v2();
    let source_kind = policy_source_kind_tau_id_v1();

    let json = serde_json::json!({
        "policy_hash": compilation.policy_hash,
        "policy_exec_kind_id": exec_kind,
        "policy_exec_version_id": exec_version,
        "policy_source_kind_id": source_kind,
        "policy_source_hash": compilation.policy_source_hash,
        "policy_hash_hex": hex(&compilation.policy_hash),
        "policy_exec_kind_id_hex": hex(&exec_kind),
        "policy_exec_version_id_hex": hex(&exec_version),
        "policy_source_kind_id_hex": hex(&source_kind),
        "policy_source_hash_hex": hex(&compilation.policy_source_hash),
    });

    let json_str = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("failed to serialize JSON: {}", e))?;

    match output {
        Output::File(path) => fs::write(path, json_str)
            .map_err(|e| format!("failed to write output file: {}", e))?,
        Output::Stdout => println!("{}", json_str),
    }
    Ok(())
}

fn write_bundle_json(output: &Output, compilation: &CompilationOutput) -> Result<(), String> {
    let exec_kind = policy_exec_kind_tau_compiled_id_v1();
    let exec_version = policy_exec_version_id_v1();
    let source_kind = policy_source_kind_tau_id_v1();
    let empty_limits: [u8; 0] = [];
    let empty_limits_hash = limits_hash(&empty_limits);

    let mut state_key_hashes = serde_json::Map::new();
    for k in &compilation.required_state_keys {
        state_key_hashes.insert(k.clone(), serde_json::Value::String(hex(&tcv_key_hash_v1(k.as_bytes()))));
    }

    let mut candidate_key_hashes = serde_json::Map::new();
    for k in &compilation.required_candidate_keys {
        candidate_key_hashes.insert(k.clone(), serde_json::Value::String(hex(&tcv_key_hash_v1(k.as_bytes()))));
    }

    let json = serde_json::json!({
        "bundle_version": 1,
        "policy_source_kind_id": source_kind,
        "policy_source_hash": compilation.policy_source_hash,
        "policy_exec_kind_id": exec_kind,
        "policy_exec_version_id": exec_version,
        "policy_hash": compilation.policy_hash,
        "compiled_policy_bytes": hex(&compilation.artifact_bytes),
        "policy_source_kind_id_hex": hex(&source_kind),
        "policy_source_hash_hex": hex(&compilation.policy_source_hash),
        "policy_exec_kind_id_hex": hex(&exec_kind),
        "policy_exec_version_id_hex": hex(&exec_version),
        "policy_hash_hex": hex(&compilation.policy_hash),
        "limits_bytes_hex": "",
        "limits_hash": empty_limits_hash,
        "limits_hash_hex": hex(&empty_limits_hash),
        "schema": {
            "state_fields": compilation.state_fields,
            "candidate_fields": compilation.candidate_fields,
            "required_state_keys": compilation.required_state_keys,
            "required_candidate_keys": compilation.required_candidate_keys,
            "state_key_hashes": state_key_hashes,
            "candidate_key_hashes": candidate_key_hashes,
        },
        "artifact": {
            "version": compilation.artifact.version,
            "predicate_count": compilation.artifact.predicates.len(),
            "gate_count": compilation.artifact.gates.len(),
            "output_wire": compilation.artifact.output_wire,
            "temporal_field_count": compilation.artifact.temporal_fields.len(),
        },
        "registry_entry_v1": {
            "policy_hash": compilation.policy_hash,
            "policy_exec_kind_id": exec_kind,
            "policy_exec_version_id": exec_version,
            "policy_source_kind_id": source_kind,
            "policy_source_hash": compilation.policy_source_hash,
        },
    });

    let json_str = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("failed to serialize JSON: {}", e))?;

    match output {
        Output::File(path) => fs::write(path, json_str)
            .map_err(|e| format!("failed to write output file: {}", e))?,
        Output::Stdout => println!("{}", json_str),
    }
    Ok(())
}

fn write_bundle_json_v2(
    output: &Output,
    source: &str,
    compilation: &CompilationOutputV2,
) -> Result<(), String> {
    let bundle = tau_mprd_compiler::bundle_v2::build_bundle_v2(
        source,
        compilation.policy_source_hash,
        compilation.policy_hash,
        &compilation.artifact,
        compilation.artifact_bytes.clone(),
    )
    .map_err(|e| format!("failed to build bundle: {e}"))?;

    let json_str = tau_mprd_compiler::bundle_v2::bundle_to_json(&bundle)
        .map_err(|e| format!("failed to serialize bundle: {e}"))?;

    match output {
        Output::File(path) => fs::write(path, json_str)
            .map_err(|e| format!("failed to write output file: {}", e))?,
        Output::Stdout => println!("{}", json_str),
    }
    Ok(())
}

fn print_hashes(compilation: &CompilationOutput) {
    println!("policy_source_hash: {}", hex(&compilation.policy_source_hash));
    println!("policy_hash:        {}", hex(&compilation.policy_hash));
}

fn print_hashes_v2(compilation: &CompilationOutputV2) {
    println!("policy_source_hash: {}", hex(&compilation.policy_source_hash));
    println!("policy_hash:        {}", hex(&compilation.policy_hash));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
