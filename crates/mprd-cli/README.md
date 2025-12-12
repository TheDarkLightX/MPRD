# mprd-cli

Command-line interface for MPRD operations.

## Overview

This crate provides CLI tools for:

- **Policy management**: Upload, verify, and manage Tau policies
- **Proof verification**: Verify proof bundles from command line
- **System diagnostics**: Health checks and status reporting

## Usage

```bash
# Verify a proof bundle
mprd-cli verify --proof bundle.json

# Check policy
mprd-cli policy check --file policy.tau

# System status
mprd-cli status
```

## Building

```bash
cargo build -p mprd-cli --release
```
