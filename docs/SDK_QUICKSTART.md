# MPRD SDK Quickstart

Get started with MPRD in 5 minutes.

## Installation

```bash
# Install the CLI
cargo install --path crates/mprd-cli

# Or build from source
cargo build --release -p mprd-cli
```

## Quick Setup

```bash
# Initialize a new MPRD project
mprd init --mode trustless

# Check system health
mprd doctor
```

## Your First Policy

Create `my_policy.tau`:
```tau
# Only allow actions with score >= 50
candidates_exist && max_score >= 50
```

## Test Your Policy

Create `test_cases.json`:
```json
{
  "cases": [
    {
      "name": "accepts_high_score",
      "state": { "balance": 1000 },
      "candidates": [
        { "action_type": "transfer", "params": {"amount": 100}, "score": 75 }
      ],
      "expected_action": "transfer"
    },
    {
      "name": "rejects_low_score", 
      "state": { "balance": 1000 },
      "candidates": [
        { "action_type": "transfer", "params": {"amount": 100}, "score": 25 }
      ],
      "expected_action": null
    }
  ]
}
```

Run tests:
```bash
mprd policy test --policy my_policy.tau --tests test_cases.json
```

## Verify Syntax

```bash
mprd policy verify --file my_policy.tau
```

## Run a Decision

```bash
# Create state.json
echo '{"balance": 1000}' > state.json

# Create candidates.json  
echo '[{"action_type": "transfer", "params": {"amount": 100}, "score": 75}]' > candidates.json

# Run (dry run)
mprd run --policy <POLICY_HASH> --state state.json --candidates candidates.json

# Run with execution
mprd run --policy <POLICY_HASH> --state state.json --candidates candidates.json --execute
```

## Generate a Proof

```bash
mprd prove \
  --decision decision.json \
  --state state.json \
  --candidates candidates.json \
  --output proof.bin
```

## Verify a Proof

```bash
mprd verify --proof proof.bin --token proof.token.json
```

## Next Steps

- Read the [Architecture Guide](docs/ARCHITECTURE.md)
- Explore [Example Policies](examples/policies/)
- Review [Production Readiness](docs/PRODUCTION_READINESS.md)

## API Integration

For programmatic access, use the REST API:

```bash
# Start the server
mprd serve --bind 127.0.0.1:8080

# Make a decision
curl -X POST http://localhost:8080/api/v1/decide \
  -H "Content-Type: application/json" \
  -d '{"policy_hash": "...", "state": {...}, "candidates": [...]}'
```

## Support

- GitHub Issues: https://github.com/TheDarkLightX/MPRD/issues
- Documentation: https://mprd.dev/docs
