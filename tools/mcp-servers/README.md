# Multi-Codex MCP Server

An MCP server that manages multiple Codex CLI instances, enabling parallel agent coordination.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│         multi-codex-mcp (This Server)               │
│                                                     │
│  Tools exposed:                                     │
│  • create_agent(name, model, cwd)                   │
│  • send_prompt(name, prompt)                        │
│  • read_output(name) → latest output                │
│  • list_agents() → [name, status, model]            │
│  • terminate_agent(name)                            │
└─────────────────────────────────────────────────────┘
```

## Setup

### Option 1: Standalone Mode (No MCP SDK)

```bash
# Works without installing anything
python3 multi_codex_mcp.py
```

### Option 2: Full MCP Server Mode

```bash
# Create venv
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
python3 multi_codex_mcp.py
```

## Configuration

Add to your MCP config (e.g., `~/.config/mcp/config.json`):

```json
{
  "servers": {
    "multi-codex": {
      "command": ["python3", "/path/to/multi_codex_mcp.py"],
      "args": []
    }
  }
}
```

## Usage Examples

### Create and Coordinate Agents

```python
# Create two agents
create_agent(name="prover", model="o3", cwd="/project")
create_agent(name="reviewer", model="o4-mini", cwd="/project")

# Send tasks
send_prompt("prover", "Write Lean proofs for the OPI formula")
send_prompt("reviewer", "Review the proofs written by the prover agent")

# Check progress
read_output("prover", lines=50)
read_output("reviewer", lines=50)

# Cleanup
terminate_agent("prover")
terminate_agent("reviewer")
```

## Roadmap

- [ ] Add tmux support for persistent sessions
- [ ] Add inter-agent messaging
- [ ] Add orchestration patterns
- [ ] Add agent health monitoring
