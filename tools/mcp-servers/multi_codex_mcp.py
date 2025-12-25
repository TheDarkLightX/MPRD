#!/usr/bin/env python3
"""
Multi-Codex MCP Server v2 (Enhanced with Tmux)
==============================================

An advanced MCP server for multi-agent orchestration with:
- Tmux-based persistent sessions
- Inter-agent messaging
- Real-time pane visibility
- Health monitoring
- Orchestration patterns (fan-out, pipeline, review)

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                multi-codex-mcp v2 (This Server)                 │
    │                                                                 │
    │  Agent Tools:                    Orchestration Tools:           │
    │  • create_agent(name, model)     • broadcast(message)           │
    │  • send_prompt(name, prompt)     • fan_out(prompts)             │
    │  • read_output(name) → output    • collect_outputs(names)       │
    │  • list_agents() → status        • send_message(from, to, msg)  │
    │  • terminate_agent(name)         • read_messages(name)          │
    │                                                                 │
    │  Tmux Backend:                                                  │
    │  ┌─────────────────────────────────────────────────────┐       │
    │  │ Session: multi-codex                                 │       │
    │  │ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │       │
    │  │ │ agent_a │ │ agent_b │ │ agent_c │ │ monitor │     │       │
    │  │ │ (pane 0)│ │ (pane 1)│ │ (pane 2)│ │ (pane 3)│     │       │
    │  │ └─────────┘ └─────────┘ └─────────┘ └─────────┘     │       │
    │  └─────────────────────────────────────────────────────┘       │
    └─────────────────────────────────────────────────────────────────┘
"""

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import deque
from pathlib import Path

# Configuration
SESSION_NAME = "multi-codex"
MESSAGE_DIR = Path("/tmp/multi-codex-messages")
CAPTURE_LINES = 200

# Try to import MCP SDK
try:
    from mcp.server import Server
    from mcp.types import Tool, TextContent
    HAS_MCP_SDK = True
except ImportError:
    HAS_MCP_SDK = False
    print("MCP SDK not installed. Running in standalone test mode.", file=sys.stderr)


# ============================================================
# Tmux Management
# ============================================================

class TmuxManager:
    """Manages tmux sessions and panes for agent coordination."""
    
    def __init__(self, session_name: str = SESSION_NAME):
        self.session = session_name
        self.panes: Dict[str, str] = {}  # name -> pane_id
        self._ensure_session()
    
    def _run_tmux(self, args: List[str], capture: bool = False) -> Optional[str]:
        """Run a tmux command."""
        cmd = ["tmux"] + args
        try:
            if capture:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return result.stdout.strip() if result.returncode == 0 else None
            else:
                subprocess.run(cmd, timeout=10, check=True)
                return None
        except subprocess.CalledProcessError as e:
            print(f"Tmux error: {e}", file=sys.stderr)
            return None
        except subprocess.TimeoutExpired:
            print("Tmux timeout", file=sys.stderr)
            return None
    
    def _ensure_session(self):
        """Ensure tmux session exists."""
        # Check if session exists
        result = self._run_tmux(["has-session", "-t", self.session], capture=True)
        if result is None:
            # Create session
            self._run_tmux(["new-session", "-d", "-s", self.session, "-n", "main"])
            print(f"Created tmux session: {self.session}", file=sys.stderr)
    
    def create_pane(self, name: str, cmd: str, cwd: str = ".") -> bool:
        """Create a new pane with a command."""
        if name in self.panes:
            return False
        
        # Create new window for this agent
        self._run_tmux(["new-window", "-t", self.session, "-n", name, "-c", cwd])
        
        # Get pane ID
        pane_id = self._run_tmux(
            ["list-panes", "-t", f"{self.session}:{name}", "-F", "#{pane_id}"],
            capture=True
        )
        
        if pane_id:
            self.panes[name] = pane_id
            # Send command to pane
            self._run_tmux(["send-keys", "-t", f"{self.session}:{name}", cmd, "Enter"])
            return True
        return False
    
    def send_keys(self, name: str, keys: str) -> bool:
        """Send keys to a pane."""
        if name not in self.panes:
            return False
        self._run_tmux(["send-keys", "-t", f"{self.session}:{name}", keys, "Enter"])
        return True
    
    def capture_pane(self, name: str, lines: int = CAPTURE_LINES) -> Optional[str]:
        """Capture pane contents."""
        if name not in self.panes:
            return None
        return self._run_tmux(
            ["capture-pane", "-t", f"{self.session}:{name}", "-p", "-S", f"-{lines}"],
            capture=True
        )
    
    def kill_pane(self, name: str) -> bool:
        """Kill a pane."""
        if name not in self.panes:
            return False
        self._run_tmux(["kill-window", "-t", f"{self.session}:{name}"])
        del self.panes[name]
        return True
    
    def list_panes(self) -> List[Dict]:
        """List all panes."""
        result = self._run_tmux(
            ["list-windows", "-t", self.session, "-F", "#{window_name}:#{window_active}"],
            capture=True
        )
        if not result:
            return []
        
        panes = []
        for line in result.split("\n"):
            if ":" in line:
                name, active = line.rsplit(":", 1)
                if name != "main":  # Skip the default window
                    panes.append({
                        "name": name,
                        "active": active == "1",
                        "in_registry": name in self.panes
                    })
        return panes


# ============================================================
# Inter-Agent Messaging
# ============================================================

class MessageBus:
    """Simple file-based message passing between agents."""
    
    def __init__(self, base_dir: Path = MESSAGE_DIR):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
    
    def _inbox_path(self, agent: str) -> Path:
        return self.base_dir / f"{agent}.inbox"
    
    def send(self, from_agent: str, to_agent: str, message: str) -> bool:
        """Send a message to an agent's inbox."""
        inbox = self._inbox_path(to_agent)
        msg_entry = {
            "from": from_agent,
            "to": to_agent,
            "message": message,
            "timestamp": time.time()
        }
        try:
            with open(inbox, "a") as f:
                f.write(json.dumps(msg_entry) + "\n")
            return True
        except Exception:
            return False
    
    def read(self, agent: str, clear: bool = True) -> List[Dict]:
        """Read messages from an agent's inbox."""
        inbox = self._inbox_path(agent)
        if not inbox.exists():
            return []
        
        messages = []
        try:
            with open(inbox, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        messages.append(json.loads(line))
            if clear:
                inbox.unlink()
        except Exception:
            pass
        return messages
    
    def broadcast(self, from_agent: str, agents: List[str], message: str) -> int:
        """Broadcast a message to multiple agents."""
        count = 0
        for agent in agents:
            if self.send(from_agent, agent, message):
                count += 1
        return count


# ============================================================
# Enhanced Agent Dataclass
# ============================================================

@dataclass
class Agent:
    """Represents a Codex agent in a tmux pane."""
    name: str
    model: str
    cwd: str
    status: str = "created"
    created_at: float = field(default_factory=time.time)
    last_prompt: float = field(default_factory=time.time)
    prompt_count: int = 0
    use_tmux: bool = True


# ============================================================
# Enhanced Multi-Codex Server
# ============================================================

class MultiCodexServerV2:
    """Enhanced MCP Server with tmux, messaging, and orchestration."""
    
    def __init__(self):
        self.agents: Dict[str, Agent] = {}
        self.tmux = TmuxManager()
        self.messages = MessageBus()
        self._lock = threading.Lock()
    
    # --- Core Agent Operations ---
    
    def create_agent(self, name: str, model: str = "o4-mini", cwd: str = ".") -> dict:
        """Create a new Codex agent in a tmux pane."""
        with self._lock:
            if name in self.agents:
                return {"success": False, "error": f"Agent '{name}' already exists"}
            
            # Create tmux pane with codex command
            cmd = f"codex --model {model}"
            success = self.tmux.create_pane(name, cmd, cwd)
            
            if success:
                agent = Agent(name=name, model=model, cwd=cwd, status="running")
                self.agents[name] = agent
                return {
                    "success": True,
                    "name": name,
                    "model": model,
                    "cwd": cwd,
                    "status": "running",
                    "tmux_session": SESSION_NAME
                }
            else:
                return {"success": False, "error": "Failed to create tmux pane"}
    
    def send_prompt(self, name: str, prompt: str) -> dict:
        """Send a prompt to an agent."""
        with self._lock:
            if name not in self.agents:
                return {"success": False, "error": f"Agent '{name}' not found"}
            
            agent = self.agents[name]
            success = self.tmux.send_keys(name, prompt)
            
            if success:
                agent.last_prompt = time.time()
                agent.prompt_count += 1
                return {
                    "success": True,
                    "name": name,
                    "prompt_length": len(prompt),
                    "prompt_count": agent.prompt_count
                }
            return {"success": False, "error": "Failed to send to tmux"}
    
    def read_output(self, name: str, lines: int = 100) -> dict:
        """Read recent output from an agent's tmux pane."""
        with self._lock:
            if name not in self.agents:
                return {"success": False, "error": f"Agent '{name}' not found"}
            
            output = self.tmux.capture_pane(name, lines)
            agent = self.agents[name]
            
            return {
                "success": True,
                "name": name,
                "status": agent.status,
                "output": output or "",
                "output_lines": len((output or "").split("\n")),
                "prompt_count": agent.prompt_count,
                "last_prompt": agent.last_prompt
            }
    
    def list_agents(self) -> dict:
        """List all agents with their status."""
        with self._lock:
            agents = []
            tmux_panes = {p["name"]: p for p in self.tmux.list_panes()}
            
            for name, agent in self.agents.items():
                pane_info = tmux_panes.get(name, {})
                agents.append({
                    "name": name,
                    "model": agent.model,
                    "cwd": agent.cwd,
                    "status": agent.status,
                    "created_at": agent.created_at,
                    "last_prompt": agent.last_prompt,
                    "prompt_count": agent.prompt_count,
                    "tmux_active": pane_info.get("active", False)
                })
            
            return {
                "success": True,
                "agents": agents,
                "count": len(agents),
                "tmux_session": SESSION_NAME
            }
    
    def terminate_agent(self, name: str) -> dict:
        """Terminate an agent and its tmux pane."""
        with self._lock:
            if name not in self.agents:
                return {"success": False, "error": f"Agent '{name}' not found"}
            
            self.tmux.kill_pane(name)
            del self.agents[name]
            
            return {"success": True, "name": name, "terminated": True}
    
    # --- Messaging Operations ---
    
    def send_message(self, from_agent: str, to_agent: str, message: str) -> dict:
        """Send a message between agents."""
        success = self.messages.send(from_agent, to_agent, message)
        return {
            "success": success,
            "from": from_agent,
            "to": to_agent,
            "message_length": len(message)
        }
    
    def read_messages(self, name: str, clear: bool = True) -> dict:
        """Read messages from an agent's inbox."""
        messages = self.messages.read(name, clear)
        return {
            "success": True,
            "name": name,
            "message_count": len(messages),
            "messages": messages
        }
    
    def broadcast(self, from_agent: str, message: str) -> dict:
        """Broadcast a message to all agents."""
        with self._lock:
            agent_names = [n for n in self.agents.keys() if n != from_agent]
        
        count = self.messages.broadcast(from_agent, agent_names, message)
        return {
            "success": True,
            "from": from_agent,
            "recipients": agent_names,
            "sent_count": count
        }
    
    # --- Orchestration Patterns ---
    
    def fan_out(self, prompts: Dict[str, str]) -> dict:
        """Send different prompts to multiple agents simultaneously."""
        results = {}
        for name, prompt in prompts.items():
            results[name] = self.send_prompt(name, prompt)
        
        success_count = sum(1 for r in results.values() if r.get("success"))
        return {
            "success": success_count > 0,
            "total": len(prompts),
            "succeeded": success_count,
            "results": results
        }
    
    def collect_outputs(self, names: Optional[List[str]] = None, lines: int = 50) -> dict:
        """Collect outputs from multiple agents."""
        with self._lock:
            if names is None:
                names = list(self.agents.keys())
        
        outputs = {}
        for name in names:
            result = self.read_output(name, lines)
            if result.get("success"):
                outputs[name] = result["output"]
        
        return {
            "success": True,
            "collected": len(outputs),
            "agents": list(outputs.keys()),
            "outputs": outputs
        }
    
    def health_check(self) -> dict:
        """Check health of all agents."""
        with self._lock:
            health = []
            now = time.time()
            
            for name, agent in self.agents.items():
                output = self.tmux.capture_pane(name, 10)
                idle_time = now - agent.last_prompt
                
                health.append({
                    "name": name,
                    "status": agent.status,
                    "idle_seconds": round(idle_time, 1),
                    "prompt_count": agent.prompt_count,
                    "has_output": bool(output and output.strip()),
                    "healthy": agent.status == "running" and idle_time < 3600
                })
            
            healthy_count = sum(1 for h in health if h["healthy"])
            return {
                "success": True,
                "total": len(health),
                "healthy": healthy_count,
                "unhealthy": len(health) - healthy_count,
                "agents": health
            }
    
    def terminate_all(self) -> dict:
        """Terminate all agents."""
        with self._lock:
            names = list(self.agents.keys())
        
        for name in names:
            self.terminate_agent(name)
        
        return {"success": True, "terminated": names, "count": len(names)}


# ============================================================
# MCP Server Implementation
# ============================================================

if HAS_MCP_SDK:
    server = Server("multi-codex")
    mcs = MultiCodexServerV2()

    @server.list_tools()
    async def list_tools():
        return [
            # Core Agent Tools
            Tool(
                name="create_agent",
                description="Create a new Codex agent in a tmux pane",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Unique agent name"},
                        "model": {"type": "string", "default": "o4-mini", "description": "Model (o3, o4-mini)"},
                        "cwd": {"type": "string", "default": ".", "description": "Working directory"}
                    },
                    "required": ["name"]
                }
            ),
            Tool(
                name="send_prompt",
                description="Send a prompt to an agent",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Agent name"},
                        "prompt": {"type": "string", "description": "Prompt to send"}
                    },
                    "required": ["name", "prompt"]
                }
            ),
            Tool(
                name="read_output",
                description="Read recent output from an agent's tmux pane",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Agent name"},
                        "lines": {"type": "integer", "default": 100, "description": "Lines to capture"}
                    },
                    "required": ["name"]
                }
            ),
            Tool(
                name="list_agents",
                description="List all agents and their status",
                inputSchema={"type": "object", "properties": {}}
            ),
            Tool(
                name="terminate_agent",
                description="Terminate an agent",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Agent to terminate"}
                    },
                    "required": ["name"]
                }
            ),
            # Messaging Tools
            Tool(
                name="send_message",
                description="Send a message between agents",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "from_agent": {"type": "string", "description": "Sender agent name"},
                        "to_agent": {"type": "string", "description": "Recipient agent name"},
                        "message": {"type": "string", "description": "Message content"}
                    },
                    "required": ["from_agent", "to_agent", "message"]
                }
            ),
            Tool(
                name="read_messages",
                description="Read messages from an agent's inbox",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Agent name"},
                        "clear": {"type": "boolean", "default": True, "description": "Clear after reading"}
                    },
                    "required": ["name"]
                }
            ),
            Tool(
                name="broadcast",
                description="Broadcast a message to all agents",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "from_agent": {"type": "string", "description": "Sender name"},
                        "message": {"type": "string", "description": "Message to broadcast"}
                    },
                    "required": ["from_agent", "message"]
                }
            ),
            # Orchestration Tools
            Tool(
                name="fan_out",
                description="Send different prompts to multiple agents simultaneously",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "prompts": {"type": "object", "description": "Dict of {agent_name: prompt}"}
                    },
                    "required": ["prompts"]
                }
            ),
            Tool(
                name="collect_outputs",
                description="Collect outputs from multiple agents",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "names": {"type": "array", "items": {"type": "string"}, "description": "Agent names (all if empty)"},
                        "lines": {"type": "integer", "default": 50, "description": "Lines per agent"}
                    }
                }
            ),
            Tool(
                name="health_check",
                description="Check health of all agents",
                inputSchema={"type": "object", "properties": {}}
            ),
            Tool(
                name="terminate_all",
                description="Terminate all agents",
                inputSchema={"type": "object", "properties": {}}
            )
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        handlers = {
            "create_agent": lambda: mcs.create_agent(
                arguments["name"],
                arguments.get("model", "o4-mini"),
                arguments.get("cwd", ".")
            ),
            "send_prompt": lambda: mcs.send_prompt(arguments["name"], arguments["prompt"]),
            "read_output": lambda: mcs.read_output(arguments["name"], arguments.get("lines", 100)),
            "list_agents": lambda: mcs.list_agents(),
            "terminate_agent": lambda: mcs.terminate_agent(arguments["name"]),
            "send_message": lambda: mcs.send_message(
                arguments["from_agent"], arguments["to_agent"], arguments["message"]
            ),
            "read_messages": lambda: mcs.read_messages(
                arguments["name"], arguments.get("clear", True)
            ),
            "broadcast": lambda: mcs.broadcast(arguments["from_agent"], arguments["message"]),
            "fan_out": lambda: mcs.fan_out(arguments["prompts"]),
            "collect_outputs": lambda: mcs.collect_outputs(
                arguments.get("names"), arguments.get("lines", 50)
            ),
            "health_check": lambda: mcs.health_check(),
            "terminate_all": lambda: mcs.terminate_all(),
        }
        
        handler = handlers.get(name)
        result = handler() if handler else {"error": f"Unknown tool: {name}"}
        return [TextContent(type="text", text=json.dumps(result, indent=2))]


# ============================================================
# Standalone Test Mode
# ============================================================

def test_standalone():
    """Test the server in standalone mode."""
    print("=== Multi-Codex Server v2 Test ===\n")
    
    srv = MultiCodexServerV2()
    
    print("1. Creating agent 'test_agent'...")
    result = srv.create_agent("test_agent", "o4-mini", "/tmp")
    print(json.dumps(result, indent=2))
    
    if result.get("success"):
        print("\n2. Listing agents...")
        print(json.dumps(srv.list_agents(), indent=2))
        
        print("\n3. Sending prompt...")
        result = srv.send_prompt("test_agent", "Hello! Please respond with OK.")
        print(json.dumps(result, indent=2))
        
        print("\n4. Waiting 3 seconds...")
        time.sleep(3)
        
        print("\n5. Reading output...")
        result = srv.read_output("test_agent", 30)
        print(json.dumps(result, indent=2))
        
        print("\n6. Health check...")
        print(json.dumps(srv.health_check(), indent=2))
        
        print("\n7. Terminating agent...")
        result = srv.terminate_agent("test_agent")
        print(json.dumps(result, indent=2))
    
    print("\n=== Test Complete ===")
    print(f"\nTo view tmux session: tmux attach -t {SESSION_NAME}")


def main():
    if HAS_MCP_SDK:
        from mcp.server.stdio import stdio_server
        print("Starting Multi-Codex MCP Server v2...", file=sys.stderr)
        
        async def run():
            async with stdio_server() as (read_stream, write_stream):
                await server.run(
                    read_stream,
                    write_stream,
                    server.create_initialization_options()
                )
        
        asyncio.run(run())
    else:
        test_standalone()


if __name__ == "__main__":
    main()
