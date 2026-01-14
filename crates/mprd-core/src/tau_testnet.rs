//! Tau Testnet integration harness (development + integration testing).
//!
//! This module is intentionally scoped to:
//! - spawning a local `external/tau-testnet/server.py` node (typically in `TAU_FORCE_TEST=1` mode)
//! - issuing simple TCP "RPC" commands (string commands terminated by newline)
//!
//! It does **not** attempt to be a production Tau Net adapter. Production integration should
//! flow through `tau_net_output_attestation` and a verifier-checkable state provenance adapter.

use crate::{MprdError, Result};
use rand::{distributions::Alphanumeric, Rng};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct TauTestnetNodeOptions {
    /// Python executable (e.g. "python3" or "/path/to/venv/bin/python").
    pub python: String,
    /// Path to the Tau Testnet repo directory (contains `server.py`).
    pub tau_testnet_dir: PathBuf,
    /// Host for the TCP server bind.
    pub host: String,
    /// Port for the TCP server bind.
    pub port: u16,
    /// If true, uses `TAU_FORCE_TEST=1` so the node does not require Docker/Tau.
    pub force_test_mode: bool,
    /// Tau environment name (e.g. "development" | "test" | "production").
    pub tau_env: String,
    /// Optional database path override (keeps multiple nodes from colliding).
    pub db_path: Option<PathBuf>,
    /// Time limit for waiting until the node is accepting TCP connections.
    pub ready_timeout: Duration,
}

impl TauTestnetNodeOptions {
    pub fn dev_default(tau_testnet_dir: impl Into<PathBuf>, port: u16) -> Self {
        Self {
            python: std::env::var("TAU_TESTNET_PYTHON").unwrap_or_else(|_| "python3".to_string()),
            tau_testnet_dir: tau_testnet_dir.into(),
            host: "127.0.0.1".to_string(),
            port,
            force_test_mode: true,
            tau_env: "test".to_string(),
            db_path: None,
            ready_timeout: Duration::from_secs(10),
        }
    }
}

pub struct TauTestnetNode {
    child: Child,
    addr: SocketAddr,
}

impl TauTestnetNode {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn host(&self) -> &str {
        // SocketAddr::to_string allocates; keep this simple for now.
        "127.0.0.1"
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Spawn a Tau Testnet node process and wait until it accepts TCP connections.
    ///
    /// # Safety/Determinism
    /// - In `force_test_mode`, Tau logic execution is bypassed and validation uses a deterministic path.
    /// - For MPRD-grade determinism, callers should also isolate filesystem/db paths per run and
    ///   avoid external peers (no bootstrap peers).
    pub fn spawn(mut opts: TauTestnetNodeOptions) -> Result<Self> {
        let server_py = opts.tau_testnet_dir.join("server.py");
        if !server_py.exists() {
            return Err(MprdError::ConfigError(format!(
                "tau-testnet server.py not found at {}",
                server_py.display()
            )));
        }

        // Default DB path: temp file unique per run to avoid cross-test contamination.
        let db_path = opts.db_path.take().unwrap_or_else(|| {
            let suffix: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();
            std::env::temp_dir().join(format!("tau-testnet-node-{suffix}.db"))
        });

        let mut cmd = Command::new(&opts.python);
        cmd.current_dir(&opts.tau_testnet_dir)
            .arg("server.py")
            .arg("--ephemeral-identity")
            // quiet-ish by default, but keep stderr/stdout for debugging when failures occur.
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("TAU_HOST", &opts.host)
            .env("TAU_PORT", opts.port.to_string())
            .env("TAU_DB_PATH", db_path.to_string_lossy().to_string())
            // Ensure we don't attempt to connect to a real network by default.
            .env("TAU_BOOTSTRAP_PEERS", "[]")
            .env("TAU_NETWORK_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("TAU_ENV", &opts.tau_env);

        if opts.force_test_mode {
            cmd.env("TAU_FORCE_TEST", "1");
        }

        let mut child = cmd.spawn().map_err(|e| {
            MprdError::ExecutionError(format!(
                "failed to spawn tau-testnet node (python='{}', dir='{}'): {e}",
                opts.python,
                opts.tau_testnet_dir.display()
            ))
        })?;

        let addr: SocketAddr = format!("{}:{}", opts.host, opts.port)
            .parse()
            .map_err(|e| MprdError::ConfigError(format!("invalid tau-testnet addr: {e}")))?;

        wait_for_tcp_ready(&mut child, addr, opts.ready_timeout)?;

        Ok(Self { child, addr })
    }

    pub fn kill(&mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        Ok(())
    }
}

impl Drop for TauTestnetNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for_tcp_ready(child: &mut Child, addr: SocketAddr, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    let mut last_err: Option<String> = None;

    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait().map_err(|e| {
            MprdError::ExecutionError(format!("failed to poll tau-testnet process: {e}"))
        })? {
            let mut stderr = String::new();
            if let Some(mut s) = child.stderr.take() {
                use std::io::Read;
                let _ = s.read_to_string(&mut stderr);
            }
            return Err(MprdError::ExecutionError(format!(
                "tau-testnet exited early (status={status}); stderr:\n{stderr}"
            )));
        }

        match TcpStream::connect_timeout(&addr, Duration::from_millis(150)) {
            Ok(_) => return Ok(()),
            Err(e) => last_err = Some(e.to_string()),
        }

        thread::sleep(Duration::from_millis(50));
    }

    Err(MprdError::ExecutionError(format!(
        "tau-testnet not ready after {:?} (last_err={:?})",
        timeout, last_err
    )))
}

/// Minimal TCP client for Tau Testnet "RPC" (newline-delimited string commands).
#[derive(Clone, Debug)]
pub struct TauTestnetClient {
    addr: SocketAddr,
    timeout: Duration,
}

impl TauTestnetClient {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            timeout: Duration::from_secs(2),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send one command and read exactly one line response.
    ///
    /// # Protocol notes
    /// Tau Testnet uses a simple line-oriented protocol over TCP.
    pub fn call(&self, command: &str) -> Result<String> {
        let mut stream = TcpStream::connect_timeout(&self.addr, self.timeout).map_err(|e| {
            MprdError::ExecutionError(format!("failed to connect tau-testnet at {}: {e}", self.addr))
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| MprdError::ExecutionError(format!("failed to set read timeout: {e}")))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| MprdError::ExecutionError(format!("failed to set write timeout: {e}")))?;

        // Tau server expects utf-8; it strips whitespace.
        stream
            .write_all(format!("{command}\n").as_bytes())
            .map_err(|e| MprdError::ExecutionError(format!("failed to write to tau-testnet: {e}")))?;
        stream.flush().ok();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| {
            MprdError::ExecutionError(format!("failed to read tau-testnet response: {e}"))
        })?;
        Ok(line.trim().to_string())
    }
}

/// Pick a free local TCP port.
pub fn pick_free_local_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| MprdError::ExecutionError(format!("failed to bind ephemeral port: {e}")))?;
    Ok(listener
        .local_addr()
        .map_err(|e| MprdError::ExecutionError(format!("failed to read local_addr: {e}")))?
        .port())
}

/// Convenience for locating `external/tau-testnet` from `CARGO_MANIFEST_DIR` (mprd-core crate).
pub fn default_tau_testnet_dir_from_manifest() -> PathBuf {
    // crates/mprd-core -> crates -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("external")
        .join("tau-testnet")
}

