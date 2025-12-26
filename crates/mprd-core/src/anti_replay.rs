//! Anti-replay mechanism for decision tokens.
//!
//! Enforces invariant S4: No `DecisionToken` can be validly used more than once.
//!
//! # Security Warning
//!
//! The `InMemoryNonceTracker` is suitable for development and testing only.
//! For production deployments, implement `PersistentNonceStore` with durable
//! storage (database, Redis, blockchain) to prevent replay attacks after
//! process restarts.
//!
//! # Production Recommendations
//!
//! 1. Use `PersistentNonceTracker` with a database-backed store
//! 2. Consider blockchain anchoring for highest assurance
//! 3. Implement WAL or similar for crash recovery
//! 4. Replicate nonce state across nodes in distributed deployments

use crate::{DecisionToken, MprdError, NonceHash, PolicyHash, Result};
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

/// Configuration for anti-replay validation.
#[derive(Clone, Debug)]
pub struct AntiReplayConfig {
    /// Maximum token age in milliseconds.
    pub max_token_age_ms: i64,

    /// How long to retain nonces for replay checking.
    pub nonce_retention_ms: i64,

    /// Maximum allowed clock skew (future timestamps).
    pub max_future_skew_ms: i64,

    pub max_tracked_nonces: usize,
}

impl AntiReplayConfig {
    /// Create a new AntiReplayConfig with validation.
    ///
    /// # Security
    /// Validates that `nonce_retention_ms >= max_token_age_ms + max_future_skew_ms`.
    /// This ensures nonces are retained for at least as long as tokens could be valid,
    /// preventing replay attacks in the gap between token validity and nonce expiry.
    ///
    /// # Errors
    /// Returns an error if the config would allow replay attacks.
    pub fn new(
        max_token_age_ms: i64,
        nonce_retention_ms: i64,
        max_future_skew_ms: i64,
        max_tracked_nonces: usize,
    ) -> Result<Self> {
        let min_retention = max_token_age_ms.saturating_add(max_future_skew_ms);
        if nonce_retention_ms < min_retention {
            return Err(MprdError::ConfigError(format!(
                "nonce_retention_ms ({}) must be >= max_token_age_ms ({}) + max_future_skew_ms ({}) = {} \
                to prevent replay attacks in the validity-retention gap",
                nonce_retention_ms, max_token_age_ms, max_future_skew_ms, min_retention
            )));
        }
        if max_token_age_ms <= 0 {
            return Err(MprdError::ConfigError(
                "max_token_age_ms must be positive".into(),
            ));
        }
        if max_future_skew_ms < 0 {
            return Err(MprdError::ConfigError(
                "max_future_skew_ms cannot be negative".into(),
            ));
        }
        if max_tracked_nonces == 0 {
            return Err(MprdError::ConfigError(
                "max_tracked_nonces must be > 0".into(),
            ));
        }
        Ok(Self {
            max_token_age_ms,
            nonce_retention_ms,
            max_future_skew_ms,
            max_tracked_nonces,
        })
    }

    /// Create a config without validation (for tests and migration).
    ///
    /// # Security Warning
    /// This bypasses safety checks. Use `new()` for production.
    #[doc(hidden)]
    pub fn unchecked(
        max_token_age_ms: i64,
        nonce_retention_ms: i64,
        max_future_skew_ms: i64,
        max_tracked_nonces: usize,
    ) -> Self {
        Self {
            max_token_age_ms,
            nonce_retention_ms,
            max_future_skew_ms,
            max_tracked_nonces,
        }
    }
}

impl Default for AntiReplayConfig {
    fn default() -> Self {
        Self {
            max_token_age_ms: 60_000,      // 1 minute
            nonce_retention_ms: 3_600_000, // 1 hour (well above 60s + 5s)
            max_future_skew_ms: 5_000,     // 5 seconds
            max_tracked_nonces: 100_000,
        }
    }
}

/// Trait for nonce validation.
pub trait NonceValidator: Send + Sync {
    /// Check if a token's nonce is valid (not replayed, not expired).
    fn validate(&self, token: &DecisionToken) -> Result<()>;

    /// Validate a token and (optionally) claim its nonce before execution.
    ///
    /// This is used to prevent double-execution under concurrency and in
    /// multi-node deployments where multiple executors may race to execute
    /// the same token.
    ///
    /// Implementations may return `NonceClaim::NotClaimed` to preserve the
    /// legacy "mark-used-after-success" behavior.
    fn validate_and_claim(&self, token: &DecisionToken) -> Result<NonceClaim> {
        self.validate(token)?;
        Ok(NonceClaim::NotClaimed)
    }

    /// Mark a nonce as used after successful execution.
    fn mark_used(&self, token: &DecisionToken) -> Result<()>;

    /// Clean up expired nonces.
    fn cleanup(&self);
}

/// Result of `NonceValidator::validate_and_claim`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceClaim {
    /// The nonce was validated but not claimed; caller MUST call `mark_used` on success.
    NotClaimed,
    /// The nonce was claimed before execution; caller MUST NOT call `mark_used` again.
    Claimed,
}

/// Trait for persistent nonce storage (single-node).
///
/// # Security
///
/// Implementations MUST ensure durability - nonces must survive process
/// restarts to prevent replay attacks. Use database transactions, WAL,
/// or similar mechanisms for crash recovery.
///
/// # Contract
///
/// - `store`: Must durably persist the nonce before returning Ok
/// - `exists`: Must return true if nonce was ever stored (including before restarts)
/// - `remove_expired`: May remove nonces older than the retention period
///
/// # Trust Mode
///
/// This trait is suitable for **High-Trust Mode** (single-node deployments).
/// For **Low-Trust Mode** (multi-node deployments), use `DistributedNonceStore`.
pub trait PersistentNonceStore: Send + Sync {
    /// Store a nonce with its usage timestamp.
    ///
    /// # Durability Requirement
    ///
    /// This method MUST NOT return Ok until the nonce is durably persisted.
    /// A process crash after Ok should not lose the nonce.
    fn store(&self, policy_hash: &PolicyHash, nonce: &NonceHash, used_at_ms: i64) -> Result<()>;

    /// Check if a nonce exists in the store.
    fn exists(&self, policy_hash: &PolicyHash, nonce: &NonceHash) -> Result<bool>;

    /// Remove nonces older than the cutoff timestamp.
    fn remove_expired(&self, cutoff_ms: i64) -> Result<usize>;

    /// Count total stored nonces (for capacity management).
    fn count(&self) -> Result<usize>;
}

// =============================================================================
// Low-Trust Mode: Distributed Nonce Store (multi-node anti-replay)
// =============================================================================

/// Trait for distributed nonce storage (multi-node).
///
/// # Security
///
/// Implementations MUST ensure:
/// - **Atomicity**: The check-and-set operation is atomic across all nodes.
/// - **Consistency**: All nodes see the same nonce state.
/// - **Durability**: Nonces survive node failures.
///
/// # Contract
///
/// - `try_claim_nonce`: Atomically checks if nonce exists and claims it if not.
///   Returns `Ok(true)` if successfully claimed (first caller wins).
///   Returns `Ok(false)` if already claimed (replay detected).
///   Returns `Err` on infrastructure failures (fail-closed).
///
/// # Trust Mode
///
/// This trait is required for **Low-Trust Mode** (multi-node deployments).
/// It eliminates the single point of failure present in `PersistentNonceStore`.
///
/// # Example Implementations
///
/// - Redis with `SETNX` (SET if Not eXists)
/// - PostgreSQL with `INSERT ... ON CONFLICT DO NOTHING`
/// - etcd with transactions
/// - On-chain nonce tracking (highest assurance)
pub trait DistributedNonceStore: Send + Sync {
    /// Atomically check-and-claim a nonce.
    ///
    /// This is the core primitive for distributed anti-replay:
    /// - If nonce does not exist: create it and return `Ok(true)`
    /// - If nonce already exists: return `Ok(false)` (replay detected)
    /// - On any error: return `Err` (fail-closed)
    ///
    /// # Atomicity Requirement
    ///
    /// The check-and-set MUST be atomic. A race between two nodes
    /// calling this method with the same nonce MUST result in exactly
    /// one `Ok(true)` and one `Ok(false)`.
    fn try_claim_nonce(
        &self,
        policy_hash: &PolicyHash,
        nonce: &NonceHash,
        used_at_ms: i64,
        ttl_ms: i64,
    ) -> Result<bool>;

    /// Check if a nonce has been claimed (without claiming it).
    fn is_claimed(&self, policy_hash: &PolicyHash, nonce: &NonceHash) -> Result<bool>;

    /// Get the backend name (for logging/diagnostics).
    fn backend_name(&self) -> &'static str;
}

/// Shared-filesystem distributed nonce store.
///
/// This is a pragmatic pre-testnet backend: if multiple nodes share the same directory
/// (with correct atomic-create semantics), they can coordinate replay protection by
/// claiming nonce files. This is not suitable for adversarial environments unless the
/// filesystem is trusted to provide atomicity.
#[derive(Clone, Debug)]
pub struct SharedFsDistributedNonceStore {
    root: PathBuf,
}

impl SharedFsDistributedNonceStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| {
            MprdError::ExecutionError(format!("Failed to create nonce store root: {}", e))
        })?;
        Ok(Self { root })
    }

    fn nonce_path(&self, policy_hash: &PolicyHash, nonce: &NonceHash) -> PathBuf {
        let policy = hex::encode(policy_hash.0);
        let nonce = hex::encode(nonce.0);
        self.root.join(policy).join(nonce)
    }
}

impl DistributedNonceStore for SharedFsDistributedNonceStore {
    fn try_claim_nonce(
        &self,
        policy_hash: &PolicyHash,
        nonce: &NonceHash,
        used_at_ms: i64,
        ttl_ms: i64,
    ) -> Result<bool> {
        let path = self.nonce_path(policy_hash, nonce);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                MprdError::ExecutionError(format!("Failed to create nonce dir: {}", e))
            })?;
        }

        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
            Err(e) => {
                return Err(MprdError::ExecutionError(format!(
                    "Failed to claim nonce: {}",
                    e
                )))
            }
        };

        // Best-effort metadata: used_at_ms and ttl_ms are stored for audit/debugging.
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&used_at_ms.to_le_bytes());
        bytes[8..16].copy_from_slice(&ttl_ms.to_le_bytes());
        file.write_all(&bytes)
            .map_err(|e| MprdError::ExecutionError(format!("Failed to write nonce file: {}", e)))?;
        file.sync_all().ok(); // best-effort durability; fail-closed on write, not on sync.
        Ok(true)
    }

    fn is_claimed(&self, policy_hash: &PolicyHash, nonce: &NonceHash) -> Result<bool> {
        Ok(self.nonce_path(policy_hash, nonce).exists())
    }

    fn backend_name(&self) -> &'static str {
        "shared_fs"
    }
}

// =============================================================================
// Low-Trust Mode: Redis Distributed Nonce Store
// =============================================================================

#[derive(Clone, Debug)]
struct RedisEndpoint {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    db: u32,
    use_tls: bool,
}

type RedisTlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

enum RedisConnection {
    Plain(TcpStream),
    Tls(RedisTlsStream),
}

impl std::fmt::Debug for RedisConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedisConnection::Plain(_) => f.write_str("RedisConnection::Plain"),
            RedisConnection::Tls(_) => f.write_str("RedisConnection::Tls"),
        }
    }
}

impl Read for RedisConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            RedisConnection::Plain(stream) => stream.read(buf),
            RedisConnection::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for RedisConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            RedisConnection::Plain(stream) => stream.write(buf),
            RedisConnection::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            RedisConnection::Plain(stream) => stream.flush(),
            RedisConnection::Tls(stream) => stream.flush(),
        }
    }
}

fn parse_redis_url(url: &str) -> Result<RedisEndpoint> {
    // Supported: redis://[user[:password]@]host[:port][/db]
    //            rediss://[user[:password]@]host[:port][/db] (TLS)
    // Security: redis:// is plaintext; use rediss:// for non-loopback deployments.
    const REDIS_PREFIX: &str = "redis://";
    const REDISS_PREFIX: &str = "rediss://";
    let (rest, use_tls) = if let Some(rest) = url.strip_prefix(REDISS_PREFIX) {
        (rest, true)
    } else if let Some(rest) = url.strip_prefix(REDIS_PREFIX) {
        (rest, false)
    } else {
        return Err(MprdError::ConfigError(
            "redis_url must start with redis:// or rediss://".into(),
        ));
    };

    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (rest, None),
    };

    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };

    let (username, password) = match userinfo {
        None => (None, None),
        Some(u) => {
            if u.is_empty() {
                (None, None)
            } else if let Some((user, pass)) = u.split_once(':') {
                let username = (!user.is_empty()).then(|| user.to_string());
                let password = (!pass.is_empty()).then(|| pass.to_string());
                (username, password)
            } else if let Some(pass) = u.strip_prefix(':') {
                let password = (!pass.is_empty()).then(|| pass.to_string());
                (None, password)
            } else {
                (Some(u.to_string()), None)
            }
        }
    };

    let (host, port) = if hostport.starts_with('[') {
        // IPv6: [::1]:6379
        let close = hostport.find(']').ok_or_else(|| {
            MprdError::ConfigError("redis_url has invalid IPv6 host bracket".into())
        })?;
        let host = hostport[1..close].to_string();
        let rest = &hostport[(close + 1)..];
        let port = if rest.is_empty() {
            6379
        } else {
            let rest = rest
                .strip_prefix(':')
                .ok_or_else(|| MprdError::ConfigError("redis_url has invalid host:port".into()))?;
            rest.parse::<u16>()
                .map_err(|_| MprdError::ConfigError("redis_url has invalid port".into()))?
        };
        (host, port)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        // If there is a colon, treat it as host:port.
        // NOTE: This does not support raw (unbracketed) IPv6, which is non-standard in URLs.
        let port = p
            .parse::<u16>()
            .map_err(|_| MprdError::ConfigError("redis_url has invalid port".into()))?;
        (h.to_string(), port)
    } else {
        (hostport.to_string(), 6379)
    };

    if host.trim().is_empty() {
        return Err(MprdError::ConfigError(
            "redis_url must include a host".into(),
        ));
    }

    let db = match path {
        None | Some("") => 0,
        Some(p) => p
            .parse::<u32>()
            .map_err(|_| MprdError::ConfigError("redis_url has invalid db index".into()))?,
    };

    Ok(RedisEndpoint {
        host,
        port,
        username,
        password,
        db,
        use_tls,
    })
}

const ALLOW_INSECURE_REDIS_ENV: &str = "MPRD_ALLOW_INSECURE_REDIS";

fn allow_insecure_redis_from_env() -> bool {
    let Ok(value) = std::env::var(ALLOW_INSECURE_REDIS_ENV) else {
        return false;
    };
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn enforce_redis_tls_policy(endpoint: &RedisEndpoint, allow_insecure_redis: bool) -> Result<()> {
    if endpoint.use_tls || is_loopback_host(&endpoint.host) {
        return Ok(());
    }
    if allow_insecure_redis {
        warn!(
            "Redis is configured without TLS for non-loopback host {}; traffic (including AUTH) \
             is sent in plaintext. Use rediss:// for production.",
            endpoint.host
        );
        return Ok(());
    }
    Err(MprdError::ConfigError(format!(
        "redis_url points to a non-loopback host without TLS; use rediss:// or set {}=1 to allow insecure redis",
        ALLOW_INSECURE_REDIS_ENV
    )))
}

fn redis_tls_server_name(host: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(rustls::pki_types::ServerName::IpAddress(ip.into()));
    }
    rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| MprdError::ConfigError("redis_url has invalid TLS server name".into()))
}

fn redis_tls_config() -> Arc<ClientConfig> {
    static TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(TLS_CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }))
}

/// Distributed nonce store backed by Redis.
///
/// # Security
/// - Prefer `rediss://` to enforce TLS for remote Redis endpoints.
/// - Non-loopback `redis://` is plaintext; set `MPRD_ALLOW_INSECURE_REDIS=1` only
///   for trusted local networks and be aware credentials/nonce traffic are exposed.
#[derive(Debug)]
pub struct RedisDistributedNonceStore {
    endpoint: RedisEndpoint,
    key_prefix: String,
    io_timeout: Duration,
    conn: Mutex<Option<RedisConnection>>,
}

impl RedisDistributedNonceStore {
    pub fn new(redis_url: &str, key_prefix: &str, io_timeout: Duration) -> Result<Self> {
        if io_timeout.is_zero() {
            return Err(MprdError::ConfigError(
                "redis_timeout_ms must be > 0".into(),
            ));
        }
        let key_prefix = key_prefix.trim();
        if key_prefix.is_empty() {
            return Err(MprdError::ConfigError(
                "redis_key_prefix must be non-empty".into(),
            ));
        }
        let endpoint = parse_redis_url(redis_url)?;
        let allow_insecure_redis = allow_insecure_redis_from_env();
        enforce_redis_tls_policy(&endpoint, allow_insecure_redis)?;
        Ok(Self {
            endpoint,
            key_prefix: key_prefix.to_string(),
            io_timeout,
            conn: Mutex::new(None),
        })
    }

    fn nonce_key(&self, policy_hash: &PolicyHash, nonce: &NonceHash) -> String {
        let policy = hex::encode(policy_hash.0);
        let nonce = hex::encode(nonce.0);
        format!("{}:{}:{}", self.key_prefix, policy, nonce)
    }

    fn connect(&self) -> Result<RedisConnection> {
        // Use tuple-based resolution to handle IPv6 correctly (avoids `::1:6379` format issue)
        let addrs: Vec<_> = (self.endpoint.host.as_str(), self.endpoint.port)
            .to_socket_addrs()
            .map_err(|e| MprdError::ExecutionError(format!("Redis DNS resolution failed: {}", e)))?
            .collect();
        let sock = addrs.first().ok_or_else(|| {
            MprdError::ExecutionError("Redis DNS resolution returned no addresses".into())
        })?;

        let stream = TcpStream::connect_timeout(&sock, self.io_timeout)
            .map_err(|e| MprdError::ExecutionError(format!("Failed to connect to Redis: {}", e)))?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|e| {
                MprdError::ExecutionError(format!("Redis set_read_timeout failed: {}", e))
            })?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|e| {
                MprdError::ExecutionError(format!("Redis set_write_timeout failed: {}", e))
            })?;

        let mut conn = if self.endpoint.use_tls {
            let server_name = redis_tls_server_name(&self.endpoint.host)?;
            let config = redis_tls_config();
            let tls = rustls::ClientConnection::new(config, server_name).map_err(|e| {
                MprdError::ExecutionError(format!("Redis TLS configuration failed: {}", e))
            })?;
            RedisConnection::Tls(rustls::StreamOwned::new(tls, stream))
        } else {
            RedisConnection::Plain(stream)
        };

        self.initialize_connection(&mut conn)?;
        Ok(conn)
    }

    fn initialize_connection(&self, stream: &mut RedisConnection) -> Result<()> {
        if let Some(ref pass) = self.endpoint.password {
            let mut args: Vec<&[u8]> = Vec::new();
            args.push(b"AUTH");
            if let Some(ref user) = self.endpoint.username {
                args.push(user.as_bytes());
            }
            args.push(pass.as_bytes());
            let resp = redis_roundtrip(stream, &args)?;
            match resp {
                RedisValue::SimpleString(ref s) if s == "OK" => {}
                _ => {
                    return Err(MprdError::ExecutionError("Redis AUTH failed".into()));
                }
            }
        }

        if self.endpoint.db != 0 {
            let db = self.endpoint.db.to_string();
            let resp = redis_roundtrip(stream, &[b"SELECT", db.as_bytes()])?;
            match resp {
                RedisValue::SimpleString(ref s) if s == "OK" => {}
                _ => {
                    return Err(MprdError::ExecutionError("Redis SELECT failed".into()));
                }
            }
        }

        Ok(())
    }

    fn with_connection<T>(&self, f: impl FnOnce(&mut RedisConnection) -> Result<T>) -> Result<T> {
        let stream = self
            .conn
            .lock()
            .map_err(|_| MprdError::ExecutionError("Redis connection mutex poisoned".into()))?
            .take();

        let mut stream = match stream {
            Some(s) => s,
            None => self.connect()?,
        };

        let result = f(&mut stream);

        if result.is_ok() {
            let mut guard = self
                .conn
                .lock()
                .map_err(|_| MprdError::ExecutionError("Redis connection mutex poisoned".into()))?;
            *guard = Some(stream);
        }
        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RedisValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
}

fn read_line_crlf(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader
            .read_exact(&mut byte)
            .map_err(|e| MprdError::ExecutionError(format!("Redis read failed: {}", e)))?;
        buf.push(byte[0]);
        let n = buf.len();
        if n >= 2 && buf[n - 2] == b'\r' && buf[n - 1] == b'\n' {
            buf.truncate(n - 2);
            return Ok(buf);
        }
        if buf.len() > 8 * 1024 {
            return Err(MprdError::ExecutionError(
                "Redis protocol line too long".into(),
            ));
        }
    }
}

fn read_i64_crlf(reader: &mut impl Read) -> Result<i64> {
    let line = read_line_crlf(reader)?;
    let s = std::str::from_utf8(&line)
        .map_err(|_| MprdError::ExecutionError("Redis invalid UTF-8 integer".into()))?;
    s.parse::<i64>()
        .map_err(|_| MprdError::ExecutionError("Redis invalid integer".into()))
}

fn redis_read_value(reader: &mut impl Read) -> Result<RedisValue> {
    let mut prefix = [0u8; 1];
    reader
        .read_exact(&mut prefix)
        .map_err(|e| MprdError::ExecutionError(format!("Redis read failed: {}", e)))?;
    match prefix[0] {
        b'+' => {
            let line = read_line_crlf(reader)?;
            let s = String::from_utf8(line)
                .map_err(|_| MprdError::ExecutionError("Redis invalid UTF-8 string".into()))?;
            Ok(RedisValue::SimpleString(s))
        }
        b'-' => {
            let line = read_line_crlf(reader)?;
            let s = String::from_utf8(line)
                .map_err(|_| MprdError::ExecutionError("Redis invalid UTF-8 error".into()))?;
            Ok(RedisValue::Error(s))
        }
        b':' => Ok(RedisValue::Integer(read_i64_crlf(reader)?)),
        b'$' => {
            let len = read_i64_crlf(reader)?;
            if len < 0 {
                return Ok(RedisValue::Bulk(None));
            }
            let len: usize = len
                .try_into()
                .map_err(|_| MprdError::ExecutionError("Redis bulk length overflow".into()))?;
            if len > 16 * 1024 * 1024 {
                return Err(MprdError::ExecutionError(
                    "Redis bulk response too large".into(),
                ));
            }
            let mut data = vec![0u8; len];
            reader
                .read_exact(&mut data)
                .map_err(|e| MprdError::ExecutionError(format!("Redis read bulk failed: {}", e)))?;
            let mut crlf = [0u8; 2];
            reader
                .read_exact(&mut crlf)
                .map_err(|e| MprdError::ExecutionError(format!("Redis read CRLF failed: {}", e)))?;
            if crlf != [b'\r', b'\n'] {
                return Err(MprdError::ExecutionError("Redis bulk missing CRLF".into()));
            }
            Ok(RedisValue::Bulk(Some(data)))
        }
        b'*' => Err(MprdError::ExecutionError(
            "Redis array responses not supported".into(),
        )),
        other => Err(MprdError::ExecutionError(format!(
            "Redis invalid response prefix byte: {}",
            other
        ))),
    }
}

fn redis_encode_command(args: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for arg in args {
        out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        out.extend_from_slice(arg);
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn redis_roundtrip(stream: &mut (impl Read + Write), args: &[&[u8]]) -> Result<RedisValue> {
    let cmd = redis_encode_command(args);
    stream
        .write_all(&cmd)
        .map_err(|e| MprdError::ExecutionError(format!("Redis write failed: {}", e)))?;
    stream
        .flush()
        .map_err(|e| MprdError::ExecutionError(format!("Redis flush failed: {}", e)))?;
    let resp = redis_read_value(stream)?;
    if let RedisValue::Error(e) = &resp {
        return Err(MprdError::ExecutionError(format!("Redis error: {}", e)));
    }
    Ok(resp)
}

impl DistributedNonceStore for RedisDistributedNonceStore {
    fn try_claim_nonce(
        &self,
        policy_hash: &PolicyHash,
        nonce: &NonceHash,
        used_at_ms: i64,
        ttl_ms: i64,
    ) -> Result<bool> {
        if ttl_ms <= 0 {
            return Err(MprdError::ExecutionError(
                "Redis nonce ttl_ms must be > 0".into(),
            ));
        }
        let key = self.nonce_key(policy_hash, nonce);
        let val = used_at_ms.to_string();
        let ttl = ttl_ms.to_string();

        self.with_connection(|stream| {
            // SET key value PX ttl NX
            let resp = redis_roundtrip(
                stream,
                &[
                    b"SET",
                    key.as_bytes(),
                    val.as_bytes(),
                    b"PX",
                    ttl.as_bytes(),
                    b"NX",
                ],
            )?;

            match resp {
                RedisValue::SimpleString(ref s) if s == "OK" => Ok(true),
                RedisValue::Bulk(None) => Ok(false),
                _ => Err(MprdError::ExecutionError(
                    "Redis SET returned unexpected response".into(),
                )),
            }
        })
    }

    fn is_claimed(&self, policy_hash: &PolicyHash, nonce: &NonceHash) -> Result<bool> {
        let key = self.nonce_key(policy_hash, nonce);
        self.with_connection(|stream| {
            let resp = redis_roundtrip(stream, &[b"EXISTS", key.as_bytes()])?;
            match resp {
                RedisValue::Integer(i) => Ok(i > 0),
                _ => Err(MprdError::ExecutionError(
                    "Redis EXISTS returned unexpected response".into(),
                )),
            }
        })
    }

    fn backend_name(&self) -> &'static str {
        "redis"
    }
}

/// Nonce validator that uses a distributed store (low-trust mode).
///
/// Provides the same `NonceValidator` interface but backed by a
/// distributed store suitable for multi-node deployments.
pub struct DistributedNonceTracker<S: DistributedNonceStore> {
    store: S,
    config: AntiReplayConfig,
}

impl<S: DistributedNonceStore> DistributedNonceTracker<S> {
    pub fn new(store: S, config: AntiReplayConfig) -> Self {
        Self { store, config }
    }
}

impl<S: DistributedNonceStore> NonceValidator for DistributedNonceTracker<S> {
    fn validate(&self, token: &DecisionToken) -> Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MprdError::ExecutionError("system clock error".into()))?
            .as_millis() as i64;

        // Check timestamp bounds
        let age_ms = now_ms - token.timestamp_ms;
        if age_ms > self.config.max_token_age_ms {
            return Err(MprdError::TokenExpired {
                age_ms,
                max_age_ms: self.config.max_token_age_ms,
            });
        }
        if age_ms < -self.config.max_future_skew_ms {
            return Err(MprdError::ExecutionError(format!(
                "token timestamp too far in future: {}ms",
                -age_ms
            )));
        }

        // Check if nonce is already claimed (without claiming yet)
        if self
            .store
            .is_claimed(&token.policy_hash, &token.nonce_or_tx_hash)?
        {
            return Err(MprdError::NonceReplay {
                nonce: token.nonce_or_tx_hash.clone(),
            });
        }

        Ok(())
    }

    fn validate_and_claim(&self, token: &DecisionToken) -> Result<NonceClaim> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MprdError::ExecutionError("system clock error".into()))?
            .as_millis() as i64;

        // Check timestamp bounds (same as `validate` but without the TOCTOU gap).
        let age_ms = now_ms - token.timestamp_ms;
        if age_ms > self.config.max_token_age_ms {
            return Err(MprdError::TokenExpired {
                age_ms,
                max_age_ms: self.config.max_token_age_ms,
            });
        }
        if age_ms < -self.config.max_future_skew_ms {
            return Err(MprdError::ExecutionError(format!(
                "token timestamp too far in future: {}ms",
                -age_ms
            )));
        }

        // Atomic claim (first caller wins). This prevents a multi-node race from
        // executing the same token twice.
        let claimed = self.store.try_claim_nonce(
            &token.policy_hash,
            &token.nonce_or_tx_hash,
            now_ms,
            self.config.nonce_retention_ms,
        )?;

        if !claimed {
            return Err(MprdError::NonceReplay {
                nonce: token.nonce_or_tx_hash.clone(),
            });
        }

        Ok(NonceClaim::Claimed)
    }

    fn mark_used(&self, token: &DecisionToken) -> Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MprdError::ExecutionError("system clock error".into()))?
            .as_millis() as i64;

        // Atomic claim - fails if another node already claimed it
        let claimed = self.store.try_claim_nonce(
            &token.policy_hash,
            &token.nonce_or_tx_hash,
            now_ms,
            self.config.nonce_retention_ms,
        )?;

        if !claimed {
            return Err(MprdError::NonceReplay {
                nonce: token.nonce_or_tx_hash.clone(),
            });
        }

        Ok(())
    }

    fn cleanup(&self) {
        // Distributed stores typically handle TTL-based cleanup internally
        // (e.g., Redis EXPIRE, PostgreSQL scheduled jobs)
    }
}

/// File-backed nonce store.
///
/// Stores each used nonce as a file:
/// `root/<policy_hash_hex>/<nonce_hex>`
///
/// The file content is `used_at_ms` encoded as `i64` little-endian (8 bytes).
///
/// # Security
/// - `store()` uses `create_new(true)` so concurrent calls fail-closed if the nonce already exists.
/// - Files are `sync_all()`'d before returning Ok (best-effort durability).
#[derive(Clone, Debug)]
pub struct FileNonceStore {
    root: PathBuf,
}

impl FileNonceStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| {
            MprdError::ExecutionError(format!("Failed to create nonce_store_dir: {e}"))
        })?;
        Ok(Self { root })
    }

    fn nonce_path(&self, policy_hash: &PolicyHash, nonce: &NonceHash) -> PathBuf {
        let policy_hex = hex::encode(policy_hash.0);
        let nonce_hex = hex::encode(nonce.0);
        self.root.join(policy_hex).join(nonce_hex)
    }

    fn sync_dir(path: &Path) -> Result<()> {
        let dir = File::open(path).map_err(|e| {
            MprdError::ExecutionError(format!("Failed to open directory for sync: {e}"))
        })?;
        dir.sync_all()
            .map_err(|e| MprdError::ExecutionError(format!("Failed to sync directory: {e}")))?;
        Ok(())
    }
}

impl PersistentNonceStore for FileNonceStore {
    fn store(&self, policy_hash: &PolicyHash, nonce: &NonceHash, used_at_ms: i64) -> Result<()> {
        let path = self.nonce_path(policy_hash, nonce);
        let parent = path.parent().ok_or_else(|| {
            MprdError::ExecutionError("Invalid nonce path (missing parent)".into())
        })?;
        fs::create_dir_all(parent).map_err(|e| {
            MprdError::ExecutionError(format!("Failed to create policy nonce dir: {e}"))
        })?;

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    MprdError::NonceReplay {
                        nonce: nonce.clone(),
                    }
                } else {
                    MprdError::ExecutionError(format!("Failed to create nonce file: {e}"))
                }
            })?;

        file.write_all(&used_at_ms.to_le_bytes())
            .map_err(|e| MprdError::ExecutionError(format!("Failed to write nonce file: {e}")))?;
        file.sync_all()
            .map_err(|e| MprdError::ExecutionError(format!("Failed to sync nonce file: {e}")))?;

        // Fail-closed: propagate directory fsync errors to ensure durability.
        // Silent fsync failures could lead to nonce loss on crash -> replay attacks.
        Self::sync_dir(parent)?;
        Self::sync_dir(&self.root)?;
        Ok(())
    }

    fn exists(&self, policy_hash: &PolicyHash, nonce: &NonceHash) -> Result<bool> {
        Ok(self.nonce_path(policy_hash, nonce).exists())
    }

    fn remove_expired(&self, cutoff_ms: i64) -> Result<usize> {
        let mut removed = 0usize;
        let policy_dirs = match fs::read_dir(&self.root) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => {
                return Err(MprdError::ExecutionError(format!(
                    "Failed to read nonce store dir: {e}"
                )))
            }
        };

        for policy_entry in policy_dirs {
            let policy_entry = match policy_entry {
                Ok(v) => v,
                Err(_) => continue,
            };
            let policy_path = policy_entry.path();
            if !policy_path.is_dir() {
                continue;
            }

            let nonces = match fs::read_dir(&policy_path) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for nonce_entry in nonces {
                let nonce_entry = match nonce_entry {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let path = nonce_entry.path();
                if !path.is_file() {
                    continue;
                }

                let mut buf = [0u8; 8];
                let mut file = match File::open(&path) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                if file.read_exact(&mut buf).is_err() {
                    // Fail-closed: keep entries we can't parse.
                    continue;
                }
                let used_at = i64::from_le_bytes(buf);
                if used_at < cutoff_ms && fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }

            if fs::read_dir(&policy_path)
                .map(|mut it| it.next().is_none())
                .unwrap_or(false)
            {
                let _ = fs::remove_dir(&policy_path);
            }
        }

        Ok(removed)
    }

    fn count(&self) -> Result<usize> {
        let mut count = 0usize;
        let policy_dirs = match fs::read_dir(&self.root) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => {
                return Err(MprdError::ExecutionError(format!(
                    "Failed to read nonce store dir: {e}"
                )))
            }
        };

        for policy_entry in policy_dirs {
            let policy_entry = match policy_entry {
                Ok(v) => v,
                Err(_) => continue,
            };
            let policy_path = policy_entry.path();
            if !policy_path.is_dir() {
                continue;
            }
            let nonces = match fs::read_dir(&policy_path) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for nonce_entry in nonces {
                let nonce_entry = match nonce_entry {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if nonce_entry.path().is_file() {
                    count += 1;
                }
            }
        }

        Ok(count)
    }
}

/// Persistent nonce tracker that uses a durable store.
///
/// # Security
///
/// This tracker provides production-grade replay protection by persisting
/// nonces to durable storage. Use this for production deployments.
pub struct PersistentNonceTracker<S: PersistentNonceStore> {
    store: S,
    config: AntiReplayConfig,
}

impl<S: PersistentNonceStore> PersistentNonceTracker<S> {
    /// Create a new persistent tracker with the given store.
    pub fn new(store: S, config: AntiReplayConfig) -> Self {
        Self { store, config }
    }

    fn current_time_ms() -> Result<i64> {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MprdError::ExecutionError("System clock error".into()))?
            .as_millis();
        let ms: i64 = ms
            .try_into()
            .map_err(|_| MprdError::ExecutionError("System clock overflow".into()))?;
        Ok(ms)
    }
}

impl<S: PersistentNonceStore> NonceValidator for PersistentNonceTracker<S> {
    fn validate(&self, token: &DecisionToken) -> Result<()> {
        let now_ms = Self::current_time_ms()?;
        let age = now_ms - token.timestamp_ms;

        if age > self.config.max_token_age_ms {
            return Err(MprdError::TokenExpired {
                age_ms: age,
                max_age_ms: self.config.max_token_age_ms,
            });
        }

        if age < -self.config.max_future_skew_ms {
            return Err(MprdError::TokenFromFuture { skew_ms: -age });
        }

        // Check persistent store for replay
        if self
            .store
            .exists(&token.policy_hash, &token.nonce_or_tx_hash)?
        {
            return Err(MprdError::NonceReplay {
                nonce: token.nonce_or_tx_hash.clone(),
            });
        }

        Ok(())
    }

    fn mark_used(&self, token: &DecisionToken) -> Result<()> {
        let now_ms = Self::current_time_ms()?;

        // Check capacity
        let count = self.store.count()?;
        if count >= self.config.max_tracked_nonces {
            // Try to clean up expired first
            let cutoff = now_ms - self.config.nonce_retention_ms;
            self.store.remove_expired(cutoff)?;

            // Check again
            let count = self.store.count()?;
            if count >= self.config.max_tracked_nonces {
                return Err(MprdError::ExecutionError(
                    "Nonce store capacity exceeded".into(),
                ));
            }
        }

        // SECURITY: Double-check for replay under store operation
        // The store implementation should use transactions/locking
        if self
            .store
            .exists(&token.policy_hash, &token.nonce_or_tx_hash)?
        {
            return Err(MprdError::NonceReplay {
                nonce: token.nonce_or_tx_hash.clone(),
            });
        }

        self.store
            .store(&token.policy_hash, &token.nonce_or_tx_hash, now_ms)
    }

    fn cleanup(&self) {
        if let Ok(now_ms) = Self::current_time_ms() {
            let cutoff = now_ms - self.config.nonce_retention_ms;
            let _ = self.store.remove_expired(cutoff);
        }
    }
}

/// Entry tracking when a nonce was used.
#[derive(Clone, Debug)]
struct NonceEntry {
    used_at_ms: i64,
}

/// In-memory nonce tracker.
///
/// # Security Warning
///
/// **DO NOT USE IN PRODUCTION** without understanding the implications:
/// - Nonces are lost on process restart, enabling replay attacks
/// - Not suitable for distributed deployments (no shared state)
/// - Use `PersistentNonceTracker` with a durable store for production
///
/// This implementation is suitable for:
/// - Development and testing
/// - Single-process deployments with acceptable replay risk window
/// - Situations where tokens have very short lifetimes (< restart frequency)
pub struct InMemoryNonceTracker {
    /// Map of (policy_hash, nonce) -> usage info.
    used: RwLock<HashMap<(PolicyHash, NonceHash), NonceEntry>>,

    /// Configuration.
    config: AntiReplayConfig,

    /// Whether the production warning has been emitted.
    warned: std::sync::atomic::AtomicBool,
}

impl InMemoryNonceTracker {
    /// Create a new tracker with default configuration.
    ///
    /// # Security Warning
    ///
    /// Emits a warning on first use. For production, use `PersistentNonceTracker`.
    pub fn new() -> Self {
        Self::with_config(AntiReplayConfig::default())
    }

    /// Create a new tracker with custom configuration.
    pub fn with_config(config: AntiReplayConfig) -> Self {
        Self {
            used: RwLock::new(HashMap::new()),
            config,
            warned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Emit a one-time warning about production use.
    fn warn_if_production(&self) {
        if !self.warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
            warn!(
                "InMemoryNonceTracker is NOT suitable for production. \
                 Nonces will be lost on restart, enabling replay attacks. \
                 Use PersistentNonceTracker with durable storage instead."
            );
        }
    }

    fn current_time_ms() -> Result<i64> {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MprdError::ExecutionError("System clock error".into()))?
            .as_millis();
        let ms: i64 = ms
            .try_into()
            .map_err(|_| MprdError::ExecutionError("System clock overflow".into()))?;
        Ok(ms)
    }
}

impl Default for InMemoryNonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceValidator for InMemoryNonceTracker {
    fn validate(&self, token: &DecisionToken) -> Result<()> {
        // SECURITY: Warn about production use
        self.warn_if_production();

        let now_ms = Self::current_time_ms()?;
        let age = now_ms - token.timestamp_ms;

        // Check if token is too old
        if age > self.config.max_token_age_ms {
            return Err(MprdError::TokenExpired {
                age_ms: age,
                max_age_ms: self.config.max_token_age_ms,
            });
        }

        // Check if token is from the future (beyond allowed skew)
        if age < -self.config.max_future_skew_ms {
            return Err(MprdError::TokenFromFuture { skew_ms: -age });
        }

        // SECURITY: replay check is a read-side check and therefore subject to TOCTOU.
        // Correctness relies on re-checking inside `mark_used` under a write lock.
        // This keeps the overall executor flow fail-closed even under concurrency.
        // SECURITY: Handle poisoned lock gracefully.
        let key = (token.policy_hash.clone(), token.nonce_or_tx_hash.clone());
        let used = self
            .used
            .read()
            .map_err(|_| MprdError::ExecutionError("Nonce tracker lock poisoned".into()))?;

        if used.contains_key(&key) {
            return Err(MprdError::NonceReplay {
                nonce: token.nonce_or_tx_hash.clone(),
            });
        }

        Ok(())
    }

    fn mark_used(&self, token: &DecisionToken) -> Result<()> {
        let key = (token.policy_hash.clone(), token.nonce_or_tx_hash.clone());
        let entry = NonceEntry {
            used_at_ms: Self::current_time_ms()?,
        };

        // SECURITY: Handle poisoned lock gracefully
        let mut used = self
            .used
            .write()
            .map_err(|_| MprdError::ExecutionError("Nonce tracker lock poisoned".into()))?;

        // SECURITY: this is the authoritative replay check under an exclusive lock.
        // If a concurrent caller validated the same token, this prevents a double-spend.
        if used.contains_key(&key) {
            return Err(MprdError::NonceReplay {
                nonce: token.nonce_or_tx_hash.clone(),
            });
        }

        if used.len() >= self.config.max_tracked_nonces {
            // SECURITY: storage is bounded. We attempt to prune expired entries first; if still at
            // capacity, we fail closed rather than silently dropping replay protection.
            let cutoff = entry.used_at_ms - self.config.nonce_retention_ms;
            used.retain(|_, existing| existing.used_at_ms > cutoff);

            if used.len() >= self.config.max_tracked_nonces {
                return Err(MprdError::ExecutionError(
                    "Nonce tracker capacity exceeded".into(),
                ));
            }
        }

        used.insert(key, entry);
        Ok(())
    }

    fn cleanup(&self) {
        let Ok(now_ms) = Self::current_time_ms() else {
            return;
        };
        let cutoff = now_ms - self.config.nonce_retention_ms;

        // Best effort cleanup - if lock is poisoned, skip cleanup
        if let Ok(mut used) = self.used.write() {
            used.retain(|_, entry| entry.used_at_ms > cutoff);
        }
    }
}

/// Executor wrapper that enforces anti-replay.
pub struct AntiReplayExecutor<E, N> {
    inner: E,
    nonce_validator: N,
}

impl<E, N> AntiReplayExecutor<E, N>
where
    E: crate::ExecutorAdapter,
    N: NonceValidator,
{
    /// Create a new anti-replay executor.
    pub fn new(inner: E, nonce_validator: N) -> Self {
        Self {
            inner,
            nonce_validator,
        }
    }
}

impl<E, N> crate::ExecutorAdapter for AntiReplayExecutor<E, N>
where
    E: crate::ExecutorAdapter,
    N: NonceValidator,
{
    fn execute(&self, verified: &crate::VerifiedBundle<'_>) -> Result<crate::ExecutionResult> {
        // SECURITY: Checks-Effects-Interactions
        // - Check: validate timestamp bounds and replay status (fail closed on any error).
        // - Interaction: call the wrapped executor (external side effects).
        // - Effect:
        //   - High-trust: consume nonce only on success to prevent attacker-induced exhaustion.
        //   - Low-trust: may claim nonce before execution to prevent multi-node replay races.
        //
        // Invariant: a (policy_hash, nonce_or_tx_hash) tuple MUST be used at most once for a
        // successful execution.

        let token = verified.token();

        // Pre-condition: validate nonce (and, for distributed deployments, claim before execute).
        let claim = self.nonce_validator.validate_and_claim(token)?;

        // Execute the action
        let result = self.inner.execute(verified)?;

        // Post-condition: mark nonce as used (only on success)
        if result.success && claim == NonceClaim::NotClaimed {
            self.nonce_validator.mark_used(token)?;
        }

        Ok(result)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash32;
    use crate::{ExecutionResult, ExecutorAdapter, ProofBundle, VerifiedBundle};
    use proptest::prelude::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    fn new_temp_dir(prefix: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let pid = std::process::id();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!("mprd_{prefix}_{pid}_{now}"));
        std::fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn dummy_token(nonce_byte: u8, timestamp_ms: i64) -> DecisionToken {
        DecisionToken {
            policy_hash: Hash32([1u8; 32]),
            policy_ref: crate::PolicyRef {
                policy_epoch: 1,
                registry_root: Hash32([9u8; 32]),
            },
            state_hash: Hash32([2u8; 32]),
            state_ref: crate::StateRef::unknown(),
            chosen_action_hash: Hash32([3u8; 32]),
            nonce_or_tx_hash: Hash32([nonce_byte; 32]),
            timestamp_ms,
            signature: vec![],
        }
    }

    #[test]
    fn file_nonce_store_persists_across_restarts() {
        let dir = new_temp_dir("nonce_store");
        let store = FileNonceStore::new(&dir).expect("store");

        let policy = Hash32([1u8; 32]);
        let nonce = Hash32([2u8; 32]);

        assert!(!store.exists(&policy, &nonce).expect("exists"));
        store.store(&policy, &nonce, 123).expect("store nonce");
        assert!(store.exists(&policy, &nonce).expect("exists"));

        let store2 = FileNonceStore::new(&dir).expect("store2");
        assert!(store2
            .exists(&policy, &nonce)
            .expect("exists after restart"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_nonce_store_create_new_is_fail_closed() {
        let dir = new_temp_dir("nonce_store_replay");
        let store = FileNonceStore::new(&dir).expect("store");

        let policy = Hash32([1u8; 32]);
        let nonce = Hash32([2u8; 32]);

        store.store(&policy, &nonce, 123).expect("first store ok");
        let err = store
            .store(&policy, &nonce, 124)
            .expect_err("second store fails");
        assert!(matches!(err, MprdError::NonceReplay { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_fs_distributed_nonce_store_claims_once() {
        let dir = new_temp_dir("shared_fs_nonce_store");
        let store = SharedFsDistributedNonceStore::new(&dir).expect("store");

        let policy = Hash32([1u8; 32]);
        let nonce = Hash32([2u8; 32]);

        let claimed1 = store
            .try_claim_nonce(&policy, &nonce, 123, 60_000)
            .expect("claim1");
        let claimed2 = store
            .try_claim_nonce(&policy, &nonce, 124, 60_000)
            .expect("claim2");

        assert!(claimed1);
        assert!(!claimed2);
        assert!(store.is_claimed(&policy, &nonce).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_redis_url_supported_forms() {
        let e = parse_redis_url("redis://localhost").expect("url");
        assert_eq!(e.host, "localhost");
        assert_eq!(e.port, 6379);
        assert_eq!(e.db, 0);
        assert!(e.username.is_none());
        assert!(e.password.is_none());
        assert!(!e.use_tls);

        let e = parse_redis_url("redis://:pw@127.0.0.1:6380/2").expect("url");
        assert_eq!(e.host, "127.0.0.1");
        assert_eq!(e.port, 6380);
        assert_eq!(e.db, 2);
        assert_eq!(e.username, None);
        assert_eq!(e.password.as_deref(), Some("pw"));
        assert!(!e.use_tls);

        let e = parse_redis_url("redis://user:pw@[::1]:6379/0").expect("url");
        assert_eq!(e.host, "::1");
        assert_eq!(e.port, 6379);
        assert_eq!(e.db, 0);
        assert_eq!(e.username.as_deref(), Some("user"));
        assert_eq!(e.password.as_deref(), Some("pw"));
        assert!(!e.use_tls);

        let e = parse_redis_url("rediss://redis.example.com:6380/1").expect("url");
        assert_eq!(e.host, "redis.example.com");
        assert_eq!(e.port, 6380);
        assert_eq!(e.db, 1);
        assert!(e.use_tls);
    }

    #[test]
    fn redis_protocol_roundtrip_primitives_parse() {
        use std::io::Cursor;

        let ok = redis_read_value(&mut Cursor::new(b"+OK\r\n")).expect("ok");
        assert_eq!(ok, RedisValue::SimpleString("OK".to_string()));

        let nil = redis_read_value(&mut Cursor::new(b"$-1\r\n")).expect("nil");
        assert_eq!(nil, RedisValue::Bulk(None));

        let one = redis_read_value(&mut Cursor::new(b":1\r\n")).expect("one");
        assert_eq!(one, RedisValue::Integer(1));

        let cmd = redis_encode_command(&[b"PING", b""]);
        assert_eq!(cmd, b"*2\r\n$4\r\nPING\r\n$0\r\n\r\n".to_vec());
    }

    #[test]
    fn valid_token_passes() {
        let tracker = InMemoryNonceTracker::new();
        let now = InMemoryNonceTracker::current_time_ms().expect("clock");
        let token = dummy_token(1, now);

        assert!(tracker.validate(&token).is_ok());
    }

    #[test]
    fn expired_token_rejected() {
        let config = AntiReplayConfig {
            max_token_age_ms: 100,
            ..Default::default()
        };
        let tracker = InMemoryNonceTracker::with_config(config);

        let old_timestamp = InMemoryNonceTracker::current_time_ms().expect("clock") - 200;
        let token = dummy_token(1, old_timestamp);

        let result = tracker.validate(&token);
        assert!(matches!(result, Err(MprdError::TokenExpired { .. })));
    }

    #[test]
    fn future_token_rejected() {
        let config = AntiReplayConfig {
            max_future_skew_ms: 100,
            ..Default::default()
        };
        let tracker = InMemoryNonceTracker::with_config(config);

        let future_timestamp = InMemoryNonceTracker::current_time_ms().expect("clock") + 200;
        let token = dummy_token(1, future_timestamp);

        let result = tracker.validate(&token);
        assert!(matches!(result, Err(MprdError::TokenFromFuture { .. })));
    }

    #[test]
    fn replay_rejected() {
        let tracker = InMemoryNonceTracker::new();
        let now = InMemoryNonceTracker::current_time_ms().expect("clock");
        let token = dummy_token(1, now);

        // First use succeeds
        assert!(tracker.validate(&token).is_ok());
        tracker.mark_used(&token).unwrap();

        // Replay fails
        let result = tracker.validate(&token);
        assert!(matches!(result, Err(MprdError::NonceReplay { .. })));
    }

    #[test]
    fn different_nonces_allowed() {
        let tracker = InMemoryNonceTracker::new();
        let now = InMemoryNonceTracker::current_time_ms().expect("clock");

        let token1 = dummy_token(1, now);
        let token2 = dummy_token(2, now);

        tracker.validate(&token1).unwrap();
        tracker.mark_used(&token1).unwrap();

        // Different nonce should work
        assert!(tracker.validate(&token2).is_ok());
    }

    #[test]
    fn capacity_exhaustion_rejected() {
        let config = AntiReplayConfig {
            max_tracked_nonces: 1,
            nonce_retention_ms: 60_000,
            ..Default::default()
        };
        let tracker = InMemoryNonceTracker::with_config(config);
        let now = InMemoryNonceTracker::current_time_ms().expect("clock");

        let token1 = dummy_token(1, now);
        tracker.validate(&token1).unwrap();
        tracker.mark_used(&token1).unwrap();

        let token2 = dummy_token(2, now);
        tracker.validate(&token2).unwrap();
        let result = tracker.mark_used(&token2);
        assert!(matches!(result, Err(MprdError::ExecutionError(_))));
    }

    // =============================================================================
    // Stateful / model-based security tests (PBT-style, deterministic)
    // =============================================================================

    #[derive(Clone, Debug)]
    struct SplitMix64 {
        state: u64,
    }

    impl SplitMix64 {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        }

        fn next_usize(&mut self, max: usize) -> usize {
            if max == 0 {
                return 0;
            }
            (self.next_u64() as usize) % max
        }

        fn next_i64_range_inclusive(&mut self, min: i64, max: i64) -> i64 {
            debug_assert!(min <= max);
            let span: u64 = (max - min) as u64;
            min + ((self.next_u64() % (span + 1)) as i64)
        }
    }

    #[derive(Clone, Default)]
    struct RecordingParityExecutor {
        calls_by_nonce_byte: Arc<Mutex<HashMap<u8, u64>>>,
    }

    impl RecordingParityExecutor {
        fn calls_for(&self, nonce_byte: u8) -> u64 {
            *self
                .calls_by_nonce_byte
                .lock()
                .expect("lock")
                .get(&nonce_byte)
                .unwrap_or(&0)
        }
    }

    impl ExecutorAdapter for RecordingParityExecutor {
        fn execute(&self, verified: &crate::VerifiedBundle<'_>) -> Result<ExecutionResult> {
            let token = verified.token();
            let nonce_byte = token.nonce_or_tx_hash.0[0];
            let mut map = self.calls_by_nonce_byte.lock().expect("lock");
            *map.entry(nonce_byte).or_insert(0) += 1;

            // Deterministic success/failure: parity of timestamp.
            let success = (token.timestamp_ms % 2) == 0;
            Ok(ExecutionResult {
                success,
                message: None,
            })
        }
    }

    fn dummy_proof_for(token: &DecisionToken) -> ProofBundle {
        ProofBundle {
            policy_hash: token.policy_hash.clone(),
            state_hash: token.state_hash.clone(),
            candidate_set_hash: Hash32([4u8; 32]),
            chosen_action_hash: token.chosen_action_hash.clone(),
            limits_hash: Hash32([5u8; 32]),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![1],
            attestation_metadata: HashMap::new(),
        }
    }

    #[test]
    fn state_machine_high_trust_nonce_consumed_only_on_success() {
        let base = InMemoryNonceTracker::current_time_ms().expect("clock");

        for seed in 0u64..10 {
            let mut rng = SplitMix64::new(seed);
            let tracker = InMemoryNonceTracker::new();
            let inner = RecordingParityExecutor::default();
            let exec = AntiReplayExecutor::new(inner.clone(), tracker);

            let mut used: HashSet<u8> = HashSet::new();

            // Fixed small nonce set to force collisions and replay paths.
            let nonce_pool: [u8; 6] = [1, 2, 3, 4, 5, 6];

            for _ in 0..200 {
                let nonce_byte = nonce_pool[rng.next_usize(nonce_pool.len())];
                let ts_delta = rng.next_i64_range_inclusive(-10, 10);
                let token = dummy_token(nonce_byte, base + ts_delta);
                let proof = dummy_proof_for(&token);

                let expected_replay = used.contains(&nonce_byte);
                let expected_success = (token.timestamp_ms % 2) == 0;

                let verified = VerifiedBundle::new(&token, &proof);
                let result = exec.execute(&verified);

                if expected_replay {
                    assert!(matches!(result, Err(MprdError::NonceReplay { .. })));
                    continue;
                }

                let ok = result.expect("not replay");
                assert_eq!(ok.success, expected_success);
                if ok.success {
                    used.insert(nonce_byte);
                }
            }

            // Sanity: once a nonce is used successfully, any further attempts must not call inner.
            for &b in &nonce_pool {
                if used.contains(&b) {
                    // Upper bound: inner is called at least once; further calls are blocked.
                    assert!(inner.calls_for(b) >= 1);
                }
            }
        }
    }

    #[test]
    fn state_machine_low_trust_claims_nonce_before_execute_and_denies_retries() {
        for seed in 0u64..10 {
            let mut rng = SplitMix64::new(seed);
            let dir = new_temp_dir("state_machine_low_trust");
            let store = SharedFsDistributedNonceStore::new(&dir).expect("store");
            let config = AntiReplayConfig::default();

            // Two independent executors ("nodes") sharing the same distributed nonce store.
            let inner = RecordingParityExecutor::default();
            let exec0 = AntiReplayExecutor::new(
                inner.clone(),
                DistributedNonceTracker::new(store.clone(), config.clone()),
            );
            let exec1 =
                AntiReplayExecutor::new(inner.clone(), DistributedNonceTracker::new(store, config));

            let mut claimed: HashSet<u8> = HashSet::new();

            let nonce_pool: [u8; 6] = [7, 8, 9, 10, 11, 12];

            for _ in 0..200 {
                let node = rng.next_usize(2);
                let nonce_byte = nonce_pool[rng.next_usize(nonce_pool.len())];
                let ts_delta = rng.next_i64_range_inclusive(-10, 10);
                let now = InMemoryNonceTracker::current_time_ms().expect("clock");
                let token = dummy_token(nonce_byte, now + ts_delta);
                let proof = dummy_proof_for(&token);

                let expected_replay = claimed.contains(&nonce_byte);
                let executor = if node == 0 { &exec0 } else { &exec1 };

                let verified = VerifiedBundle::new(&token, &proof);
                let result = executor.execute(&verified);

                if expected_replay {
                    assert!(matches!(result, Err(MprdError::NonceReplay { .. })));
                } else {
                    let _ = result.expect("first claim executes (may succeed or fail)");
                    claimed.insert(nonce_byte);
                }
            }

            // Model property: in low-trust claim-before-execute mode, at most one inner call per nonce.
            for &b in &nonce_pool {
                let calls = inner.calls_for(b);
                assert!(
                    calls <= 1,
                    "nonce_byte={} was executed {} times (expected <= 1)",
                    b,
                    calls
                );
            }

            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    proptest! {
        #[test]
        fn high_trust_nonce_is_consumed_only_after_first_success(
            steps in proptest::collection::vec((any::<u8>(), -10i64..=10i64), 0..128),
        ) {
            let base = InMemoryNonceTracker::current_time_ms().expect("clock");

            // Keep timestamps within default skew/age bounds, and focus on replay logic.
            let tracker = InMemoryNonceTracker::new();
            let inner = RecordingParityExecutor::default();
            let exec = AntiReplayExecutor::new(inner.clone(), tracker);

            let mut used_success: HashSet<u8> = HashSet::new();
            let mut first_success_at: HashMap<u8, usize> = HashMap::new();

            for (idx, (nonce_byte, delta)) in steps.iter().copied().enumerate() {
                let token = dummy_token(nonce_byte, base + delta);
                let proof = dummy_proof_for(&token);

                let expected_success = (token.timestamp_ms % 2) == 0;
                let expect_replay = used_success.contains(&nonce_byte);

                let verified = VerifiedBundle::new(&token, &proof);
                let result = exec.execute(&verified);

                if expect_replay {
                    prop_assert!(
                        matches!(result, Err(MprdError::NonceReplay { .. })),
                        "expected NonceReplay"
                    );
                    continue;
                }

                let ok = result.expect("not replay");
                prop_assert_eq!(ok.success, expected_success);

                if ok.success {
                    used_success.insert(nonce_byte);
                    first_success_at.entry(nonce_byte).or_insert(idx);
                }
            }

            // After the first success for a nonce, later attempts must not reach inner.
            for (nonce, first_idx) in first_success_at {
                let total_calls = inner.calls_for(nonce);
                // Inner can be called multiple times *before* the first success, and exactly once on success.
                // It must never be called after the first success.
                prop_assert!(total_calls >= 1);

                let attempts_after_success = steps
                    .iter()
                    .enumerate()
                    .filter(|(i, (b, _))| *i > first_idx && *b == nonce)
                    .count();
                if attempts_after_success > 0 {
                    // If there were attempts after success, they should have been replay-blocked;
                    // the inner call count should not increase because of them.
                    // The minimal guarantee we can assert without peeking into pre-success failures:
                    // inner calls are <= number of attempts up to and including the first success for that nonce.
                    let attempts_through_success = steps
                        .iter()
                        .enumerate()
                        .filter(|(i, (b, _))| *i <= first_idx && *b == nonce)
                        .count();
                    prop_assert!(total_calls as usize <= attempts_through_success);
                }
            }
        }

        /// Property: nonces are partitioned by policy_hash.
        /// Claiming (policy_a, nonce_x) does NOT prevent claiming (policy_b, nonce_x).
        #[test]
        fn nonces_are_partitioned_by_policy(
            nonce_byte in any::<u8>(),
            policy_a_byte in any::<u8>(),
            policy_b_byte in any::<u8>(),
        ) {
            prop_assume!(policy_a_byte != policy_b_byte);

            let tracker = InMemoryNonceTracker::new();
            let now = InMemoryNonceTracker::current_time_ms().expect("clock");

            let mut token_a = dummy_token(nonce_byte, now);
            token_a.policy_hash = Hash32([policy_a_byte; 32]);

            let mut token_b = dummy_token(nonce_byte, now);
            token_b.policy_hash = Hash32([policy_b_byte; 32]);

            // First: validate and mark token_a
            prop_assert!(tracker.validate(&token_a).is_ok());
            prop_assert!(tracker.mark_used(&token_a).is_ok());

            // Second: token_b with SAME nonce but DIFFERENT policy should still work
            prop_assert!(tracker.validate(&token_b).is_ok());
            prop_assert!(tracker.mark_used(&token_b).is_ok());

            // Third: token_a replay should fail
            prop_assert!(tracker.validate(&token_a).is_err());
        }

        /// Property: mark_used is idempotent - second mark fails with NonceReplay.
        #[test]
        fn mark_used_is_idempotent(nonce_byte in any::<u8>()) {
            let tracker = InMemoryNonceTracker::new();
            let now = InMemoryNonceTracker::current_time_ms().expect("clock");
            let token = dummy_token(nonce_byte, now);

            // First mark succeeds
            prop_assert!(tracker.mark_used(&token).is_ok());

            // Second mark fails with NonceReplay
            let result = tracker.mark_used(&token);
            let is_replay = matches!(result, Err(MprdError::NonceReplay { .. }));
            prop_assert!(is_replay, "second mark_used should fail with NonceReplay");
        }

        /// Stateful test: InMemoryNonceTracker matches a simple reference model.
        /// Generates random operation sequences and verifies SUT == Model after each op.
        #[test]
        fn nonce_tracker_stateful_model_test(
            ops in proptest::collection::vec(
                (any::<u8>(), any::<u8>(), prop::bool::ANY),
                10..50
            )
        ) {
            // Reference model: simple HashSet of used (policy, nonce) pairs
            #[derive(Default)]
            struct NonceTrackerModel {
                used: HashSet<(Hash32, Hash32)>,
            }

            impl NonceTrackerModel {
                fn mark_used(&mut self, policy: &Hash32, nonce: &Hash32) -> bool {
                    // Returns true if insert succeeded (was not present)
                    self.used.insert((policy.clone(), nonce.clone()))
                }

                fn is_used(&self, policy: &Hash32, nonce: &Hash32) -> bool {
                    self.used.contains(&(policy.clone(), nonce.clone()))
                }
            }

            let tracker = InMemoryNonceTracker::new();
            let mut model = NonceTrackerModel::default();
            let now = InMemoryNonceTracker::current_time_ms().expect("clock");

            for (policy_byte, nonce_byte, do_mark) in ops {
                let policy_hash = Hash32([policy_byte; 32]);
                let nonce_hash = Hash32([nonce_byte; 32]);

                let mut token = dummy_token(nonce_byte, now);
                token.policy_hash = policy_hash.clone();

                // INVARIANT 1: validate() should succeed iff model says nonce is not used
                let model_says_unused = !model.is_used(&policy_hash, &nonce_hash);
                let sut_validate_result = tracker.validate(&token);

                if model_says_unused {
                    prop_assert!(
                        sut_validate_result.is_ok(),
                        "Model says unused, SUT should accept. policy={}, nonce={}",
                        policy_byte, nonce_byte
                    );
                } else {
                    prop_assert!(
                        sut_validate_result.is_err(),
                        "Model says used, SUT should reject. policy={}, nonce={}",
                        policy_byte, nonce_byte
                    );
                }

                // Optionally mark the nonce as used
                if do_mark && model_says_unused {
                    // INVARIANT 2: mark_used() should succeed iff model says nonce is unused
                    let sut_mark_result = tracker.mark_used(&token);
                    let model_mark_result = model.mark_used(&policy_hash, &nonce_hash);

                    prop_assert!(
                        sut_mark_result.is_ok(),
                        "Model allows mark, SUT should succeed. policy={}, nonce={}",
                        policy_byte, nonce_byte
                    );
                    prop_assert!(
                        model_mark_result,
                        "Model should have inserted new entry. policy={}, nonce={}",
                        policy_byte, nonce_byte
                    );

                    // INVARIANT 3: After mark_used, validate must fail
                    let verify_reject = tracker.validate(&token);
                    prop_assert!(
                        verify_reject.is_err(),
                        "After mark_used, validate must reject. policy={}, nonce={}",
                        policy_byte, nonce_byte
                    );
                }
            }

            // FINAL INVARIANT: Model and SUT should have same "used" state
            // (We can't directly compare internals, but we can verify via validate calls)
            for (policy_hash, nonce_hash) in &model.used {
                let mut token = dummy_token(nonce_hash.0[0], now);
                token.policy_hash = policy_hash.clone();
                token.nonce_or_tx_hash = nonce_hash.clone();

                prop_assert!(
                    tracker.validate(&token).is_err(),
                    "All model-used nonces should be rejected by SUT"
                );
            }
        }

        /// Stateful test: FileNonceStore matches a reference model.
        /// Generates random store/exists operations and verifies SUT == Model.
        #[test]
        fn file_nonce_store_stateful_model_test(
            ops in proptest::collection::vec(
                (any::<u8>(), any::<u8>(), prop::bool::ANY),
                5..30
            )
        ) {
            // Reference model: HashSet of stored (policy, nonce) pairs
            #[derive(Default)]
            struct FileNonceModel {
                stored: HashSet<(Hash32, Hash32)>,
            }

            impl FileNonceModel {
                fn store(&mut self, policy: &Hash32, nonce: &Hash32) -> bool {
                    // Returns true if insert succeeded (was not present)
                    self.stored.insert((policy.clone(), nonce.clone()))
                }

                fn exists(&self, policy: &Hash32, nonce: &Hash32) -> bool {
                    self.stored.contains(&(policy.clone(), nonce.clone()))
                }
            }

            let dir = new_temp_dir("file_nonce_stateful");
            let store = FileNonceStore::new(&dir).expect("store");
            let mut model = FileNonceModel::default();
            let timestamp = 12345i64;

            for (policy_byte, nonce_byte, do_store) in ops {
                let policy_hash = Hash32([policy_byte; 32]);
                let nonce_hash = Hash32([nonce_byte; 32]);

                // INVARIANT 1: exists() should match model
                let model_exists = model.exists(&policy_hash, &nonce_hash);
                let sut_exists = store.exists(&policy_hash, &nonce_hash).expect("exists");

                prop_assert_eq!(
                    sut_exists, model_exists,
                    "exists() mismatch. policy={}, nonce={}",
                    policy_byte, nonce_byte
                );

                if do_store && !model_exists {
                    // INVARIANT 2: store() should succeed iff model says not stored
                    let sut_store_result = store.store(&policy_hash, &nonce_hash, timestamp);
                    let model_store_result = model.store(&policy_hash, &nonce_hash);

                    prop_assert!(
                        sut_store_result.is_ok(),
                        "store() should succeed for new entry. policy={}, nonce={}",
                        policy_byte, nonce_byte
                    );
                    prop_assert!(model_store_result, "model should accept new entry");

                    // INVARIANT 3: After store, exists must return true
                    let verify_exists = store.exists(&policy_hash, &nonce_hash).expect("exists");
                    prop_assert!(
                        verify_exists,
                        "After store, exists must return true. policy={}, nonce={}",
                        policy_byte, nonce_byte
                    );

                    // INVARIANT 4: Double store should fail
                    let double_store = store.store(&policy_hash, &nonce_hash, timestamp);
                    let is_replay = matches!(double_store, Err(MprdError::NonceReplay { .. }));
                    prop_assert!(is_replay, "Double store should fail with NonceReplay");
                }
            }

            // Cleanup
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
