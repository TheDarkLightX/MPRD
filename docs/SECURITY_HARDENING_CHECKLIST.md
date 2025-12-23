# Security Hardening Checklist (CVE/Advisory-Driven)

This checklist is intended to be used as a **production security gate** for MPRD deployments. It is **advisory-driven**: every release should be checked against vulnerability databases and supply-chain policies, not just unit tests.

## 1) Vulnerability databases and scanning (CVE/RustSec/OSV)

- [x] **RustSec (`cargo-audit`) is enforced in CI** (fail build on vulnerabilities).
  - Run: `cargo audit`
  - Offline/local (no network): `cargo audit --no-fetch` (uses cached advisory DB).
  - Notes:
    - Warnings like “unmaintained” are not CVEs but are still risk signals; treat them as tickets with an explicit disposition.

- [ ] **OSV scan is enforced for crates + direct source** (GitHub Advisory DB / OSV aggregation).
  - Tool: `osv-scanner` (recommended for cross-ecosystem projects).
  - Inputs:
    - `Cargo.lock` (Rust deps)
    - SBOM (see below)

- [ ] **SBOM is generated for every release** and scanned.
  - Tools: `cargo sbom` (or CycloneDX), then scan with OSV/Trivy/Grype.
  - Store SBOM as a release artifact.

- [ ] **Base image / host OS scanning** for deployed containers/VMs.
  - Tools: Trivy/Grype (container), distro CVE feeds.

## 2) Dependency policy and supply chain

- [x] **Pin toolchains** (Rust + Risc0) and verify reproducible guest builds.
- [x] **Minimize dependency surface** (especially `proc-macro` heavy stacks).
  - Prefer `reqwest` with `rustls-tls` and `default-features = false` to avoid system TLS/OpenSSL where feasible.
- [ ] **Block unknown licenses** and deny risky crates.
  - Tooling suggestion: `cargo-deny` (licenses + advisories + bans).

- [ ] **Vendoring strategy** for long-lived deployments.
  - Prefer `cargo vendor` + locked checksums for air-gapped environments.

## 3) Secrets and key management

- [ ] **Never serialize master keys** (Mode C): ensure secrets are `#[serde(skip)]`.
  - Plan: `docs/MODE_C_KEY_MANAGEMENT.md`

- [ ] **Secret zeroization** for derived keys and buffers.
  - Verify `zeroize` is used where appropriate (derived AES key bytes are already zeroized).

- [ ] **Key rotation policy** documented and tested (accept overlap window, then revoke).

## 4) Input validation and DoS resistance

- [ ] **Bound every untrusted input** (bytes, counts, map sizes, recursion depth).
- [x] **Fail-closed deserialization** for untrusted receipts/artifacts.
  - Ensure deserialization is bounded (receipt deserialization is already bounded in `mprd-zk`).

- [ ] **Canonicalization is single-source-of-truth** and hash preimages are documented.

## 5) ZK statement integrity (host/guest/verifier)

- [x] **Journal schema is versioned and fail-closed** (unknown versions rejected).
- [x] **Exec kind/version and encoding IDs are allowlisted fail-closed**.
- [x] **Nonce / anti-replay is bound into the proof statement**.
- [x] **Limits are committed and enforced** (not “theater”).
- [x] **No host-trusted policy correctness in production** (`mpb_v1` guest recomputes selection/allowed).

## 6) External interactions (network + processes)

- [x] **SSRF-hardening** for any outbound HTTP execution or policy fetching.
  - Enforce scheme allowlist, forbid private/link-local IPs, **disable redirects**, timeouts, bounded retries.
  - Note: DNS-rebinding hardening via IP pinning / egress proxy is recommended for high-security deployments.

- [ ] **Command execution hardening** (Tau CLI or other binaries).
  - Pin binary provenance (hash/signature).
  - Run in a sandboxed environment (container/seccomp/AppArmor), least-privilege user.
  - Bound runtime and output sizes (timeouts + max stdout/stderr bytes).

## 7) Logging, observability, and incident response

- [ ] **Structured security logs** (why verification failed, which check).
- [ ] **Metrics** (proof generation time, verification time, denial reasons, nonce replay rate).
- [ ] **Audit trails** for executed actions (append-only logs).
- [ ] **Incident playbooks** (key compromise, registry compromise, Tau binary compromise).

## 8) Testing beyond unit tests

- [x] **Property-based tests** for “any-field tamper fails verification”.
- [ ] **Adversarial test matrix** for downgrade/substitution/routing attacks.
- [ ] **Fuzzing** for:
  - candidate/state canonical decoding
  - limits_bytes parser
  - receipt/journal decoding (host-side)
  - Status: `docs/FUZZING.md`
  - Status: ✅ fuzz targets present under `fuzz/`

## 9) Code quality gates (best practices)

- [x] **`cargo fmt` gate**: `cargo fmt --check`
- [x] **`cargo clippy` gate**: `RISC0_SKIP_BUILD=1 cargo clippy --workspace --all-targets -- -D warnings`
  - Optional: a separate job with the Risc0 guest target installed to lint guests.

- [ ] **Panic/unwrap policy**:
  - No `unwrap/expect` in production paths (tests are fine).
  - Guests may `panic!` on malformed witnesses, but denial behavior should be explicit where required.

## 10) Architecture (SOLID / complexity)

- [ ] **SRP**: split mega-modules (e.g., `modes_v2.rs`, `risc0_host.rs`) into focused submodules.
- [ ] **DIP**: keep verifier/attestor wired via traits, and keep I/O boundaries injectable.
- [ ] **Cyclomatic complexity**: refactor large `verify()` methods into pure, testable check functions.
