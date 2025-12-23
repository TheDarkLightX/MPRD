# Mode C Key Management Plan (Production)

Mode C (Private) binds encrypted state metadata into the verified statement (via a committed encryption context hash carried in `limits_hash/limits_bytes`). This document defines the *operational* requirements for managing encryption keys safely in production.

## Key material and trust boundaries

- `EncryptionConfig.master_key` is the *only* secret key material used to derive per-message AEAD keys (HKDF); it must come from a secure source (KMS/HSM/Vault/secure file with OS-level protections).
- `EncryptionConfig.key_id` is **not** a secret; it is a rotation/audit identifier that is bound into the proof statement and surfaced to verifiers.
- The prover/executor operator necessarily sees plaintext (the zk proof does not provide confidentiality from the prover); Mode C’s goal is confidentiality from *external verifiers* and third-party observers, not from the operator.

## Storage and loading requirements

- Never serialize `master_key`. The code enforces this via `#[serde(skip)]`:
  - `crates/mprd-zk/src/privacy.rs` (`EncryptionConfig.master_key`)
  - `crates/mprd-zk/src/modes_v2.rs` (`PrivateAttestationConfig.master_key`)
- Load `master_key` at process start from one of:
  - KMS/HSM API (recommended)
  - Vault (recommended)
  - sealed file (fallback): root-owned, `0600`, on encrypted disk, with audited access
- `key_id` must be configured alongside `master_key` and must change on rotation.

## Rotation strategy

- Rotation is *id-based*: deploy a new `key_id` + `master_key`, then:
  - New attestations use the new `key_id`.
  - Verifiers accept both the old and new `key_id` during a defined overlap window (configured allowlist).
  - After the overlap window ends, remove the old `key_id` from the allowlist and revoke the old key material in KMS/HSM.
- Rotation cadence: choose per deployment (e.g., monthly) and on incident response.

## Verification and downgrade resistance

- Verifiers must enforce:
  - algorithm allowlist (currently `AES-256-GCM` only),
  - `key_id` allowlist (deployment-specific),
  - the committed encryption context hash matches `(state_hash, nonce_or_tx_hash, key_id, algorithm, encryption_nonce, ciphertext_hash)` (fail-closed).
- The above is implemented in `crates/mprd-zk/src/modes_v2.rs` (`RobustPrivateVerifier`) and in `crates/mprd-core/src/limits.rs` (canonical limits encoding + context hash).

## Audit logging

- Log (at minimum): `key_id`, encryption algorithm, and the committed context hash (not the `master_key`).
- Persist logs to an append-only store (centralized logging with retention + tamper-evident storage).

## Incident response (key compromise)

- Immediately remove compromised `key_id` from verifier allowlists.
- Rotate to a new `key_id` + `master_key`.
- Treat all ciphertext under the compromised key as potentially decryptable; re-encrypt if confidentiality must be preserved.

