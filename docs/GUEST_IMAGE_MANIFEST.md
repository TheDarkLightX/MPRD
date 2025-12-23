# Guest Image Manifest (Production)

Production verifiers should route zkVM receipts using a **signed guest image manifest** rather than a single hardcoded image ID.

## Data model

- Type: `mprd_zk::manifest::GuestImageManifestV1`
- Mapping: `(policy_exec_kind_id, policy_exec_version_id) -> image_id`
- Signature: ed25519 over canonical bytes (`MANIFEST_DOMAIN_V1`)

## Verifier usage

- External verifier: `mprd_zk::external_verifier::ExternalVerifier::with_verified_manifest(...)`
- Local verifier: `mprd_zk::create_production_verifier_from_manifest(...)`

## Creating a manifest

Create a manifest offline with a dedicated manifest signing key:

- Load key: `mprd_core::TokenSigningKey::from_hex(...)`
- Sign: `mprd_zk::manifest::GuestImageManifestV1::sign(...)`
- Distribute:
  - the manifest JSON (pinned artifact)
  - the manifest signer public key (pinned trust anchor)

The verifier must pin the signer public key out-of-band and reject manifests signed by other keys.

