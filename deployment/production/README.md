# MPRD Production Deployment Bundle

This directory is a deterministic registry-bound deployment bundle used by the
production-readiness gate. It is materialized by
`tools/release/materialize_deployment_bundle_fixture.sh` and verified by
`tools/release/check_deployment_bundle.sh`.

The bundle contains public deployment inputs only. Do not add private signing
keys, token signing key env files, operator request payloads, or private registry
seeds to this directory.

Verification:

```sh
tools/release/check_deployment_bundle.sh \
  --manifest deployment/production/deployment-bundle.json \
  --out-dir dist/deployment-bundle-gate
```
