# Deployment (Docker / Kubernetes)

This folder contains deployment scaffolding for running `mprd serve` in:

- Docker (`Dockerfile`)
- Docker Compose (`docker-compose.yml`)
- Kubernetes (raw manifests + Helm chart skeleton)

## Docker Compose

### Demo (insecure)

Runs the operator API/UI without trust anchors or registry binding.

```bash
docker compose --profile demo up --build
```

Then open `http://localhost:8080`.

### Production wiring (registry-bound)

1) Provide a signed registry checkpoint + policy artifacts:

```bash
mkdir -p deploy/run/artifacts
cp /path/to/registry_state.json deploy/run/registry_state.json
cp /path/to/policy_artifacts/* deploy/run/artifacts/
```

2) Export required secrets (32-byte hex, 64 chars):

```bash
export MPRD_REGISTRY_KEY_HEX=...
export MPRD_TOKEN_SIGNING_KEY_HEX=...
```

3) Run:

```bash
docker compose --profile prod up --build
```

### Data persistence

The Compose setup uses a named volume mounted at `/data` inside the container.
Key directories used by `mprd serve`:

- `/data/operator` (operator store) via `MPRD_OPERATOR_STORE_DIR`
- `/data/policies` (policy storage) via `--policy-dir`
- `/data/anti_replay` (durable nonce store) via `MPRD_CONFIG` (`anti_replay.nonce_store_dir`)
- `/data/artifacts` (policy artifacts) via `--artifacts-dir`

### Executor configuration

`mprd serve` uses `execution.executor_type` from `MPRD_CONFIG`:

- `noop`: logs-only (no side effects)
- `file`: append-only JSONL audit sink (`execution.audit_file`)
- `http`: calls a remote executor (`execution.http_url`, optional `MPRD_EXECUTOR_API_KEY`)

## Risc0 build mode

By default, the Dockerfile builds with placeholder Risc0 methods (`RISC0_SKIP_BUILD=1`) to keep
iteration fast and avoid extra toolchain installation.

To embed real Risc0 methods (slower, requires network + toolchain install), build with:

```bash
docker build --build-arg RISC0_BUILD=1 -t mprd:prod .
```

See `methods/README.md` for prerequisites and fail-closed behavior (`RISC0_FORCE_BUILD=1`).

## Kubernetes

### Raw manifests

Manifests live in `deploy/k8s/`:

- `namespace.yaml`
- `pvc.yaml`
- `configmap.yaml`
- `secret.yaml` (fill in keys)
- `deployment.yaml`
- `service.yaml`

Apply:

```bash
kubectl apply -f deploy/k8s/
```

### Helm (skeleton)

The chart is in `deploy/helm/mprd/`.

```bash
helm install mprd deploy/helm/mprd
```

For production, provide your own `values.yaml` with:

- image repo/tag
- registry checkpoint path (ConfigMap) and keys (Secret)
- PVC size/class

## AWS / RunPod / “anywhere Docker runs”

This is a standard OCI container:

- Run locally with Docker/Compose.
- Push to a registry and deploy on AWS ECS/EKS, GKE, AKS, or RunPod.
- For Kubernetes clusters, use `deploy/k8s/` or the Helm chart.
