# private-pki-operator

Kubernetes operator that automates zero-downtime root CA rotation for cert-manager + trust-manager PKI hierarchies. Implements a dual-trust window state machine so the old root stays trusted until all intermediate CAs have been re-issued against the new root.

**State machine:** `Idle → PreservingOldRoot → DualTrustActive → AwaitingReissuance → VerifyingChain → Complete → Idle`

## Documentation

Full documentation lives in the platform docs:

| Document | Purpose |
|----------|---------|
| [Operator Manual](../../docs/features/private-pki-operator/operator-manual.md) | Architecture, state machine, deployment, verification, troubleshooting |
| [DEC-002](../../docs/architecture/ADRs/DEC-002-private-pki-operator.md) | Architecture decision record |
| [Standards Assessment](../../docs/architecture/analysis/private-pki-operator-standards.md) | Industry best practice evaluation |
| [Upstream Path](../../docs/architecture/analysis/private-pki-operator-upstream.md) | cert-manager ecosystem submission analysis |
| [AGENTS.md](./AGENTS.md) | AI agent guide for this project |

## Quick Start

```bash
# Build and push the image
make build-push TAG=dev CONTAINER_TOOL=docker

# Deploy via Helm template (values file supplies the image tag, pkirotation.enabled, etc.)
make deploy VALUES=<path-to-values.yaml>

# Check status
make rotation-status

# Trigger a manual rotation (testing)
make trigger-rotation

# Tear down
make undeploy VALUES=<path-to-values.yaml>
```

## Development

```bash
make manifests generate   # Regenerate CRDs/RBAC from markers
make lint-fix             # Auto-fix code style
make test                 # Run unit tests (all packages, incl. envtest)
```

See [AGENTS.md](./AGENTS.md) for the complete AI agent guide including CLI commands, project structure, and kubebuilder conventions.

## CI

`.github/workflows/build.yml` runs on every push: `go build`/`go vet`/`go test` for `cmd`, `api`, and `internal/pki`, plus `helm lint` on the chart. Release/publish is manual — see `Makefile`'s `build-push` target.

> The `internal/controller` suite requires a live Kubernetes API (envtest) and is excluded from CI.

## License

Copyright 2026. Licensed under the Apache License, Version 2.0.
