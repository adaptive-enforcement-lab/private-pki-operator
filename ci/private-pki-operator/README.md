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
# Build, push, and deploy to QAC
make deploy-poc TAG=dev

# Enable PKIRotation CR
helm template private-pki-operator ../../charts/private-pki-operator \
  --set pkirotation.enabled=true | kubectl apply -f -

# Check status
make rotation-status

# Trigger a manual rotation (testing)
make trigger-rotation

# Tear down
make undeploy-poc
```

## Development

```bash
make manifests generate   # Regenerate CRDs/RBAC from markers
make lint-fix             # Auto-fix code style
make test                 # Run unit tests (internal/pki, internal/gcp)
```

See [AGENTS.md](./AGENTS.md) for the complete AI agent guide including CLI commands, project structure, and kubebuilder conventions.

## CI / SAST

The build pipeline runs on every push:

| Stage | What it does |
|-------|-------------|
| `test-operator` | `go vet`, `golangci-lint`, race-enabled tests with coverage (`./internal/pki/...`, `./internal/gcp/...`) |
| `sonarqube` | Downloads coverage artifact and runs SonarQube SAST scan |
| `build-operator-container` | Builds and pushes linux/amd64 image to GAR |

> The `./internal/controller/...` suite requires a live Kubernetes API (envtest) and is excluded from CI coverage collection.

## License

Copyright 2026. Licensed under the Apache License, Version 2.0.
