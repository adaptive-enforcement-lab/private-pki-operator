# private-pki-operator

Kubernetes operator that automates zero-downtime root CA rotation for a
cert-manager + trust-manager private PKI hierarchy. Implements a dual-trust
window state machine — the old root stays trusted until every intermediate CA
has been re-issued against the new one — so a root CA rotation never breaks
chain verification the way an unmanaged one can.

Go source: `ci/private-pki-operator` (own [README](ci/private-pki-operator/README.md)).
Helm chart: `charts/private-pki-operator`.

Deployment values (image tag, `pkirotation.enabled`, `pkirotation.rootCA`,
etc.) live in the consuming cluster's own repo, not here — e.g. homelab's
`k8s/private-pki-operator/values.yaml`. This repo does not provision the PKI
hierarchy itself (the root/intermediate CA `Certificate`/`ClusterIssuer`
resources) — it only manages rotation on top of whatever already provisioned
them.

## Repository Structure

```
.
├── charts/private-pki-operator/   # Helm chart
│   ├── Chart.yaml
│   ├── values.yaml
│   ├── values.schema.json
│   └── templates/
│       ├── crds/pkirotations.yaml
│       ├── shared/serviceaccount.yaml
│       └── features/k8s/
├── ci/private-pki-operator/       # Go source, Dockerfile, Makefile
├── docs/                          # ADRs, design plans, operator manual/user guide
├── hack/
│   ├── pki-status/                # Nushell CLI: point-in-time PKI inventory report
│   └── pki-gap-test/               # unmanaged 4-tier test stack, no operator/ArgoCD —
│                                    # demonstrates exactly where cert-manager stops and
│                                    # the rotation gap this operator closes begins
└── .github/workflows/
    ├── build.yml                  # go build/vet/test + helm lint
    └── trufflehog.yaml            # secret scanning
```

## Prerequisites

- cert-manager ≥ v1.14 and trust-manager, with a root/intermediate CA
  `Certificate`/`ClusterIssuer` hierarchy already provisioned (by hand or
  otherwise) — see `docs/architecture/ADRs/DEC-002-private-pki-operator.md`
  for the expected shape.

## Development

```bash
cd ci/private-pki-operator
make test              # go test (envtest) + go vet
make lint              # golangci-lint
helm lint ../../charts/private-pki-operator
helm unittest -f "tests/**/*_test.yaml" ../../charts/private-pki-operator
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for commit conventions and PR guidelines.

## Maintainers

| Name | Contact |
|---|---|
| Mark Cheret | mark@cheret.de |
