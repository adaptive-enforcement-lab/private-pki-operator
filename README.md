# private-pki-operator

Private PKI trust hierarchy for a single cluster, plus the operator that keeps
it rotating safely. Two components:

- **`charts/cert-manager-extensions`** — provisions the three-tier CA chain
  itself (root → cluster intermediate → namespace intermediates) using
  cert-manager, giving the cluster an isolated root CA, a cluster
  intermediate CA, and a consumer-facing issuer for namespace intermediates.
- **`ci/private-pki-operator`** (chart: `charts/private-pki-operator`) —
  the `PKIRotation` operator that automates zero-downtime root CA rotation:
  a dual-trust window state machine so the old root stays trusted until every
  intermediate CA has been re-issued against the new one. See its own
  [README](ci/private-pki-operator/README.md).

Deployment values (image tag, `labels.environment`, `pkirotation.enabled`, etc.)
live in the consuming cluster's own repo, not here — e.g. homelab's
`k8s/private-pki-operator/values.yaml` and `k8s/cert-manager-extensions/values.yaml`.

## Overview

```
private-root-ca-selfsigned (ClusterIssuer)
        │
        └─▶ private-root-ca (Certificate, isCA=true, 2yr)
                    │
                    └─▶ private-root-ca (ClusterIssuer)
                                │
                                └─▶ private-intermediate-ca (Certificate, isCA=true, 90d)
                                            │
                                            └─▶ private-intermediate-ca (ClusterIssuer)
                                                        │
                                                        └─▶ <namespace> intermediate CAs
                                                                    │
                                                                    └─▶ leaf certs (24h)
```

Five cert-manager resources are deployed per environment, plus five Kyverno `ClusterPolicy` resources (audit mode) when `pki.policies.enabled: true`:

| Resource | Kind | Purpose |
|---|---|---|
| `private-root-ca-selfsigned` | `ClusterIssuer` | Permanent self-signed issuer; issues and auto-renews the root CA only |
| `private-root-ca` | `Certificate` | Per-environment root CA (ECDSA P-256, 2yr) |
| `private-root-ca` | `ClusterIssuer` | Signs the cluster intermediate CA only |
| `private-intermediate-ca` | `Certificate` | Cluster intermediate CA (ECDSA P-256, 90d) |
| `private-intermediate-ca` | `ClusterIssuer` | Consumer-facing issuer for namespace intermediate CAs |
| `pki-restrict-platform-clusterissuers` | `ClusterPolicy` | Audit: consumer Certificates must not reference platform ClusterIssuers directly |
| `pki-intermediate-ca-issuer` | `ClusterPolicy` | Audit: namespace intermediate CAs must reference `ClusterIssuer/private-intermediate-ca` |
| `pki-intermediate-ca-max-validity` | `ClusterPolicy` | Audit: intermediate CA validity must not exceed 2160h (90 days) |
| `pki-cert-sign-usage-requires-isca` | `ClusterPolicy` | Audit: `cert sign` key usage requires `isCA: true` |
| `pki-no-selfsigned-leaf-certs` | `ClusterPolicy` | Audit: leaf Certificates must not reference a self-signed namespace Issuer |

## Repository Structure

```
.
├── charts/
│   └── cert-manager-extensions/   # Helm chart
│       ├── Chart.yaml
│       ├── values.yaml
│       ├── values.schema.json
│       └── templates/
│           ├── shared/
│           │   └── _helpers.tpl
│           └── features/
│               ├── root-ca/
│               │   ├── cluster-issuer-private-root-ca-selfsigned.yaml
│               │   ├── certificate-root-ca.yaml
│               │   └── cluster-issuer-root-ca.yaml
│               ├── intermediate-ca/
│               │   ├── certificate-intermediate-ca.yaml
│               │   ├── cluster-issuer-intermediate-ca.yaml
│               │   ├── cluster-policy-restrict-platform-clusterissuers.yaml
│               │   ├── cluster-policy-intermediate-ca-issuer.yaml
│               │   └── cluster-policy-intermediate-ca-max-validity.yaml
│               └── leaf-certs/
│                   ├── cluster-policy-cert-sign-usage-requires-isca.yaml
│                   └── cluster-policy-no-selfsigned-leaf-certs.yaml
└── .github/
    └── workflows/
        ├── build.yml              # go build/vet/test + helm lint
        └── trufflehog.yaml        # secret scanning
```

## Prerequisites

- cert-manager ≥ v1.14 installed in the `cert-manager` namespace
- Kyverno ≥ v1.9 installed (required for `pki.policies.enabled: true`; set to `false` to skip)

## Chart Configuration

The only required value is `labels.environment`. CommonNames and secret names are
derived automatically. All other values have production-ready defaults.

```yaml
labels:
  environment: homelab   # REQUIRED — drives commonName generation

# Defaults (override only if needed)
pki:
  rootCA:
    validity: "17520h"     # 2 years
    renewBefore: "720h"    # 30 days
  intermediateCA:
    validity: "2160h"      # 90 days
    renewBefore: "168h"    # 7 days
  policies:
    enabled: true          # set false if Kyverno is not installed
```

Before installing into a cluster that already has a PKI hierarchy running
(e.g. one built by hand before this chart existed): check
`kubectl get clusterissuer,certificate -n cert-manager` against this chart's
`templates/features/` first — `helm install` will otherwise try to create
those same resources fresh and either fail with "already exists" or, worse,
silently take ownership and diverge.

## Development

```bash
# Lint the chart
helm lint charts/cert-manager-extensions

# Render templates (pass your own values file, or none for chart defaults)
helm template cert-manager-extensions charts/cert-manager-extensions \
  --set labels.environment=homelab
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for commit conventions and PR guidelines.

## Maintainers

| Name | Contact |
|---|---|
| Mark Cheret | mark@cheret.de |
