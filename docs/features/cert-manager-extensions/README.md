# cert-manager-extensions — Documentation Bundle

Chart that provisions the private PKI trust hierarchy for a single cluster environment: root CA, cluster intermediate CA, consumer-facing ClusterIssuers, Kyverno audit policies, and trust-manager Bundles for CA distribution.

## Documents

| Document | Audience | Purpose |
|----------|----------|---------|
| [Operator Manual](./operator-manual.md) | Platform / Security Squad | Architecture, resources deployed, deployment, verification, PKI lifecycle, troubleshooting, values reference |
| [User Guide](./user-guide.md) | Service teams | Namespace intermediate CA setup, leaf certificate issuance, mTLS configuration |

## Feature sub-bundles

| Feature | Bundle | Status |
|---------|--------|--------|
| GKE TrustConfig Sync | [docs/features/gke-trust-config-sync/](../gke-trust-config-sync/README.md) | QAC enabled |

## Related Records

| Document | Purpose |
|----------|---------|
| [DEC-001 — Automated GKE TrustConfig Synchronisation via Argo Events](../../architecture/ADRs/DEC-001-gke-trust-config-sync-pipeline.md) | Architecture decision record for the pki-trust-sync sub-feature |
| [SBDR-001 — pki-trust-sync IAM and RBAC Credential Scope](../../security/SBDR/SBDR-001-pki-trust-sync-iam-and-rbac-scope.md) | Security boundary decision record for the pki-trust-sync sub-feature |
