# private-pki-operator — Documentation Bundle

Kubernetes operator that automates zero-downtime root CA rotation for cert-manager + trust-manager PKI hierarchies using a dual-trust window state machine.

## Documents

| Document | Audience | Purpose |
|----------|----------|---------|
| [User Guide](./user-guide.md) | Application / Squad engineers | Which trust bundle to mount; workload behaviour during CA rotation |
| [Operator Manual](./operator-manual.md) | Platform / Security Squad | Architecture, state machine, resources deployed, deployment, verification, troubleshooting, implementation decisions |

## Related Records

| Document | Purpose |
|----------|---------|
| [DEC-002 — private-pki-operator](../../architecture/ADRs/DEC-002-private-pki-operator.md) | Architecture decision record: why an operator, alternatives rejected |
| [Standards Assessment](../../architecture/analysis/private-pki-operator-standards.md) | Evaluation against industry best practices and Kubernetes operator conventions |
| [Upstream Submission Analysis](../../architecture/analysis/private-pki-operator-upstream.md) | Feasibility of contributing to the cert-manager ecosystem; what would need to change |
| [01-problem-statement](../../architecture/01-problem-statement/README.md) | Root cause analysis of the 2026-02-20 incident that motivated this operator |
