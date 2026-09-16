# PKI Root Rotation: Problem Statement

**Author:** Mark Cheret
**Date:** 2026-03-01
**Status:** Final
**Relates to:** [DEC-002: private-pki-operator](../ADRs/DEC-002-private-pki-operator.md), Issue #37, Issue #38

---

## Summary

This document records the incident that exposed a structural flaw in the cluster PKI architecture, the research conducted into cert-manager and trust-manager capabilities, and the reasoning that leads to the `private-pki-operator` as the correct long-term solution. It serves as the design input for DEC-002.

---

## 1. The Incident

On 2026-02-20, a root CA rotation in QAC produced an AKID/SKID mismatch that broke chain verification for all workloads relying on the namespace trust bundle. The incident was discovered on 2026-03-01 during PLAT-711 platform-identity TLS validation and recorded in issue #37.

### Timeline

```
11:32 UTC  Certificate/private-intermediate-ca issued (revision 2)
           AKID: 05:C6:4B:8E:21:68:95:40:50:45:3A:52:9B:39:44:E9:DF:CB:0A:9B

12:01 UTC  Certificate/private-root-ca re-issued (revision 4) with a NEW key pair
           New SKID: 7D:A2:DE:D1:8F:4E:52:AC:99:48:C0:2F:51:07:04:8C:CC:6C:AA:FF

           trust-manager detects Secret/private-root-ca change.
           ConfigMap/private-root-ca in all namespaces updated atomically to new root.
           Old root key (SKID 05:C6:4B:8E...) no longer present anywhere in the trust bundle.

           Certificate/private-intermediate-ca still at revision 2.
           Its AKID references 05:C6:4B:8E... — a key that no longer exists.
           Chain verification broken.
```

The intermediate was signed 29 minutes before the root CA was replaced. cert-manager does not cascade re-issuance; no existing mechanism detected or repaired the inconsistency.

### Observed impact

| Workload class | Impact |
|---|---|
| mTLS (full chain validation) | Certificate chain verification fails |
| Admission webhooks using private CA | New pod scheduling blocked |
| Ingress with client cert validation | All authenticated requests rejected |
| Server-only TLS (no chain check) | Unaffected operationally |

### Affected blast radius in QAC

Five downstream intermediate CAs (`chaos-mesh-ca`, `workflows-intermediate-ca`, `rabbitmq-intermediate-ca`, `security-intermediate-ca`, `groups-directory-intermediate-ca`) all correctly reference the private-intermediate-ca by SKID. The break is at exactly one point: `private-intermediate-ca` → root CA. Repairing the intermediate would restore the entire hierarchy.

---

## 2. Root Cause

### Proximate cause

The `private-root-ca` Secret was replaced in-place (with a new key pair) after the intermediate had already been issued against the prior root key. cert-manager does not cascade re-issuance when an issuer's backing Secret changes.

### Structural cause

`Bundle/private-root-ca` is configured to source directly from `Secret/private-root-ca` — the Secret that cert-manager owns and writes on every renewal:

```yaml
# Current bundle-root-ca.yaml — UNSAFE FOR ROTATION
spec:
  sources:
    - secret:
        name: "private-root-ca"
        key: "tls.crt"
```

The trust-manager documentation explicitly warns against this pattern:

> *"If you rotate your issuer such that it's issued from a new root certificate, trust-manager will see the Secret be updated and automatically update your trust bundle to include the new root — **immediately distrusting the old root.** That means that if any services were still using a certificate issued by the old root, they'll be distrusted and will break."*

> *"By consuming the CA directly from your Secret, it becomes impossible to do [dual-trust rotation]; `ca.crt` will only ever contain the best effort guess for the CA for the current certificate, and will never include an older or a new CA."*

When the root CA Secret is updated — whether by cert-manager auto-renewal, manual deletion, or operator action — trust-manager atomically replaces the ConfigMap in every namespace with the new cert only. There is no grace period. The old trust anchor disappears before any downstream consumer can react.

### Code evidence

`certificate-root-ca.yaml` contains the following comment, written at initial setup:

```yaml
# Never: root CA key is intentionally stable. Changing this to Always without
# trust-manager in place causes an up-to-83-day chain validation gap while the
# intermediate CA re-issues against the new root key.
# Revisit once trust-manager is onboarded (see task: trust-manager onboarding).
rotationPolicy: Never
```

trust-manager has since been onboarded. The `rotationPolicy: Never` constraint is no longer about safety against trust-manager; it is now a workaround for the absence of a rotation state machine. Without one, enabling `rotationPolicy: Always` on the root CA guarantees that every future auto-renewal reproduces the conditions of this incident.

---

## 3. Research: What cert-manager and trust-manager Actually Support

This section records findings from direct investigation of the tools' capabilities. Sources: official cert-manager.io documentation, trust-manager source code (`pkg/bundle/controller.go`, `pkg/bundle/internal/source/source.go`), GitHub repository trust-manager v0.21.1, cert-manager v1.19.

### 3.1 trust-manager Bundle source aggregation

A `Bundle` can have multiple entries in `spec.sources`. All source types (`secret`, `configMap`, `inLine`, `useDefaultCAs`) may appear multiple times. The bundle assembly is **concatenation**: all PEM blocks from all sources are merged into a single output. When any source changes, trust-manager re-reads all sources and rebuilds the full bundle atomically.

This is the foundational primitive for a dual-trust window: a Bundle with two `secret` (or `configMap`) sources will distribute both root PEMs simultaneously. A client loading the bundle trusts both.

### 3.2 trust-manager does not watch Certificate objects

trust-manager watches `Secret` resources in the trust namespace and `ConfigMap` resources. It has no awareness of `cert-manager.io/Certificate` objects or their issuance state. The reconciliation chain is:

```
cert-manager renews → updates Secret → trust-manager detects Secret change → rebuilds bundle
```

### 3.3 No native dual-trust window

There is no trust-manager feature that maintains both the old and new root during a rotation window. The multi-source capability provides the mechanism; a state machine external to trust-manager must drive it.

### 3.4 cert-manager has no cascade re-issuance

From the CA issuer documentation:

> *"There's **no automatic rotation** for the CA certificate in the Secret you configured."*

> *"**Updating the secret** used for the CA certificate **won't trigger re-issuance of leaf certificates.**"*

When a CA's backing Secret is updated, cert-manager does not re-issue any certificates that were issued by that CA. Each Certificate only renews according to its own `renewBefore` window.

### 3.5 cert-manager v1.18 changed the default rotationPolicy

cert-manager v1.18 (June 2025) changed the cluster-wide default for `Certificate.spec.privateKey.rotationPolicy` from `Never` to `Always`. This is a breaking change. Without a rotation state machine, any root CA configured with `rotationPolicy: Always` will produce an AKID mismatch on every auto-renewal.

### 3.6 No official CA rotation tutorial exists

The URL `https://cert-manager.io/docs/tutorials/rotate-root-ca/` returns 404. No tutorial for automated root CA rotation has been published by the cert-manager project. The documentation acknowledges this gap; the community's implicit position is that external orchestration is required.

### 3.7 CAInjectorMerging feature gate (cert-manager v1.17+, Beta in v1.19)

This feature merges CA certificates into webhook configurations (`ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration`, `CRD`, `APIService`) instead of replacing them. It is scoped to the ca-injector subsystem only and does not affect trust-manager Bundles or workload trust stores. It is not relevant to this problem.

---

## 4. Vendor Guidance

**Reference:** [github.com/SgtCoDFish/rotate-roots](https://github.com/SgtCoDFish/rotate-roots)
Companion repository to the KubeCon EU 2023 talk *Rotate Roots Right Round: Using cert-manager for Safer Private PKI* by SgtCoDFish (cert-manager core maintainer). Recorded in issue #38.

The vendor-recommended safe rotation procedure is a **five-step dual-trust window**:

| Step | Action | Why |
|---|---|---|
| 1 | Create new root Certificate object (separate Secret) | New root exists without touching the old one |
| 2 | Add new root to Bundle alongside old root | Both roots trusted simultaneously — no gap |
| 3 | Wait for bundle propagation to all namespaces | All consumers hold the new bundle before any issuance shifts |
| 4 | Re-issue intermediate from new root issuer | Intermediate AKID now matches new root SKID |
| 5 | Remove old root from Bundle | Old root gone only after all downstream certs are clean |

**The invariant:** the old root must remain in the trust bundle until every certificate that references it has been re-issued. Violating this invariant — by removing the old root before re-issuance completes — is precisely what produced this incident.

The repository demonstrates this as a manual procedure. It does not automate it. The tools (cert-manager + trust-manager) provide the primitives; a state machine external to both is required to drive the sequence correctly.

---

## 5. Why Argo Workflows Is Insufficient

An earlier, GCP-specific sync pipeline used Argo Events watching `ConfigMap/private-root-ca` UPDATE events to push trust material into GCP Certificate Manager. That mechanism has since been removed (this repo no longer targets GCP), but the underlying gap it exposed still applies generally: watching a ConfigMap for changes is insufficient for the rotation state machine.

### The timing problem

The Argo EventSource fires on `ConfigMap/private-root-ca` UPDATE. That event is emitted by trust-manager **after** it has already distributed the new root and discarded the old one. At the moment the EventSource fires, the dual-trust window is already closed. Any Argo-based approach that reacts to this event has an irreducible gap — a period during which the intermediate's AKID references a root no longer present in the trust bundle.

```
cert-manager renews root → Secret updated → trust-manager updates ConfigMap
                                                     ↑
                                          OLD ROOT ALREADY GONE
                                          EventSource fires here
```

### What would be needed to close the gap

Closing the gap requires acting **before** the root CA Secret is updated. The only event that fires before the Secret changes is `CertificateRequest` creation for the root CA. Argo Events cannot watch `CertificateRequest` resources with the current RBAC model (doing so would require cross-namespace access to `cert-manager` namespace resources). Even if it could, driving a multi-step state machine from an Argo Sensor involves polling, sleep steps, and workflow-level state that does not survive controller restarts.

### Summary

| Capability | Argo Workflows | Kubernetes Operator |
|---|---|---|
| Watch CertificateRequest creation (pre-Secret-update) | No | Yes |
| Zero-gap dual-trust window setup | No | Yes |
| State survives controller restart | No (Workflow object) | Yes (CRD status) |
| Idempotent reconciliation | Manual (shell guards) | Native (reconcile loop) |
| Kubernetes-native event model | Partial (polling) | Full |
| RBAC confined to single namespace | Yes | Configurable |

---

## 6. The Architectural Fix

Two changes are required — one to the Bundle configuration, one to add the state machine.

### 6.1 Bundle must not source directly from the cert-manager Secret

The Bundle must point at a separately curated staging resource, not the cert-manager-managed Secret. The staging resource is a ConfigMap that the operator writes to; it is never touched by cert-manager.

```
CURRENT (unsafe):
  Bundle sources: [Secret/private-root-ca]
  → any cert-manager renewal immediately drops the old root

CORRECT:
  Bundle sources: [ConfigMap/private-root-ca-trust-anchor]
  → the operator controls what is in the ConfigMap at all times
  → during rotation: ConfigMap holds both old and new PEM
  → after verification: ConfigMap holds only new PEM
```

### 6.2 A state machine must drive the rotation sequence

The state machine has six states:

```
Idle → PreservingOldRoot → DualTrustActive → AwaitingReissuance → VerifyingChain → Complete
                                                                                        ↓
                                                                                      Idle
```

Each transition is triggered by a Kubernetes event, not a timer. The state is durable — stored in a CRD status subresource and survives operator restarts. Every step is idempotent.

---

## 7. Why a Kubernetes Operator Is the Right Vehicle

A Kubernetes operator built with kubebuilder provides:

1. **Pre-rotation hook via CertificateRequest watch.** The operator watches `CertificateRequest` creation events for the root CA. This fires before the root CA Secret is updated, giving the operator the opportunity to capture the old root PEM and extend the trust bundle before the rotation completes. This is the only mechanism that provably eliminates the gap.

2. **Durable state via CRD status.** The `PKIRotation` CRD holds the full rotation state. An operator restart at any point during rotation converges back to the correct state on the next reconciliation without manual intervention.

3. **Event-driven correctness.** Each state transition is triggered by a Kubernetes watch event, not a sleep or poll. The operator reacts to `CertificateRequest` creation, `Secret` changes, and `Certificate` status updates without any timing assumptions.

4. **Open-source potential.** The problem — automated safe root CA rotation for cert-manager + trust-manager hierarchies — is not specific to this cluster. No open-source operator currently addresses it. `private-pki-operator` is designed to be general-purpose from the start.

---

## 8. Open Questions

These are inputs to the DEC-002 design process:

- **Discovery model:** Should the operator discover the PKI hierarchy dynamically via label selectors on Certificate objects, or should it be configured explicitly via the `PKIRotation` CRD spec?
- **Approver-policy integration:** Should the operator integrate with cert-manager's `approver-policy` to gate intermediate re-issuance during rotation? (Deferred per operator note, 2026-03-01.)
- **Cross-namespace scope:** The operator must read `cert-manager` namespace Secrets (to capture old root PEM before rotation) and write to the trust namespace. RBAC scope must be justified.
- **pki-status integration:** The AKID/SKID consistency check should be added to `hack/pki-status/main.nu` as a canary independent of the operator.

---

## Related Resources

- Issue: private-intermediate-ca needs re-signing against current root CA
- Issue: adopt safe root rotation procedure from cert-manager/rotate-roots
- [SgtCoDFish/rotate-roots](https://github.com/SgtCoDFish/rotate-roots) — KubeCon EU 2023 reference implementation
- [DEC-002: private-pki-operator](../ADRs/DEC-002-private-pki-operator.md)
- `ci/private-pki-operator/` — operator source
