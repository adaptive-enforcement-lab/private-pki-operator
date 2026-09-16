---
date: 2026-03-01
status: Accepted
category: Architecture
version: 1.0.0
decision_driver:
  name: Mark Cheret
  email: mark@cheret.de
  title: Staff Security Engineer
---

# DEC-002: private-pki-operator — Kubernetes Operator for Automated Safe Root CA Rotation

## Decision

Implement `private-pki-operator`, a kubebuilder-based Kubernetes operator written in Go, to manage the complete lifecycle of safe root CA rotation for cert-manager + trust-manager PKI hierarchies. The operator introduces a `PKIRotation` CRD that drives a durable, event-driven state machine, eliminating the gap between root CA renewal and intermediate CA re-issuance that currently exists in the Argo Workflows approach.

The operator is designed to be general-purpose and suitable for open-source release.

## Context

A root CA rotation in QAC on 2026-02-20 produced an AKID/SKID mismatch between the trust bundle (distributed by trust-manager) and the intermediate CA (signed by the pre-rotation root key). Any workload performing full chain verification against the namespace trust bundle failed. See [01-problem-statement/README.md](../01-problem-statement/README.md) for the complete root cause analysis.

The incident exposed two structural problems:

**Problem 1: The Bundle sources directly from the cert-manager Secret.**

`Bundle/private-root-ca` is configured with `spec.sources[0].secret.name: private-root-ca`. trust-manager watches this Secret and propagates any change atomically — the old root disappears from the trust bundle at the same instant the new root appears. There is no window during which both are trusted simultaneously. Any workload holding a certificate signed by the old root will fail chain verification immediately after the rotation, before re-issuance can occur.

**Problem 2: No state machine exists to drive the dual-trust window.**

The vendor-required safe rotation procedure (SgtCoDFish/rotate-roots, KubeCon EU 2023) has five ordered steps. Steps 2 through 4 — adding the new root to the bundle, waiting for propagation, re-issuing the intermediate — constitute a stateful sequence that must survive interruption and complete correctly regardless of how cert-manager and trust-manager schedule their own reconciliation. Nothing in the current infrastructure manages this sequence.

### Why Argo Workflows cannot close the gap

The existing GKE TrustConfig sync pipeline (DEC-001) uses Argo Events watching `ConfigMap/private-root-ca` UPDATE events. This fires after trust-manager has already distributed the new root and discarded the old one. Any Argo-based rotation handler built on this event has an irreducible gap. Closing the gap requires acting before the root CA Secret is updated, which requires watching `CertificateRequest` creation events in the `cert-manager` namespace — an event type Argo Events cannot access without cross-namespace RBAC that violates the least-privilege model.

Additionally, Argo Workflow state is not durable across Argo controller restarts. A rotation interrupted mid-flight requires manual intervention to resume.

### The correct trigger point

cert-manager's renewal cycle for a CA certificate proceeds as follows:

```
1. Certificate/private-root-ca reaches renewalTime
2. CertificateRequest/private-root-ca-{N+1} CREATED     ← operator acts here
3. CertificateRequest approved
4. CertificateRequest signed
5. Secret/private-root-ca updated with new cert + key
6. trust-manager detects Secret change → updates all ConfigMaps
```

An operator watching step 2 can read the current cert from the Secret (still the old cert at that moment), write it to a staging ConfigMap, and extend the Bundle to source from both the staging ConfigMap and the cert-manager Secret. By the time step 6 completes, the trust bundle already contains both the old and new root. Zero gap. Provably.

## The PKIRotation CRD

`PKIRotation` is a cluster-scoped custom resource that describes a PKI rotation operation and holds its state.

```yaml
apiVersion: platform.adaptive-enforcement-lab.com/v1alpha1
kind: PKIRotation
metadata:
  name: private-root-ca
spec:
  # The cert-manager Certificate object representing the root CA
  rootCertificate:
    name: private-root-ca
    namespace: cert-manager
  # The trust-manager Bundle to manage during rotation
  bundle:
    name: private-root-ca
  # The staging ConfigMap the operator writes to (must pre-exist in trust namespace)
  stagingConfigMap:
    name: private-root-ca-trust-anchor
    namespace: cert-manager   # trust-manager trust namespace
status:
  phase: Idle  # Idle | PreservingOldRoot | DualTrustActive | AwaitingReissuance | VerifyingChain | Complete
  currentRootSKID: "7D:A2:DE:D1:..."
  previousRootSKID: ""
  rotationStartedAt: null
  lastTransitionTime: "2026-03-01T00:00:00Z"
  conditions:
    - type: DualTrustActive
      status: "False"
    - type: IntermediateReissued
      status: "False"
    - type: ChainVerified
      status: "False"
```

### State machine

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│  Idle ──[CertificateRequest created for root CA]──► PreservingOldRoot          │
│                                                           │                    │
│                                              old root PEM written to           │
│                                              staging ConfigMap                 │
│                                              Bundle patched to dual-source     │
│                                                           │                    │
│                                                           ▼                    │
│                                                    DualTrustActive             │
│                                                           │                    │
│                                              trust-manager distributes         │
│                                              both old + new root               │
│                                                           │                    │
│                                       [Certificate/private-root-ca renewed]    │
│                                                           │                    │
│                                                           ▼                    │
│                                                  AwaitingReissuance            │
│                                                           │                    │
│                                              operator annotates intermediate   │
│                                              Certificate to trigger renew      │
│                                                           │                    │
│                                    [Certificate/private-intermediate-ca        │
│                                     renewed, AKID == new root SKID]            │
│                                                           │                    │
│                                                           ▼                    │
│                                                   VerifyingChain               │
│                                                           │                    │
│                                              AKID/SKID chain walk verified     │
│                                              for full hierarchy                │
│                                                           │                    │
│                                                           ▼                    │
│                                                        Complete                │
│                                                           │                    │
│                                              old root removed from staging     │
│                                              Bundle reverts to single-source   │
│                                              status.phase reset to Idle        │
│                                                           │                    │
│  Idle ◄───────────────────────────────────────────────────┘                    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

Every transition is triggered by a Kubernetes watch event. No polling. No sleep steps. Each step is idempotent: re-entering a state from a restart produces the same outcome.

## Alternatives Considered

### 1. Argo Workflow triggered by CertificateRequest watch (Argo Events)

**Approach**: Configure an Argo Events EventSource to watch `CertificateRequest` resources in the `cert-manager` namespace. Trigger a workflow to implement the five-step rotation procedure.

**Pros**: Uses existing Argo infrastructure. Lower initial implementation effort.

**Cons**: Watching `cert-manager` namespace resources requires cross-namespace RBAC that the current model does not grant to the `security` namespace. Workflow state is not durable across Argo controller restarts. Workflow-level state machines require polling steps (`wait-for-secret-update`, `wait-for-intermediate-reissue`) that introduce timing assumptions. The complexity of a reliable multi-step workflow with durability guarantees converges on re-implementing operator patterns in YAML.

**Rejection reason**: Requires the same RBAC as the operator with less durability and worse debuggability. The operator is the correct abstraction for this class of problem.

### 2. CronWorkflow pre-rotation approach (Argo Workflows)

**Approach**: A scheduled CronWorkflow runs N days before root CA expiry, sets up the dual-trust window proactively, triggers renewal, and waits for the cascade.

**Pros**: Avoids watching `CertificateRequest` events. Can be implemented with existing RBAC (ConfigMap writes in the trust namespace + Certificate annotation in `cert-manager` namespace).

**Cons**: Relies on the CronWorkflow running before cert-manager's own auto-renewal fires. If the CronWorkflow fires late or is missed, the renewal proceeds without the pre-rotation hook and the gap re-appears. The state machine (has the dual-trust window been set up? has the intermediate been re-issued?) must be encoded in ConfigMap annotations or Workflow parameters rather than a first-class status subresource. Recovery from interrupted rotations requires manual debugging of Workflow object state.

**Rejection reason**: The timing dependency makes correctness probabilistic rather than guaranteed. The operator's `CertificateRequest` watch provides a deterministic hook.

### 3. Manual runbook with pki-status verification

**Approach**: Document the five-step vendor procedure as a runbook. Operators execute it when rotation is required. `pki-status` checks are added as a post-rotation verification step.

**Pros**: No new infrastructure. Simplest possible change.

**Cons**: Root CA rotates every two years; intermediate CA rotates every 90 days. Manual steps at 90-day cadence accumulate operational toil and create a gap whenever a rotation is missed or delayed. In a production incident, a manual rotation runbook executed under pressure is a source of errors — exactly the scenario that produced this incident.

**Rejection reason**: Incompatible with zero-touch CA rotation. The `pki-status` AKID/SKID check is adopted regardless as a detection canary (independent of this decision).

### 4. Fork or extend trust-manager

**Approach**: Contribute a rotation state machine to trust-manager itself. Bundle would gain a `rotation` field with dual-trust window semantics.

**Pros**: Addresses the problem at the correct layer. No separate operator needed.

**Cons**: trust-manager is a focused distribution tool; a rotation state machine is outside its stated scope. Upstreaming this feature would require community consensus and an extended design period. The cluster needs a solution now.

**Rejection reason**: Timeline mismatch. Pursue as a potential upstream contribution after the operator is validated.

## Rationale

A Kubernetes operator with a `PKIRotation` CRD is the correct architectural fit for this problem because:

1. **The trigger is a Kubernetes event.** `CertificateRequest` creation is a standard Kubernetes event that an operator controller watches natively. Hooking into it before the Secret is updated is only possible with a controller registered against the cert-manager scheme.

2. **State durability is required.** A rotation takes minutes to complete. It must survive operator pod restarts, node preemptions, and temporary API server unavailability. CRD status subresources provide exactly this guarantee.

3. **The problem generalises.** cert-manager + trust-manager is the dominant Kubernetes-native PKI stack. The absence of a safe rotation operator is a gap the community will need to fill. Building `private-pki-operator` as a general-purpose tool from the start positions it for open-source release.

4. **Idempotent reconciliation eliminates recovery toil.** Each state transition is designed so that re-running it from any point produces the same result. There is no "partially rotated" state that requires manual cleanup.

## Consequences

**Positive:**

- Root CA rotation becomes fully automated and zero-touch. `rotationPolicy: Always` can be enabled on the root CA Certificate safely.
- The Bundle misconfiguration (sourcing directly from cert-manager Secret) is corrected structurally. The staging ConfigMap pattern is the correct architecture.
- The operator is auditable: every state transition is recorded in `PKIRotation.status` and emitted as Kubernetes events.
- The AKID/SKID verification step in the operator is also implemented in `pki-status` as an independent canary.

**Negative:**

- A new operator introduces a new component to maintain. It must be kept compatible with cert-manager and trust-manager version upgrades.
- The operator requires RBAC access to `CertificateRequest` resources in the `cert-manager` namespace (read-only watch). This is a new cross-namespace permission. It must be justified in an SBDR.
- The staging ConfigMap pattern requires a one-time migration: the Bundle must be updated to source from the staging ConfigMap rather than the cert-manager Secret directly. This migration must be coordinated so that the staging ConfigMap is populated before the Bundle source is changed.

## Implementation Location

`ci/private-pki-operator/` — kubebuilder project root

## Related Resources

- [01-problem-statement/README.md](../01-problem-statement/README.md) — Full root cause analysis and research
- Issue #37: private-intermediate-ca AKID mismatch
- Issue #38: adopt safe root rotation procedure
- [SgtCoDFish/rotate-roots](https://github.com/SgtCoDFish/rotate-roots) — Vendor rotation reference
- [DEC-001: Automated GKE TrustConfig Synchronisation](./DEC-001-gke-trust-config-sync-pipeline.md)
- cert-manager CA issuer docs: https://cert-manager.io/docs/configuration/ca/
- trust-manager Bundle API reference: https://cert-manager.io/docs/trust/trust-manager/api-reference/
