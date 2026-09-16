---
date: 2026-03-02
author: Mark Cheret
subject: private-pki-operator
category: Post-Implementation Standards Assessment
---

# Industry Best Practice Assessment: private-pki-operator

This document evaluates the `private-pki-operator` implementation against established PKI engineering standards, Kubernetes operator best practices, and the cert-manager ecosystem's own conventions.

**Verdict:** The implementation is correct and production-quality for its intended scope. Every technical decision is aligned with industry practice. The remaining gaps are upstream publication requirements — they matter if the goal is to contribute to the cert-manager ecosystem, not if the goal is to operate a reliable private PKI.

**Operator manual:** [docs/features/private-pki-operator/operator-manual.md](../../features/private-pki-operator/operator-manual.md)
**Upstream path:** [docs/architecture/analysis/private-pki-operator-upstream.md](./private-pki-operator-upstream.md)

---

## What Is Correct and Standard

### Dual-trust window is the industry-standard rotation approach

The core protocol — maintain simultaneous trust in both the old and new root CA during the transition period — is the canonical approach to zero-downtime CA rotation. It is described in:

- RFC 5280 §4.2.1.1 — Authority Key Identifier and chain building guidance
- NIST SP 800-57 Part 1 — key transition recommendations
- The cert-manager community's own reference implementation: [SgtCoDFish/rotate-roots](https://github.com/SgtCoDFish/rotate-roots) (KubeCon EU 2023)

Every major PKI operator — Google's internal CA systems, Apple's certificate infrastructure, and Let's Encrypt's root CA transitions — uses the dual-trust window pattern. It is not a novel design choice; it is the correct one.

### SKID/AKID cryptographic chain verification

The operator verifies a completed rotation by walking the `AuthorityKeyIdentifier → SubjectKeyIdentifier` chain for each intermediate CA. This is the correct check.

Verifying by Subject/Issuer Common Name is trivially spoofable — anyone can issue a certificate with an identical CN. Verifying that the intermediate's AKID equals the root's SKID proves the intermediate was signed by the exact key pair held by the current root CA. This is the cryptographic guarantee that the chain is legitimate. The operator verifies this after every rotation.

### State machine pattern for multi-step reconciliation

Using a finite state machine (`phase` field on the CRD status) for a multi-step operation that cannot complete in a single reconciliation pass is the idiomatic controller-runtime pattern. The Kubebuilder documentation and the cert-manager operator's own internal design both use this approach for operations that span multiple controller cycles.

The key properties our state machine satisfies:

- **Idempotent transitions:** Entering any state from a restart produces the same outcome.
- **Durable state:** `status.phase` and `status.conditions` survive operator pod restarts, node preemptions, and API server blips.
- **Observable progress:** Every intermediate state is visible via `kubectl get pkirotation` and Kubernetes events.
- **No autonomous rollback:** A partial rotation in a known state is safer than automated rollback that could itself fail. The operator holds state and alerts; humans decide to intervene.

### Using `metav1.Condition` for status conditions

The three conditions — `DualTrustActive`, `IntermediateReissued`, `ChainVerified` — use the standard `metav1.Condition` type as defined in the Kubernetes API conventions. Each has a `type`, `status`, `reason`, `message`, and `lastTransitionTime`. This is the correct Kubernetes API pattern for expressing the progress of a multi-step operation, and it integrates correctly with kubectl, kstatus, and any tooling that follows the Kubernetes conditions API.

### Leveraging cert-manager and trust-manager rather than reimplementing

The operator orchestrates existing primitives — cert-manager for certificate lifecycle, trust-manager for trust bundle distribution — rather than reimplementing either. This is the correct architectural choice. cert-manager handles all cryptographic operations, certificate approval, and the actual signing. trust-manager handles distribution of trust anchors to all namespaces. The operator handles only the coordination between them during the rotation window.

---

## RBAC Layout: Arrived at Through Live Testing

The final RBAC layout was not scaffolded — it was arrived at through live testing. Two non-obvious issues were discovered and fixed during rotation verification:

**Issue 1 — Events for cluster-scoped CRDs go to the `default` namespace.** controller-runtime emits Events for cluster-scoped objects (like PKIRotation) into the `default` namespace, which is the Kubernetes convention for objects with no namespace. Putting `events create/patch` in the ClusterRole (the kubebuilder default pattern) would grant that permission in every namespace cluster-wide. The correct minimum is a Role scoped to `default` only. This was confirmed by inspecting actual Event objects after rotation: all PKIRotation Events land in `default`.

**Issue 2 — controller-runtime cache starts cluster-wide informers by default.** Even with namespace-scoped Roles granting `list`/`watch` on Secrets and Certificates only in `cert-manager`, the manager started cluster-wide informers on startup and immediately produced `forbidden: cannot list resource at the cluster scope` errors. The fix is `cache.Options{DefaultNamespaces: {"cert-manager": {}}}` in the manager, which restricts all namespace-scoped informers to the `cert-manager` namespace. Cluster-scoped types (PKIRotation, ClusterIssuer, Bundle) are unaffected — controller-runtime always watches those cluster-wide regardless of `DefaultNamespaces`.

The resulting layout is the minimum required:

| Object | Namespace | What it covers |
|--------|-----------|----------------|
| `ClusterRole` | cluster | `clusterissuers`, `pkirotations` ×3, `bundles` |
| `Role` | `cert-manager` | `secrets` (read-only), `configmaps`, `certificates`, `certificaterequests`, `certificates/status` (patch) |
| `Role` | `default` | `events` (create, patch) |

The operator has no write access to Secrets. Reissuance is triggered via `certificates/status: patch` (setting `Issuing: True`), which is scoped to the exact Certificate subresource being acted on.

---

## Gaps Relative to Upstream Publication

These items are not implementation deficiencies. They are the delta between "correct, production-quality internal tool" and "general-purpose operator suitable for the cert-manager ecosystem." Upstream submission is a separate goal that may not be required.

| Gap | Why it matters for upstream | Why it does not matter for internal use |
|-----|-----------------------------|-----------------------------------------|
| No admission webhook | CNCF projects require admission validation for security-sensitive CRDs | The `PKIRotation` CR is deployed by the operator who knows the spec; misconfiguration surfaces in logs immediately |
| Hardcoded trust-manager Bundle dependency | An upstream operator must work without trust-manager (OpenShift, air-gapped) | We run trust-manager; the coupling is correct for our stack |
| Single intermediate CA topology | Arbitrary PKIs have multi-tier hierarchies and parallel algorithms | Our PKI is one root, one intermediate; the operator matches the actual topology |
| No envtest controller test suite | External contributors need automated, reproducible coverage | Six live rotation cycles with an idempotent state machine is operationally sufficient; the pki package has unit tests |
| `v1alpha1` with no stability story | External users need migration guarantees between API versions | There is one `PKIRotation` CR in existence and we own it |

### On polling via `RequeueAfter`

The operator polls every 10–30 seconds in `PreservingOldRoot`, `AwaitingReissuance`, and `VerifyingChain`. A purely event-driven design would be more responsive. The polling exists because Watch events are not guaranteed to reach the reconciler across pod restarts or missed events during startup. `RequeueAfter` is a belt-and-suspenders guarantee. For a rotation that completes in under 60 seconds end-to-end, this is acceptable.
