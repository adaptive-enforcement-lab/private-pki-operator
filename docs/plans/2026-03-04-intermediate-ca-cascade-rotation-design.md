# Intermediate CA Cascade Rotation Design

**Date:** 2026-03-04
**Status:** Design — awaiting implementation plan
**Issue:** #74

---

## Problem

`rotationPolicy: Always` on the intermediate CA causes cert-manager to generate a new private key on every renewal. When this happens independently of a root CA rotation — on the intermediate CA's own 90-day schedule — the operator does nothing. The intermediate CA gets a new SKID, but no downstream certs (tier-2 intermediates, leaf certs) are re-issued. Their chains silently break until their own renewal schedule fires.

Empirically confirmed in `hack/pki-gap-test/`: cert-manager makes zero attempt to cascade reissuance at any tier depth. This is cert-manager design, not a configuration gap. The cascade must be owned by the operator.

See also: upstream [cert-manager Discussion #8472](https://github.com/cert-manager/cert-manager/discussions/8472) — in design phase as of March 2026, no implementation.

---

## Goals

- Detect when any intermediate CA in a managed PKI hierarchy has rotated its key independently (not as part of a root rotation)
- Automatically cascade `Issuing=True` reissuance to all downstream CAs and leaf certs at any chain depth
- Reuse the existing `AwaitingReissuance` and `VerifyingChain` logic
- No new CRD — extend the existing `PKIRotation` CRD with a `role` field
- Work for Issuer and ClusterIssuer backed CA hierarchies
- Remain correct when root rotation and independent intermediate rotation happen concurrently

## Non-Goals

- Cross-cluster or multi-root PKI topologies
- Manual (user-declared) intermediate rotation CRs — all intermediate CRs are auto-created
- GCP TrustConfig special-casing — trust-manager keeps the ConfigMap current when the intermediate Secret changes; the existing GCP sync path handles it automatically

---

## Architecture

### 1. CRD Extension — `spec.role`

The `PKIRotation` CRD gains one new spec field and renames one status field.

#### New spec field

```yaml
spec:
  # role determines which phases of the state machine apply.
  # RootCA (default) — full rotation including dual-trust window.
  # IntermediateCA   — cascade-only: AwaitingReissuance → VerifyingChain.
  # IntermediateCA CRs are auto-created by the operator; do not declare them manually.
  # +kubebuilder:validation:Enum=RootCA;IntermediateCA
  # +kubebuilder:default=RootCA
  role: IntermediateCA

  # intermediateCA identifies the cert-manager Certificate representing the
  # intermediate CA this CR manages. Required when role=IntermediateCA.
  # +optional
  intermediateCA:
    certificateName: private-intermediate-ca
    certificateNamespace: cert-manager
```

`trustBundle`, `trustConfigRef`, and `stagingConfigMap` are `RootCA`-only fields. They are ignored when `role: IntermediateCA`.

#### Status field rename

`currentRootSKID` / `previousRootSKID` → `currentSKID` / `previousSKID`. Same semantics, valid for both roles. Existing `RootCA` CRs continue to work; the field names in status are the only API break (a `v1alpha1` concern, acceptable).

#### Owner references

Auto-created `IntermediateCA` CRs carry an owner reference to the root `PKIRotation`. Kubernetes garbage-collects them when the root CR is deleted or when the underlying intermediate `Certificate` disappears.

---

### 2. State Machine per Role

The phase enum is unchanged. `role` determines which phases are reachable.

#### `RootCA` role — full machine (unchanged)

```
Idle
  → PreservingOldRoot      (root CertificateRequest detected, old SKID recorded)
  → DualTrustActive        (new root Secret live, both root PEMs in staging ConfigMap)
  → SyncingGCPTrustConfig* (GCP gate — optional, controlled by spec.trustConfigRef)
  → AwaitingReissuance     (intermediate re-issuance triggered)
  → VerifyingChain         (full AKID→SKID chain walk)
  → Complete               (old root PEM removed from staging ConfigMap)
  → Idle
```

#### `IntermediateCA` role — cascade-only machine

```
Idle
  → AwaitingReissuance     (intermediate SKID change detected, downstream re-issuance triggered)
  → VerifyingChain         (full AKID→SKID chain walk below this intermediate)
  → Complete               (update status.currentSKID, return to Idle)
  → Idle
```

#### `reconcileIdle` for `IntermediateCA`

Replaces CertificateRequest-watch detection with direct Secret inspection:

1. Read `status.currentSKID` (last known SKID for this intermediate)
2. Read the intermediate CA Secret, extract current SKID
3. **SKID unchanged** → stay Idle; no-op
4. **SKID changed AND owner root `PKIRotation` is not Idle** → **yield**: write new SKID into `status.currentSKID` (so root rotation's `reconcileComplete` sync does not overwrite it back), requeue in 30 s, do not cascade
5. **SKID changed AND owner root `PKIRotation` is Idle** → transition to `AwaitingReissuance`

The yield read is a single `r.Get` on the owner CR by name from the owner reference. No locking, no patching.

#### `reconcileComplete` for `IntermediateCA`

Much simpler than the root's: set `status.currentSKID = newSKID`, clear `status.previousSKID`, return to Idle. No ConfigMap cleanup, no Bundle patch.

---

### 3. Recursive BFS Discovery — the Pull-Apart

The existing `discoverIntermediates`, `discoverNamespaceIntermediates`, and `discoverLeafCerts` functions are replaced by a single recursive BFS function:

```go
// discoverDownstream returns all Certificate objects below anchorIssuer
// at any chain depth, separated into CA certs (isCA=true) and leaf certs.
// It handles both Issuer and ClusterIssuer anchors.
func (r *PKIRotationReconciler) discoverDownstream(
    ctx context.Context,
    anchor IssuerRef, // {Name, Kind, Namespace, Group}
) (cas []cmv1.Certificate, leaves []cmv1.Certificate, err error)
```

**Algorithm (one level of BFS):**

1. List all `Certificate` objects where `spec.issuerRef` matches `anchor` (name + kind; for namespace-scoped Issuers, restrict to the Issuer's namespace)
2. For each result:
   - `isCA: false` → collect as leaf, do not recurse
   - `isCA: true` → collect as CA, then find all Issuers/ClusterIssuers where `spec.ca.secretName == cert.Spec.SecretName` (in cert's namespace for Issuers; cluster-wide for ClusterIssuers), recurse into each
3. Terminate when no CA certs are found at a level

Result is two flat slices — all CAs and all leaves at any depth below the anchor — regardless of how many tiers exist.

**Parameterisation of `AwaitingReissuance` and `VerifyingChain`:**

Both phases are refactored to accept an anchor resolved at the top of `Reconcile`:

| Role | `anchor` | `anchorSKID` |
|------|----------|-------------|
| `RootCA` | Issuer/ClusterIssuer backed by root CA Secret | `status.currentSKID` (new root SKID) |
| `IntermediateCA` | Issuer/ClusterIssuer backed by intermediate CA Secret | `status.currentSKID` (new intermediate SKID) |

The implementation of both phases is otherwise identical. The root's existing AKID→SKID chain walk already handles n-tier — the BFS generalisation makes the discovery match.

**RBAC note:** Reading a CA cert's Secret to extract SKID/AKID requires Secret access in that CA's namespace. The current Role is scoped to `cert-manager`. Any tier-2+ CA living in another namespace (e.g. `chaos-mesh`) requires either an additional namespace-scoped Role or a ClusterRole with broader Secret access. This is a deployment concern resolved per actual topology; the code handles it correctly once RBAC is in place.

---

### 4. Auto-Creation

The root `PKIRotation` controller creates and maintains child `IntermediateCA` CRs during `reconcileIdle`, alongside its existing staging ConfigMap setup.

**Upsert logic (idempotent):**

1. Call `discoverDownstream` from the root's anchor — returns all CA certs at any depth
2. For each discovered CA cert, create-or-update a `PKIRotation` with:
   - `spec.role: IntermediateCA`
   - `spec.intermediateCA`: `{certificateName, certificateNamespace}`
   - `metadata.name`: `<root-cr-name>-<sha256-truncated-of-namespace/name>` — deterministic, ≤63 chars
   - `metadata.ownerReferences`: owner is the root `PKIRotation`
3. Do not delete child CRs explicitly — owner-reference GC handles removal when a CA disappears

If the child CR already exists with the correct spec, no patch is issued. Re-entering `reconcileIdle` on every loop is safe.

**Bootstrap (first deploy on existing cluster):**

On first creation, each child `IntermediateCA` CR reads its intermediate CA's current SKID and writes it into `status.currentSKID` as the baseline. This is not a rotation trigger — `reconcileIdle` only cascades when the SKID *changes* from the stored value.

---

### 5. Merge During Root Rotation

Root rotation is the single coordinator. When an intermediate CA SKID changes during an active root rotation, the intermediate CR **yields** (step 4 in `reconcileIdle` above). The root rotation's `AwaitingReissuance` already discovers and re-issues all downstream certs via `discoverDownstream` — the independently-rotated intermediate is naturally included.

**Handoff at `reconcileComplete` (root rotation):**

After the root rotation verifies the chain and before returning to Idle, it patches `status.currentSKID` on every child `IntermediateCA` CR to the SKID it just verified. When the child CRs resume from yield, their stored SKID matches the Secret — no cascade fires. This is the merge: root rotation owns the cascade *and* updates the intermediate CRs' bookkeeping.

---

### 6. Watches

One new watch is added; one existing watch is extended.

```
PKIRotationReconciler watches:
  PKIRotation                → self (existing)
  Secret (root CA)           → enqueue root PKIRotation (existing)
  Secret (intermediate CAs)  → enqueue matching IntermediateCA PKIRotation (NEW)
  Bundle                     → enqueue root PKIRotation (existing)
  Certificate                → enqueue root PKIRotation via CertReq detection (existing)
```

**New intermediate Secret watch:**

`handler.EnqueueRequestsFromMapFunc` maps `Secret → PKIRotation` by:
1. Listing all `IntermediateCA`-role `PKIRotation` CRs
2. Matching `spec.intermediateCA.certificateNamespace/certificateName` → `cert.Spec.SecretName`
3. Enqueuing the matching CR

Predicate: fire only when Secret `resourceVersion` changes (not on every metadata touch). Correctness is maintained by the SKID comparison in `reconcileIdle` even if the predicate is coarse.

---

## Data Flow — Independent Intermediate Rotation

```
cert-manager renews private-intermediate-ca (new key, new SKID)
    ↓
intermediate CA Secret updated
    ↓
Secret watch fires → enqueues IntermediateCA PKIRotation CR
    ↓
reconcileIdle: SKID changed, owner RootCA PKIRotation is Idle
    ↓
→ AwaitingReissuance
    discoverDownstream(intermediateCA's Issuer/ClusterIssuer)
    → finds: [tier-2 CAs, leaf certs] at all depths
    triggerReissuance(Issuing=True) for each
    ↓
cert-manager re-issues all downstream certs
    ↓
→ VerifyingChain
    AKID→SKID walk: all downstream certs must have AKID = new intermediate SKID
    ↓
→ Complete
    status.currentSKID = new SKID
    → Idle

trust-manager detects intermediate Secret change → updates Bundle ConfigMap → GCP sync fires automatically
```

---

## Data Flow — Concurrent Root + Independent Intermediate Rotation

```
cert-manager renews root CA → PKIRotation enters PreservingOldRoot
cert-manager renews intermediate CA (simultaneously, rotationPolicy: Always)
    ↓
IntermediateCA PKIRotation reconcileIdle:
    SKID changed, BUT owner RootCA PKIRotation phase ≠ Idle
    → yield: write new intermediate SKID to status.currentSKID, requeue 30s
    ↓
Root rotation proceeds through DualTrustActive → AwaitingReissuance
    discoverDownstream finds the independently-rotated intermediate
    triggerReissuance for it and all its downstream
    ↓
Root rotation: reconcileComplete
    patches IntermediateCA PKIRotation status.currentSKID = verified SKID
    → root returns to Idle
    ↓
IntermediateCA PKIRotation reconcileIdle (resumes from requeue):
    SKID matches status.currentSKID (patched by root rotation)
    → stays Idle, no duplicate cascade
```

---

## What Gets Refactored vs What Stays

| Component | Change |
|-----------|--------|
| `PKIRotationSpec` | Add `role`, `intermediateCA` fields |
| `PKIRotationStatus` | Rename `currentRootSKID`→`currentSKID`, `previousRootSKID`→`previousSKID` |
| `Reconcile` | Add role-based anchor resolution before phase switch |
| `reconcileIdle` | Split: root path (existing) vs intermediate path (new SKID detection) |
| `reconcileComplete` | Split: root path (ConfigMap cleanup) vs intermediate path (SKID update only) |
| `reconcileAwaitingReissuance` | Parameterise by anchor — otherwise unchanged |
| `reconcileVerifyingChain` | Parameterise by anchorSKID — otherwise unchanged |
| `discoverIntermediates` + `discoverNamespaceIntermediates` + `discoverLeafCerts` | Replace with `discoverDownstream(anchor IssuerRef)` — recursive BFS, handles Issuer and ClusterIssuer |
| `reconcileIdle` (root) | Add child CR upsert after staging ConfigMap setup |
| `reconcileComplete` (root) | Add child CR SKID patch before returning to Idle |
| `SetupWithManager` | Add intermediate Secret watch |
| `reconcilePreservingOldRoot`, `reconcileDualTrustActive`, `reconcileSyncingGCPTrustConfig` | Unchanged — `RootCA` role only, never entered by `IntermediateCA` CRs |
