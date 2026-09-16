# Namespace Intermediate CA Authority Design

**Date:** 2026-08-23
**Status:** Design — implementation in progress (see Epic tree below)
**Issue:** #328 (Epic)

---

## Problem

Rolling out databus mutual-TLS client certs across QAC surfaced a real ownership gap. Five
namespaces each need their own `<namespace>-intermediate-ca` + `Issuer/<namespace>-ca` +
`databus-client` leaf: `platform`, `inventory`, `performance-testing`, `kong-ingress`, `security`.

Four of those five namespace intermediate CAs were each hand-rolled independently, in four
different repos, by copying the pattern from this repo's own
[cert-manager-extensions user guide](../features/cert-manager-extensions/user-guide.md):

- `workflows` chart → `platform` namespace
- `inventory` chart → `inventory` namespace
- `k6-extensions` chart (`performance-testing` repo) → `performance-testing` namespace
- `api-gateway-platform-core-config` chart → `kong-ingress` namespace

The fifth, `security`, turned out to already have a namespace intermediate CA
(`security-intermediate-ca` / `Issuer/security-ca`) — but owned by `google-sso`'s
`identity-resolver` chart, not any repo whose name suggests "security." Three separate PRs
(onboarding `inventory`, `performance-testing`, `kong-ingress`) each asserted `security` "already
has its own databus-client cert via its own chart" — which was never true until
an internal SSO-integration ticket fixed it. Nobody working those PRs could verify the claim from the
outside: "who issues a namespace's intermediate CA" was answered by "whichever chart needed one
first, if you can find it."

That produced: four independent copies of near-identical CA + Issuer boilerplate, no way to
discover an existing namespace CA's owner without a live cluster scan, and a false claim that
propagated across three separate PRs unchecked.

## Goals

- One discoverable, governed authority for namespace intermediate CA issuance, replacing N
  independent per-team copies of the same boilerplate
- Self-service namespace opt-in via a label, not a platform-gated PR per namespace
- Zero manual per-namespace YAML after this ships
- Safe, audited rollout — never block cert admission before the sanctioned mechanism is proven
  clean everywhere it needs to run

## Non-Goals

- Root or cluster-intermediate CA rotation (owned by `private-pki-operator`; explicitly considered
  and rejected for this problem — see [Rejected Alternatives](#rejected-alternatives))
- Retroactively auditing every namespace in the estate for CA correctness (`#340` covers namespaces
  carrying the `pki-managed` label going forward, not a full-estate sweep)
- A generic "any namespace-scoped label needs a MetadataBehavior CR" policy — this doc covers this
  one label only

---

## Architecture

### Trigger

A Kyverno `generate` `ClusterPolicy` in `charts/cert-manager-extensions/templates/features/namespace-ca/`
(new feature directory, sibling to the existing `intermediate-ca/`, `leaf-certs/`, `root-ca/` — this
chart already owns the cluster intermediate CA these namespace CAs chain under).

Matches `kind: Namespace` carrying label `pki-managed: "true"` — boolean, closed set,
no other value accepted. Registered as a governed contract by a `MetadataBehavior` CR (see
[MetadataBehavior CR](#metadatabehavior-cr) below), not left as informal convention.

### Generated objects

Per matched namespace, following the existing user-guide naming
(#239 CN/O/OU standard):

- `Certificate/<namespace>-intermediate-ca` — `issuerRef: private-intermediate-ca` (ClusterIssuer),
  `isCA: true`
- `Issuer/<namespace>-ca` — backed by that Certificate's secret

`generateExisting: true` backfills every already-PKI-managed namespace in the same rollout, not as
separate follow-up work per namespace.

### MetadataBehavior CR

Ships from **this repo**, as part of `cert-manager-extensions` (the same chart implementing the
generate policy) — not delegated to the namespace-provisioning tooling, despite that repo's own precedent of
shipping `MetadataBehavior` records for namespace-scoped labels (`namespace-type-scope`,
`namespaces#77`, deployed to the `inventory` namespace). `pki-managed` has exactly one consumer —
this chart's own generate policy — so this repo owns the contract for a label only it acts on. The
`namespaces` chart owns the *label value* on each namespace (`config[].labels` per environment);
this repo owns *what the label means*.

The CR deploys into the **`cert-manager` namespace**, not `inventory` — the `MetadataBehavior`
controller's RBAC is cluster-scoped, so it can reconcile records anywhere; `cert-manager` is this
chart's own natural destination, not borrowed from another chart's AppProject.

### Existing per-repo intermediates: kept or dropped, decided per namespace

The generated objects are **namespace-keyed**: `<namespace>-intermediate-ca` / `<namespace>-ca`.
Whether a producer's existing hand-rolled CA survives as a second hop depends on whether it
collides with that name:

| Namespace | Chart | Existing CA name | Collides? | Decision |
|---|---|---|---|---|
| `platform` | `workflows` | `workflows-intermediate-ca` (product-named) | No | **Keep** — re-parent `issuerRef` from `private-intermediate-ca` to the new `platform-ca`. Only producer with a documented reason for an independent second hop (workflows#700). |
| `inventory` | `inventory` | `inventory-intermediate-ca` (namespace-named) | Yes | **Drop** — sole tenant of its namespace, no isolation value from a second hop it copied by convention, not necessity (inventory#747). |
| `performance-testing` | `k6-extensions` | `performance-testing-intermediate-ca` | Yes | **Drop** — sole-tenant confirmed via live ArgoCD app inventory (performance-testing#212). |
| `kong-ingress` | `api-gateway-platform-core-config` | `kong-ingress-intermediate-ca` | Yes | **Drop** — sole-tenant confirmed (api-gateway-platform#546). |
| `security` | `identity-resolver` | `security-intermediate-ca` | Yes | **Drop** — despite **not** sole-tenant (6 leaf certs across 4 products: identity-issuer, identity-resolver, policy-platform, secret-lifecycle-management). Deliberate: converging onto the central authority is the exact failure this design closes — undiscoverable, whichever-team-got-there-first custodianship on behalf of tenants who never signed up for it (google-sso#381). |

Target shape for the "keep" case (`workflows`, the only one):
`private-root-ca → private-intermediate-ca → platform-ca (sanctioned, this policy) →
workflows-ca (workflows' own extra hop) → leaves`.

### Accepted operational gap: no coexistence during drop

Because the central policy's object name is identical to the dropped hand-rolled one, Kyverno's
generate rule **no-ops while the old object exists** — there is no side-by-side coexistence, no
gradual traffic shift, no instant rollback mid-transition. This was evaluated against the
strangler-fig pattern (build new alongside old, shift traffic incrementally, remove old only once
it carries zero traffic) and deliberately **not** adopted — same-name reuse means leaf certs never
need repointing, at the cost of a brief window with zero CA present between deleting the old object
and Kyverno re-creating the replacement.

**Confirmed live** on `inventory` and `performance-testing`: deleting the hand-rolled `Certificate`/
`Issuer` does not automatically trigger Kyverno to regenerate — the namespace has no intermediate
CA/Issuer at all until something re-touches the `Namespace` object (e.g. an annotation bump) to
force policy re-evaluation. **This is the runbook step for every remaining drop**: after deleting
the old objects, bump a harmless annotation on the `Namespace` to force Kyverno to re-evaluate and
create the replacement. Don't assume it appears on its own.

This is accepted as-is, not engineered around — QAC is the low-stakes environment for exactly this
kind of transition, and building an event-based regeneration trigger to close the gap would be
solving a problem nobody asked for at this scale.

### Enforcement rollout sequencing

1. Generate policy + backfill ships (`#351`)
2. Per-namespace drop/re-parent lands (`#747`, `#212`, `#546`, `#381`, `workflows#700`)
3. MetadataBehavior CR registers the label contract (`#339`, parallel with 1, not blocked by it)
4. Chain-of-custody enforcement (`#340`) ships **`validationFailureAction: Audit` only** — nothing
   to enforce conformance against until the sanctioned mechanism exists and has actually run
5. `#353` verifies the backfill is audit-clean across all 5 namespaces (`hack/pki-status`) —
   including an explicit check for the dead-window condition above, not just end-state
6. `#340` flips to `Enforce` only after step 5 is clean — never before, and never as part of this
   rollout without a separate, explicit decision

### Opt-out semantics

Unlabeling a namespace **does** auto-delete its generated `Certificate`/`Issuer`. The generate
policy's `synchronize` flipped from `false` to `true` once the migration period ended and the 4
hand-rolled duplicate producers were dropped — this policy is now sole owner of every object it
names, and Kyverno's `synchronize: true` semantics delete the generated downstream resource when
the triggering namespace no longer matches. This is a deliberate operator decision, not an
oversight: the trade-off (unlabeling now yanks trust out from under running workloads, not just
stops updating it) was accepted in exchange for `synchronize: true`'s other half — Kyverno's
background sync controller now self-heals drift on the 5 existing namespace CAs (e.g. stale
subject fields from before the CN/O/OU fix) without manual deletion. No separate `CleanupPolicy`
companion is needed; `synchronize: true` already covers both directions.

### Testing

One `_test.yaml` per template under `tests/features/namespace-ca/`, matching this chart's existing
1:1 template-path-mirroring convention (`intermediate-ca/`, `leaf-certs/`, `root-ca/`).

---

## Rejected Alternatives

**`private-pki-operator`.** The issue that opened this discussion floated either a Kyverno generate
policy or extending `private-pki-operator`. Checked the operator's actual scope before choosing:
it's a dual-trust-window state machine for **root CA rotation** — `Idle → PreservingOldRoot →
DualTrustActive → AwaitingReissuance → VerifyingChain → Complete` (see
[intermediate-ca-cascade-rotation-design.md](2026-03-04-intermediate-ca-cascade-rotation-design.md)) —
nothing about namespace-level provisioning. Extending it would mean adding a new CRD and reconcile
loop for a problem the estate already has a proven pattern for.

**Values.yaml allowlist instead of a label.** Considered as the more platform-gated alternative — a
static namespace list in this chart's own `values.yaml`, extended by PR review per new namespace.
Rejected: the whole point of this design is a governed, discoverable *self-service* mechanism, and
a values.yaml allowlist just relocates the "whichever team got there first" pattern one level up
without actually solving discoverability. The label + `MetadataBehavior` contract gives both
self-service and governance.

**Strangler-fig coexistence for the drop/cutover.** See
[Accepted operational gap](#accepted-operational-gap-no-coexistence-during-drop) above.

---

## Epic tree

```
pki-platform#328 (Epic)
├── pki-platform#339 (Story) — MetadataBehavior CR
├── pki-platform#340 (Story) — chain-of-custody enforcement (Audit-only)
├── pki-platform#351 (Story) — generate policy + backfill
│   ├── pki-platform#352 (Subtask) — test coverage
│   ├── pki-platform#353 (Subtask) — audit-clean verification gate, blocks #340
│   ├── workflows#700 (Subtask) — re-parent workflows-intermediate-ca
│   ├── inventory#747 (Subtask) — drop
│   ├── performance-testing#212 (Subtask) — drop
│   ├── api-gateway-platform#546 (Subtask) — drop
│   └── google-sso#381 (Subtask) — drop
└── workflows#658 (Story) — downstream databus-client leaf-cert consolidation, blocked by #340
```
