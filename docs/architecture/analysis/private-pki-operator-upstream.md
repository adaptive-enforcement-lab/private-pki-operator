---
date: 2026-03-02
author: Mark Cheret
subject: private-pki-operator
category: Upstream Submission Analysis
---

# Upstream Submission Analysis: private-pki-operator

This document analyses the feasibility of contributing `private-pki-operator` — or the pattern it implements — to the cert-manager ecosystem as an upstream project.

**Operator manual:** [docs/features/private-pki-operator/operator-manual.md](../../features/private-pki-operator/operator-manual.md)
**Standards assessment:** [docs/architecture/analysis/private-pki-operator-standards.md](./private-pki-operator-standards.md)

---

## Executive Summary

The dual-trust window state machine is technically sound and fills a real gap in the cert-manager ecosystem. The operator would **not be accepted upstream in its current form**, but the primary technical blocker — the Secret deletion reissuance trigger — has been resolved: reissuance now uses the `cmctl renew` mechanism (`Issuing: True` condition status patch), which requires no write access to Secrets.

The remaining gaps are generalisation and community requirements, not correctness issues. Whether upstream submission is worth pursuing is a separate question from whether the operator is fit for production internal use — it is.

The gaps are known and fixable if submission becomes a goal. They require engineering work and community engagement, not a fundamental rethink.

---

## Why It Would Be Rejected Today

### 1. Scope mismatch with the cert-manager project charter

cert-manager is a CNCF graduated project. Its charter is certificate lifecycle management: issuance, renewal, revocation. Root CA rotation orchestration is a higher-level policy concern. The cert-manager maintainers have been consistent in declining features that embed orchestration logic into the core project — trust-manager started as an external project precisely because trust distribution was considered out of scope for cert-manager itself.

A standalone operator in the cert-manager ecosystem (like trust-manager, approver-policy, or csi-driver) is a more realistic target than a feature in the cert-manager core.

### 2. ~~The Secret deletion trigger is a hack~~ — Resolved

~~The most technically contentious element is the use of Secret deletion to force intermediate CA reissuance.~~ This is no longer the case. Reissuance is now triggered by patching the intermediate Certificate's `status` subresource with `Issuing: True` — the same mechanism `cmctl renew` uses. The operator has no write access to Secrets. This blocker is closed.

### 3. No admission webhook

Graduated CNCF projects expect admission webhooks on CRDs that manage security-sensitive resources. A `PKIRotation` that silently error-loops when misconfigured is not production-grade by the standard of the cert-manager project.

### 4. Insufficient test coverage

cert-manager has a comprehensive envtest integration test suite. A submitted operator would need:
- Integration tests for the full state machine via envtest (real Kubernetes API + etcd)
- Tests for fault scenarios: cert-manager unavailable, reissuance timeout, operator restart mid-rotation
- E2e tests against a kind cluster with cert-manager and trust-manager installed
- Unit tests for all helper functions, not just the `internal/pki` package

The current test coverage (unit tests for `internal/pki`, manual e2e validation) would be insufficient for upstream review.

### 5. Hardcoded trust-manager Bundle dependency

The operator's state machine assumes trust-manager Bundles and a staging ConfigMap as the trust distribution mechanism. This is not a universal assumption. Users on OpenShift use `TrustAnchor` resources, users in air-gapped environments may use entirely different mechanisms, and users who manage trust stores manually have no use for a Bundle-coupled state machine. An upstream operator must abstract the trust distribution layer.

### 6. Single intermediate CA topology

The `discoverIntermediates` function discovers intermediates by finding Certificates that reference the root CA's ClusterIssuer. This works for a single-tier hierarchy (one root, one intermediate). It does not handle:
- Multiple intermediates in different namespaces
- Intermediates with different algorithms (RSA + ECDSA parallel hierarchies)
- Multi-tier hierarchies (root → intermediate → sub-intermediate → leaf)

Real-world PKIs are rarely single-tier. An upstream operator must handle the general case.

### 7. `v1alpha1` API with no stability story

cert-manager's own API graduated from v1alpha2 to v1beta1 to v1 with careful migration paths. A submitted operator would need a stated API versioning and stability roadmap. `v1alpha1` with no conversion webhook or migration documentation would not be accepted into a graduated CNCF project.

---

## What Would Need to Change

### Path 1: Contribute directly to cert-manager (high bar, long timeline)

This path targets adding root CA rotation orchestration to the cert-manager core project or as an official cert-manager sub-project managed by the cert-manager maintainers.

**Required steps:**

1. ~~**Propose a cert-manager Enhancement Proposal (CEP) for operator-triggered reissuance.**~~ — **No longer required.** The `Issuing: True` condition status patch is already the documented `cmctl renew` mechanism. The operator uses it. No CEP needed.

2. ~~**Write the reissuance proposal in terms of the cert-manager Certificate controller.**~~ — **Resolved by existing API.** `certificates/status: patch` with `Issuing: True` is the stable trigger. No spec field proposal needed.

3. **Generalize the trust distribution abstraction.**
   Replace the hardcoded trust-manager Bundle + ConfigMap pattern with an interface that supports alternative trust distribution mechanisms. At minimum: trust-manager Bundle (current), raw Kubernetes Secret (for users not running trust-manager), and a pluggable provider for platform-specific mechanisms (GKE TrustConfig, OpenShift).

4. **Add a validating webhook.**
   Validate at admission time: referenced Certificate exists, Bundle exists, staging ConfigMap namespace is the trust namespace, no concurrent rotation in progress.

5. **Write a comprehensive test suite.**
   envtest suite covering: normal rotation cycle, operator restart mid-rotation (in each phase), cert-manager unavailable during AwaitingReissuance, reissuance timeout, chain verification failure. E2e suite using kind + cert-manager + trust-manager installed via Helm.

6. **Handle multi-tier and multi-intermediate topologies.**
   Expose `spec.intermediates` as an optional list for explicit control, while retaining the ClusterIssuer-based auto-discovery as a fallback. Document the supported topologies and their limitations.

7. **Write a conversion webhook and API stability roadmap.**
   State what v1alpha1 → v1beta1 → v1 graduation will require and on what timeline. cert-manager's maintainers expect this for any API they adopt.

8. **Establish a relationship with the cert-manager maintainers before submitting code.**
   The cert-manager community uses GitHub Discussions for pre-proposal conversation. Opening a discussion with the problem statement (cert-manager has no zero-downtime root CA rotation workflow) and the proposed operator approach — before writing code — is the correct way to build consensus.

### Path 2: Propose as a cert-manager ecosystem sub-project (more realistic, shorter timeline)

This path targets adoption as a community-supported companion project, similar to how trust-manager, approver-policy, csi-driver, and the `cmctl` CLI were adopted.

cert-manager ecosystem sub-projects:
- Solve a problem that cert-manager core explicitly declines to address
- Are maintained by contributors with an established relationship with the cert-manager community
- Meet the cert-manager project's code quality bar (test coverage, webhook, API stability)
- Follow the cert-manager release cadence and are kept compatible with new cert-manager versions

**Required steps for this path:**

1. ~~**Fix the Secret deletion issue**~~ — **Done.** Reissuance uses `Issuing: True` condition status patch. No `secrets: delete` permission required.

2. **Generalize the trust abstraction** to support at minimum trust-manager Bundle + raw Secret, so the operator is not exclusively trust-manager coupled.

3. **Add the validating webhook and improve test coverage** (same as Path 1, steps 4–5 — the test bar for ecosystem sub-projects is the same as for core).

4. **Open a GitHub Discussion in `cert-manager/community`** describing:
   - The problem (no zero-downtime root CA rotation workflow exists in the cert-manager ecosystem)
   - The proposed operator (with link to this repository)
   - Willingness to maintain the operator under the cert-manager GitHub org
   - The current state and what work remains

5. **Demonstrate compatibility** with at least two recent cert-manager minor versions and the current trust-manager release.

The dual-trust window concept is sound. The state machine approach is correct. The problem is real and widely felt — the cert-manager community's own KubeCon EU 2023 talk on `rotate-roots` demonstrates that maintainers are aware of the gap. The technical gap between "PoC that works against our specific setup" and "general-purpose operator the community would adopt" is real but not insurmountable. The main asks are a clean trigger API, abstracted trust layer, test suite, and pre-code community conversation.

---

## What This Operator Does Well That Upstream Would Inherit

Even in its current form, the operator demonstrates several design decisions that an upstream version should preserve:

- **Cluster-scoped CRD:** Root CA rotation is a cluster-level concern. A namespaced CRD would be the wrong model.
- **No intermediate names in spec:** Auto-discovery via ClusterIssuer reference is the right API surface. Operators should not have to enumerate their intermediate CAs.
- **No autonomous rollback:** Holding state and alerting on failure is safer than automated rollback in a security-sensitive operation.
- **Conditions following Kubernetes conventions:** All three conditions use `metav1.Condition`. No custom string fields for phase-specific status.
- **RequeueAfter as belt-and-suspenders:** Even a purely event-driven design should retain polling as a fallback to handle missed events across restarts.
