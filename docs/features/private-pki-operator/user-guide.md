# User Guide: Workload Trust Bundle Configuration

> **Related guides:**
> [Operator Manual](./operator-manual.md) — state machine internals, resources deployed, troubleshooting

## Overview

The `private-pki-operator` automates zero-downtime root CA rotation. From a workload perspective the
operator is invisible during normal operation — but the choice of **which trust anchor to mount**
determines whether your workload survives a root CA rotation without downtime.

This guide answers one question: which resource should TLS servers and clients use as their CA trust anchor?

---

## The Rule

**Mount the trust-manager-distributed Bundle (a ConfigMap in your namespace). Never mount the
cert-manager-managed root CA Secret directly.**

| Resource | Kind | Namespace | Mount? | Reason |
|---|---|---|---|---|
| `private-root-ca` (trust-manager Bundle output) | `ConfigMap` | Every namespace | ✅ Yes | Always current; contains both roots during rotation |
| `private-root-ca` (cert-manager root CA) | `Secret` | `cert-manager` | ❌ No | Pinned to one root generation; becomes stale at rotation |
| `private-root-ca-trust-anchor` (operator staging) | `ConfigMap` | `cert-manager` | ❌ No | Operator-internal; not projected to workload namespaces |

The ConfigMap and the Secret share the same name (`private-root-ca`) but live in different
namespaces. Use the **ConfigMap in your own namespace**, not the Secret in `cert-manager`.

---

## Pod Spec

```yaml
volumes:
  - name: ca-bundle
    configMap:
      name: private-root-ca      # trust-manager distributes this to every namespace
      items:
        - key: ca.crt
          path: ca.crt
volumeMounts:
  - name: ca-bundle
    mountPath: /etc/ssl/platform
    readOnly: true
```

Point your TLS configuration at `/etc/ssl/platform/ca.crt` as the CA trust file. This applies
equally to servers validating client certificates (mTLS) and to clients verifying server certificates.

---

## Why This Matters During Root CA Rotation

During root CA rotation the operator drives a dual-trust window state machine:

```
Idle → PreservingOldRoot → DualTrustActive → AwaitingReissuance → VerifyingChain → Complete
                                  ↑
                     both roots simultaneously trusted
```

During `DualTrustActive` and `AwaitingReissuance`, the trust-manager Bundle contains **both the old
and new root CA PEMs concatenated**. A workload mounting this ConfigMap trusts both certificate
generations simultaneously — no restart, no reconfiguration, no downtime.

A workload mounting the cert-manager Secret sees only the new root from the moment cert-manager
completes issuance. Any peer still presenting a certificate that chains to the old root fails TLS
verification immediately. This is the failure mode the operator exists to prevent — it was the
cause of the [incident on 2026-02-20](../../architecture/01-problem-statement/README.md).

---

## No Action Required During Rotation

Once you are mounting the trust-manager ConfigMap, rotation is transparent:

- **No pod restart needed** — Kubernetes propagates ConfigMap updates to running pods
- **No cert reload needed** — reads the file on each TLS handshake (or on inotify-triggered reload)
- **No scheduling needed** — the operator manages the full rotation timeline autonomously

The only action a workload team takes is the one-time setup of mounting the correct ConfigMap at
provisioning time.

---

## Verification

Confirm you are mounting the trust-manager ConfigMap, not the cert-manager Secret:

```bash
# ConfigMap should exist in your namespace — NOT in cert-manager
kubectl get configmap private-root-ca -n <your-namespace>

# During rotation, ca.crt contains two PEM blocks (both roots)
kubectl get configmap private-root-ca -n <your-namespace> \
  -o jsonpath='{.data.ca\.crt}' | grep -c 'BEGIN CERTIFICATE'
# → 1 (normal) or 2 (rotation in progress)
```

The staging ConfigMap is operator-internal and must not be mounted by workloads:

```bash
# This is operator-internal — do not reference it in pod specs
kubectl get configmap private-root-ca-trust-anchor -n cert-manager
```

---

## See Also

- [Operator Manual](./operator-manual.md) — state machine internals, deployed resources, and
  troubleshooting
- [DEC-002 — private-pki-operator](../../architecture/ADRs/DEC-002-private-pki-operator.md) —
  architecture decision record: why an operator, alternatives considered
