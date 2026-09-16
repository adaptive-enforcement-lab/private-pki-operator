# Spike: two-tier chain-of-custody policy (#364)

## Rule set (as specified)

1. **CAs go through platform CA in their chain** — every `isCA: true` Certificate must trace
   back to `ClusterIssuer/private-intermediate-ca`, however many hops deep.
2. **Leaves go through the last CA in their chain** — a leaf (`isCA: false`) Certificate must
   be issued by whichever CA is deepest/most-specific in its namespace, not one that skips
   past an existing product-level CA.
3. **Intermediates that are not namespace-named go through namespace CA** — any `isCA: true`
   Certificate whose name isn't `<namespace>-intermediate-ca` must chain through
   `Issuer/<namespace>-ca`, not the ClusterIssuer directly and not another namespace's Issuer.

## Feasibility

Confirmed via two existing policies in this chart, both already deployed:

- `cluster-policy-no-selfsigned-leaf-certs.yaml` — single-resource `context.apiCall` looks up
  an Issuer's `spec` by name templated from `request.object.spec.issuerRef.name`, then
  JMESPath-inspects the result (`contains(keys(issuerSpec), 'selfSigned')`).
- `cluster-policy-trust-bundle-adoption.yaml` — collection `context.apiCall` lists every
  Certificate in a namespace and reduces with JMESPath (`items | length(@)`).

Both patterns compose: a rule can carry multiple `context` entries, later ones can template off
earlier request/object fields, and JMESPath can filter/reduce a listed collection. Rules 1 and 3
are direct extensions of the already-shipped patterns. Rule 2 is graph-shaped and is the one
genuinely open design question below.

## Rule 3 — straightforward, single hop

Exactly the design I drafted before the "spike" flag: match `isCA: true` Certificates in
`pki-managed` namespaces whose name `!=` `<namespace>-intermediate-ca`, deny unless
`issuerRef == {kind: Issuer, name: <namespace>-ca}`. No `context.apiCall` needed — same
`request.namespace` templating #340 already uses.

## Rule 1 — two-hop chain walk, bounded depth

For a namespace CA (name `== <namespace>-intermediate-ca`): unchanged, direct
`issuerRef == ClusterIssuer/private-intermediate-ca` check (this **is** hop one of the chain).

For a product-level CA (name `!=`): rule 3 already forces its `issuerRef` to
`Issuer/<namespace>-ca`. To confirm *that* Issuer itself roots at the platform CA (rather than
trusting the name alone), add one more `context.apiCall`:

```yaml
context:
  - name: namespaceIssuer
    apiCall:
      urlPath: "/apis/cert-manager.io/v1/namespaces/{{ request.namespace }}/issuers/{{ request.namespace }}-ca"
      jmesPath: "spec.ca.secretName"
      default: ""
  - name: namespaceCACert
    apiCall:
      urlPath: "/apis/cert-manager.io/v1/namespaces/{{ request.namespace }}/certificates/{{ namespaceIssuer }}"
      jmesPath: "spec.issuerRef"
      default: {}
validate:
  deny:
    conditions:
      any:
        - key: "{{ namespaceCACert.kind || 'Issuer' }}"
          operator: NotEquals
          value: ClusterIssuer
        - key: "{{ namespaceCACert.name }}"
          operator: NotEquals
          value: private-intermediate-ca
```

This is bounded at exactly 2 hops because the estate's actual shape is bounded at 2 hops today
(root → namespace CA → at most one product CA, per `#328`'s design). It does **not** generalize
to a 3rd tier without a 3rd `context.apiCall` added by hand.

## Rule 2 — the real open question

"Last CA in the chain" requires knowing, for a given namespace, which CA has no other CA
chaining beneath it — i.e. walking the namespace's whole CA graph, not one resource's direct
issuer. Two options:

**Option A — bounded heuristic (matches today's actual shape).** Every namespace in this estate
has at most one product-level CA beneath its namespace CA (only `workflows` has a second tier at
all). So "last CA" reduces to: if a Certificate named `<namespace>-intermediate-ca-derived
product CA` exists and lists this namespace's `<namespace>-ca` Issuer as its own issuer, leaves
must use *that* product Issuer; otherwise leaves must use `Issuer/<namespace>-ca` directly. This
needs one collection `context.apiCall` (list Certificates in namespace, filter `isCA==true` and
`issuerRef.name == "<namespace>-ca"`) and an `Equals`/`NotEquals` check against
`request.object.spec.issuerRef.name`. Cheap, testable, matches every real namespace today.
**Breaks silently** if a third tier is ever added — the policy would keep enforcing "one level
past the namespace CA" without erroring, just wrongly.

**Option B — general N-level graph walk.** List every `isCA: true` Certificate in the namespace
in one collection call, compute (via JMESPath) the set of Issuer-backing-Certificate names that
are *never* referenced as another CA's `issuerRef.name` — that set is "the leaves' available
issuers," any size. JMESPath can express the "used as someone's issuerRef" side of the
set-difference; excluding those from the full list needs an expression along the lines of
`items[?spec.isCA==\`true\`].metadata.name` minus
`items[?spec.isCA==\`true\`].spec.issuerRef.name` — JMESPath doesn't have a native set-difference
operator, so this would need `contains()` filtering per candidate name inside a comprehension,
which is possible but noticeably more fragile to get right and to unit-test than Option A, and
harder to read in a `kubectl get clusterpolicy -o yaml` six months from now.

## Recommendation

Ship Option A now — it's a faithful, testable expression of the estate's actual current shape,
and rules 1/3 are worth having in `Audit` mode regardless of how rule 2 resolves. Flag Option B
as a follow-up issue, gated on a second product-level tier actually being requested anywhere
(nothing today needs it) — building the general graph-walk before there's a second real case to
validate it against is exactly the kind of unproven-mechanism risk this epic already burned
through once.

## Open question for the operator

Ship Option A's bounded heuristic for rule 2, or hold #364 entirely until a general graph-walk
is designed? This is the one fork in this spike that changes what gets built, not just how.
