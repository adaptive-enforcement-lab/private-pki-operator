# report-usage.nu — Certificate usage: what consumes each Certificate, and which
# Certificates nothing observably consumes.
# Requires helpers.nu to be sourced first.

def write_usage_report [r: record, w: record, out: string, scanned: string] {
    let workload_rows = (collect_workload_consumers $r $w)
    let pki_rows      = (collect_pki_consumers $r $w)
    let all_rows      = ([$workload_rows $pki_rows] | flatten)

    let usage = (
        $r.certs
        | each { |cert|
            let ns        = $cert.metadata.namespace
            let secret    = ($cert.spec.secretName? | default "")
            let key       = (secret_key $ns $secret)
            let consumers = ($all_rows | where { |row| $key in $row.Keys })
            let by = (
                $consumers
                | each { |c| $c.Kind }
                | uniq
                | each { |k| $"($k)×($consumers | where Kind == $k | length)" }
                | str join ", "
            )
            {
                Namespace: $ns
                Name:      $cert.metadata.name
                Subject:   (cert_subject $cert)
                SANs:      (cert_sans $cert)
                Secret:    $secret
                Type:      (if ($cert.spec.isCA? | default false) { "CA" } else { "leaf" })
                Consumers: ($consumers | length)
                By:        (if ($by | is-empty) { "—" } else { $by })
                Via:       ($consumers | each { |c| $c.Via } | uniq | str join ", ")
                Issuer:    $"($cert.spec.issuerRef.kind? | default 'Issuer')/($cert.spec.issuerRef.name)"
                Expires:   (try { $cert.status.notAfter | into datetime | format date "%Y-%m-%d" } catch { try { $cert.status.notAfter } catch { "" } })
                Ready:     (ready_symbol (ready_status (try { $cert.status.conditions } catch { [] } | default [])))
            }
        }
        | sort-by Namespace Name
    )

    let referenced   = ($usage | where Consumers > 0)
    let unreferenced = ($usage | where Consumers == 0)

    let used_table = if ($referenced | is-empty) { "_None_" } else {
        $referenced | to_md_table ["Namespace" "Name" "Subject" "Secret" "Type" "Consumers" "By" "Via"]
    }

    let unused_table = if ($unreferenced | is-empty) {
        "_None — every Certificate has at least one consumer this tool can see._"
    } else {
        $unreferenced | to_md_table ["Namespace" "Name" "Subject" "SANs" "Secret" "Type" "Issuer" "Expires" "Ready"]
    }

    let n_total = ($usage | length)
    let n_used  = ($referenced | length)
    let n_unused = ($unreferenced | length)

    let summary_rows = [
        { Metric: "Certificates",                     Count: $n_total }
        { Metric: "With a consumer found",            Count: $n_used }
        { Metric: "With no consumer found",           Count: $n_unused }
        { Metric: "Consumer references found",        Count: ($all_rows | length) }
    ]

    $"# Certificate Usage

_Scanned: ($scanned)_

---

## Summary

($summary_rows | to_md_table ["Metric" "Count"])

---

## Certificates with a consumer

`Subject` is the full X.509 subject — the CN alone no longer identifies a
certificate, the OU names its holding namespace. `By` counts consuming resources
by kind and `Via` names how each reference is declared; see
[Workload Consumers]\(./workloads.md\) for the individual consumers behind these
counts, and [Leaf Certificates]\(./leaves.md\) for SANs and expiry.

($used_table)

---

## Certificates with no consumer found

> **Read this before acting on the table below.**
>
> `No consumer found` does **NOT** mean `safe to delete`.
>
> It means only this: **this tool searched the resource kinds it knows about and
> found nothing that names the Certificate's Secret.** The tool inspects
> Pods \(volumes, projected volumes, env, envFrom\), Ingresses, Argo Events
> EventBus JetStream TLS, cert-manager Issuers and ClusterIssuers, and
> trust-manager Bundles. **Everything else is invisible to it.**
>
> A Certificate can be listed here and still be load-bearing. Known ways that
> happens:
>
> - The consumer is a resource kind not scanned — a Job, CronJob or any workload
>   with no Pod running at scan time; a Gateway API `Gateway` or `HTTPRoute`; a
>   webhook `caBundle`; an Istio/Linkerd or other mesh configuration; a
>   `MutatingWebhookConfiguration`; an operator CRD that names the Secret in a
>   field this tool does not know.
> - The consumer is outside the cluster entirely — the Secret is synced out,
>   exported, or read by an external client or a peer cluster.
> - The consumer reads the Secret through the API at runtime rather than
>   declaring it in a manifest, so no static reference exists to find.
> - The reference is by label selector rather than by name \(for example a
>   trust-manager Bundle source using a selector\), which names no Secret.
> - The Certificate is new and its consumer has not been deployed yet, or the
>   scan hit a window where the consuming Pods were not running.
> - RBAC clamped this tool's read of some namespace or resource kind, so the
>   consumer was never fetched. Check the fetch warnings from the run.
>
> Treat every row as **a question to answer**, not a finding. Confirm the
> certificate is genuinely orphaned by other means before removing anything.

`SANs` is every subjectAltName, type-tagged. `\(none\)` means the certificate
carries none at all — deliberate for client certificates under the estate naming
convention, and a fact about the certificate rather than a missing value.

($unused_table)

---

## What this report can and cannot see

| Scanned | Not scanned |
| --- | --- |
| Pod `volumes[].secret` | Any resource kind not listed on the left |
| Pod `volumes[].projected.sources[].secret` | Workloads with no running Pod at scan time \(Jobs, CronJobs, scaled-to-zero\) |
| Pod `env[].valueFrom.secretKeyRef` | Gateway API, webhook `caBundle`, service-mesh config |
| Pod `envFrom[].secretRef` | Consumers outside the cluster |
| Pod cert-manager CSI volumes \(no Secret involved\) | Runtime API reads with no declared reference |
| Ingress `cert-manager.io/` annotations and TLS secrets | Selector-based Secret references |
| Argo Events `EventBus` `spec.jetstreamExotic.tls` | Namespaces or kinds this tool could not read |
| Issuer / ClusterIssuer `spec.ca.secretName` | |
| trust-manager `Bundle` `spec.sources[].secret.name` | |

Two further limits worth stating plainly:

- **Reference is not transitivity.** A CA Certificate counts as referenced the
  moment an Issuer is backed by it, even if that Issuer issues nothing. Walk the
  trust chains in [PKI Status]\(./README.md\) to judge whether the branch is live.
- **ClusterIssuer and Bundle Secret references are matched by name across all
  namespaces**, because this tool does not read cert-manager's cluster resource
  namespace setting. A same-named Secret in an unrelated namespace can therefore
  be credited with a reference it does not have.

---

← [PKI Status]\(./README.md\)
" | save -f $out
}
