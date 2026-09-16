# report-readme.nu — PKI Status overview README report.
# Requires helpers.nu to be sourced first.

def write_readme_report [r: record, w: record, out: string, scanned: string] {
    let n_ci     = ($r.cluster_issuers | length)
    let n_issuer = ($r.issuers | length)
    let n_ca     = ($r.certs | where { |c| ($c.spec.isCA? | default false) } | length)
    let n_leaf   = ($r.certs | where { |c| not ($c.spec.isCA? | default false) } | length)

    let all_rows = ([(collect_workload_consumers $r $w) (collect_pki_consumers $r $w)] | flatten)
    let n_unused = (
        $r.certs
        | where { |cert|
            let key = (secret_key $cert.metadata.namespace ($cert.spec.secretName? | default ""))
            ($all_rows | where { |row| $key in $row.Keys } | is-empty)
        }
        | length
    )

    let summary_rows = [
        { Resource: "ClusterIssuers",     Count: $n_ci }
        { Resource: "Namespaced Issuers", Count: $n_issuer }
        { Resource: "CA Certificates",    Count: $n_ca }
        { Resource: "Leaf Certificates",  Count: $n_leaf }
        { Resource: "Certificates with no consumer found", Count: $n_unused }
    ]

    let chain_rows = (
        $r.certs
        | each { |cert|
            {
                Namespace: $cert.metadata.namespace
                Name:      $cert.metadata.name
                Chain:     (build_chain $cert $r.certs $r.cluster_issuers $r.issuers)
            }
        }
        | sort-by Namespace Name
    )

    $"# PKI Status

_Scanned: ($scanned)_

---

## Summary

($summary_rows | to_md_table ["Resource" "Count"])

_`No consumer found` means no consumer was found **by this tool**, which sees only
the resource kinds listed in [Certificate Usage]\(./usage.md\). It does not mean the
certificate is unused, and never means it is safe to delete._

## Trust Chains

($chain_rows | to_md_table ["Namespace" "Name" "Chain"])

---

## Reports

| Report | Description |
| --- | --- |
| [Issuers]\(./issuers.md\) | ClusterIssuers and namespaced Issuers with the backing cert's subject |
| [CA Certificates]\(./certs.md\) | Certificates with isCA: true, full subject, trust chain |
| [Leaf Certificates]\(./leaves.md\) | End-entity certificates with full subject, SANs and expiry |
| [Workload Consumers]\(./workloads.md\) | Pods, Ingresses and EventBus resources consuming cert-manager secrets |
| [Certificate Usage]\(./usage.md\) | Per-certificate consumer counts, and certificates with no consumer found |

---
" | save -f $out
}
