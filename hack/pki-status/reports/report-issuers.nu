# report-issuers.nu — ClusterIssuer and namespaced Issuer markdown report.
# Requires helpers.nu to be sourced first.

def write_issuers_report [r: record, out: string, scanned: string] {
    let ci_rows = ($r.cluster_issuers | each { |ci|
        let conditions = try { $ci.status.conditions } catch { [] }
        let type_ = if "selfSigned" in $ci.spec {
            "self-signed"
        } else if "ca" in $ci.spec {
            $"ca:($ci.spec.ca.secretName)"
        } else if "acme" in $ci.spec {
            "acme"
        } else {
            "?"
        }
        let subject = if "ca" in $ci.spec {
            let backing = ($r.certs | where { |c| ($c.spec.secretName? | default "") == $ci.spec.ca.secretName } | first_or_null)
            if $backing != null { cert_subject $backing } else { "(no Certificate manages this Secret)" }
        } else { "" }
        let status = ready_status $conditions
        { Name: $ci.metadata.name, Type: $type_, Subject: $subject, Ready: (ready_symbol $status) }
    } | sort-by Name)

    let issuer_rows = ($r.issuers | each { |i|
        let conditions = try { $i.status.conditions } catch { [] }
        let type_ = if "ca" in $i.spec {
            $"ca:($i.spec.ca.secretName)"
        } else if "acme" in $i.spec {
            "acme"
        } else {
            "?"
        }
        let subject = if "ca" in $i.spec {
            let ns = $i.metadata.namespace
            let backing = ($r.certs | where { |c| $c.metadata.namespace == $ns and ($c.spec.secretName? | default "") == $i.spec.ca.secretName } | first_or_null)
            if $backing != null { cert_subject $backing } else { "(no Certificate manages this Secret)" }
        } else { "" }
        let status = ready_status $conditions
        { Namespace: $i.metadata.namespace, Name: $i.metadata.name, Type: $type_, Subject: $subject, Ready: (ready_symbol $status) }
    } | sort-by Namespace Name)

    let ci_table     = ($ci_rows | to_md_table ["Name" "Type" "Subject" "Ready"])
    let issuer_table = if ($issuer_rows | is-empty) {
        "_None_"
    } else {
        $issuer_rows | to_md_table ["Namespace" "Name" "Type" "Subject" "Ready"]
    }

    $"# PKI Issuers

_Scanned: ($scanned)_

---

## ClusterIssuers

($ci_table)

## Namespaced Issuers

($issuer_table)

---

← [PKI Status]\(./README.md\)
" | save -f $out
}
