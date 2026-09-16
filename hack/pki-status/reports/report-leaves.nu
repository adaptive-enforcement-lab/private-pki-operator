# report-leaves.nu — Leaf Certificate (isCA: false) markdown report.
# Requires helpers.nu to be sourced first.

def write_leaves_report [r: record, out: string, scanned: string] {
    let rows = (
        $r.certs
        | where { |c| not ($c.spec.isCA? | default false) }
        | each { |cert|
            let conditions = try { $cert.status.conditions } catch { [] }
            let subject = (cert_subject $cert)
            let sans = (cert_sans $cert)
            let expires = try {
                $cert.status.notAfter | into datetime | format date "%Y-%m-%d"
            } catch { try { $cert.status.notAfter } catch { "" } }
            let renews = try {
                $cert.status.renewalTime | into datetime | format date "%Y-%m-%d"
            } catch { try { $cert.status.renewalTime } catch { "" } }
            let status = ready_status $conditions
            let algo       = try { $cert.spec.privateKey.algorithm } catch { "" }
            let key_size   = try { $cert.spec.privateKey.size | into string } catch { "" }
            let rotation   = try { $cert.spec.privateKey.rotationPolicy } catch { "" }
            let renew_before = try { $cert.spec.renewBefore } catch { "" }
            let usages     = try { $cert.spec.usages | str join ", " } catch { "" }
            {
                Namespace:      $cert.metadata.namespace
                Name:           $cert.metadata.name
                Subject:        $subject
                SANs:           $sans
                Issuer:         $"($cert.spec.issuerRef.kind? | default 'Issuer')/($cert.spec.issuerRef.name)"
                Algorithm:      $algo
                Size:           $key_size
                RotationPolicy: $rotation
                RenewBefore:    $renew_before
                Usages:         $usages
                Expires:        $expires
                Renews:         $renews
                Ready:          (ready_symbol $status)
                Chain:          (build_chain $cert $r.certs $r.cluster_issuers $r.issuers)
            }
        }
        | sort-by Namespace Name
    )

    let table = if ($rows | is-empty) { "_None_" } else {
        $rows | to_md_table ["Namespace" "Name" "Subject" "SANs" "Issuer" "Algorithm" "Size" "RotationPolicy" "RenewBefore" "Usages" "Expires" "Renews" "Ready" "Chain"]
    }

    $"# Leaf Certificates

_Scanned: ($scanned)_

---

`Subject` is the full X.509 subject — the CN alone no longer identifies a
certificate, the OU names its holding namespace. `SANs` lists every
subjectAltName, type-tagged; `\(none\)` means the certificate carries none at
all, which is deliberate for client certificates and is a fact, not a blank.

($table)

---

← [PKI Status]\(./README.md\)
" | save -f $out
}
