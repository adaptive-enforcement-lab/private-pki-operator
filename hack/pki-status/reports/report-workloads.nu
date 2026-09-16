# report-workloads.nu — Workload consumer (Pods / Ingresses / EventBus) report.
# Requires helpers.nu to be sourced first.

def write_workloads_report [r: record, w: record, out: string, scanned: string] {
    let rows = (collect_workload_consumers $r $w | sort-by Namespace Kind Name Ref)

    let table = if ($rows | is-empty) { "_None_" } else {
        $rows | to_md_table ["Namespace" "Kind" "Name" "Subject" "Ref" "Cert" "Via"]
    }

    $"# Workload Consumers

_Scanned: ($scanned)_

---

Every resource found referencing a cert-manager-managed Secret. `Subject` is the
full X.509 subject of the Certificate behind `Ref` — the CN alone no longer
identifies a certificate, the OU names its holding namespace.

`Via` says how the reference is declared:

| Via | Meaning |
| --- | --- |
| `secret-vol` | Pod mounts the Secret as a volume |
| `projected-vol` | Pod mounts the Secret inside a projected volume |
| `env-secretKeyRef` | Pod reads a Secret key into an environment variable |
| `env-envFrom` | Pod loads the whole Secret into the environment |
| `csi-vol` | cert-manager CSI driver mints a certificate into the Pod — no Secret exists |
| `cm-annotation` | Ingress carries a `cert-manager.io/` annotation |
| `eventbus-tls` | Argo Events EventBus declares JetStream TLS material by Secret name |

An EventBus row is the declaration; the `secret-vol` rows on the EventSource and
Sensor Pods it generates are the consequence.

---

($table)

---

← [PKI Status]\(./README.md\)
" | save -f $out
}
