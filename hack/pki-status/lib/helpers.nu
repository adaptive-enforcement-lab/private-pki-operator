# helpers.nu — shared utilities for pki-status submodules.
# Sourced by pki-status.nu before any report modules; do not run directly.

def first_or_null [] {
    if ($in | is-empty) { null } else { $in | first }
}

def ready_status [conditions] {
    let cond = ($conditions | where type == "Ready" | first_or_null)
    if $cond != null { $cond.status } else { "?" }
}

def ready_symbol [status: string] {
    if $status == "True" { "✓" } else if $status == "?" { "?" } else { "✗" }
}

# Safe record lookup by exact key — avoids nushell treating "." as a path separator.
def rget [rec: record, key: string] {
    let row = ($rec | transpose k v | where k == $key | first_or_null)
    if $row != null { $row.v | into string } else { "" }
}

# Key for a {namespace, secretName} pair — "::" avoids "." path-separator
# ambiguity in `get`.
def secret_key [ns: string, name: string] {
    $"($ns)::($name)"
}

# Convert a list of records to a markdown table.
# cols: ordered list of field names to include as columns.
def to_md_table [cols: list<string>] {
    let rows = ($in | each { |r|
        $cols | each { |c|
            try { $r | get $c | into string } catch { "" }
        } | str join " | "
    })
    let header = ($cols | str join " | ")
    let sep    = ($cols | each { "---" } | str join " | ")
    ([$"| ($header) |", $"| ($sep) |"] ++ ($rows | each { |r| $"| ($r) |" })) | str join "\n"
}

# Walk issuerRef chain upward from a Certificate.
# Returns "[self-signed] → backing-cert → … → this-cert".
def build_chain [cert, certs, cluster_issuers, issuers] {
    mut ancestors: list<string> = []
    mut current = $cert
    mut depth = 0

    loop {
        if $depth >= 8 { break }
        $depth += 1

        let iref  = $current.spec.issuerRef
        let ikind = ($iref.kind? | default "Issuer")
        let iname = $iref.name

        if $ikind == "ClusterIssuer" {
            let ci = ($cluster_issuers | where { |x| $x.metadata.name == $iname } | first_or_null)
            if $ci == null {
                $ancestors = ([$"[?CI:($iname)]"] ++ $ancestors); break
            } else if "selfSigned" in $ci.spec {
                $ancestors = (["[self-signed]"] ++ $ancestors); break
            } else if "ca" in $ci.spec {
                let sn      = $ci.spec.ca.secretName
                let backing = ($certs | where { |c| $c.spec.secretName == $sn } | first_or_null)
                if $backing == null { $ancestors = ([$"[secret:($sn)]"] ++ $ancestors); break }
                $ancestors = ([$backing.metadata.name] ++ $ancestors)
                $current   = $backing
            } else {
                $ancestors = ([$"[CI:($iname)]"] ++ $ancestors); break
            }
        } else {
            let ns     = $current.metadata.namespace
            let issuer = (
                $issuers
                | where { |x| $x.metadata.namespace == $ns and $x.metadata.name == $iname }
                | first_or_null
            )
            if $issuer == null {
                $ancestors = ([$"[?Issuer:($iname)]"] ++ $ancestors); break
            } else if "ca" in $issuer.spec {
                let sn      = $issuer.spec.ca.secretName
                let backing = (
                    $certs
                    | where { |c| $c.metadata.namespace == $ns and $c.spec.secretName == $sn }
                    | first_or_null
                )
                if $backing == null { $ancestors = ([$"[secret:($sn)]"] ++ $ancestors); break }
                $ancestors = ([$backing.metadata.name] ++ $ancestors)
                $current   = $backing
            } else {
                $ancestors = ([$"[Issuer:($iname)]"] ++ $ancestors); break
            }
        }
    }

    ($ancestors ++ [$cert.metadata.name]) | str join " → "
}

# ── X.509 identity rendering ──────────────────────────────────────────────────

# Render a Certificate's meaningful X.509 subject as "CN=…, OU=…, O=…".
#
# The CN alone is no longer the identity: under the estate naming convention the
# OU names the namespace holding the certificate and the O the legal entity.
# Never returns an empty string — a Certificate carrying neither a commonName
# nor a subject renders "(no subject)" so a real gap cannot be mistaken for a
# rendering failure.
def cert_subject [cert] {
    let cn      = (try { $cert.spec.commonName | into string } catch { "" })
    let subject = (try { $cert.spec.subject } catch { {} } | default {})
    let rdns = [
        { field: "organizationalUnits", label: "OU" }
        { field: "organizations",       label: "O" }
        { field: "streetAddresses",     label: "STREET" }
        { field: "localities",          label: "L" }
        { field: "provinces",           label: "ST" }
        { field: "postalCodes",         label: "PC" }
        { field: "countries",           label: "C" }
    ]
    let tail = ($rdns | each { |r|
        (try { $subject | get $r.field } catch { [] } | default [])
        | each { |v| $"($r.label)=($v)" }
    } | flatten)
    let serial = (try { $subject.serialNumber | into string } catch { "" })
    let parts = ([
        (if ($cn | is-empty) { [] } else { [$"CN=($cn)"] })
        $tail
        (if ($serial | is-empty) { [] } else { [$"SERIALNUMBER=($serial)"] })
    ] | flatten)
    if ($parts | is-empty) { "(no subject)" } else { $parts | str join ", " }
}

# Render every SAN a Certificate carries, type-tagged: "DNS:…", "IP:…", "URI:…",
# "EMAIL:…".
#
# Client certificates under the estate naming convention deliberately carry no
# SANs at all. An empty result is therefore a fact about the certificate, not
# missing data, and renders "(none)" rather than blank. Nothing here falls back
# to a SAN to establish identity — use `cert_subject` for that.
def cert_sans [cert] {
    let spec = $cert.spec
    let kinds = [
        { field: "dnsNames",       label: "DNS" }
        { field: "ipAddresses",    label: "IP" }
        { field: "uris",           label: "URI" }
        { field: "emailAddresses", label: "EMAIL" }
    ]
    let sans = ($kinds | each { |k|
        (try { $spec | get $k.field } catch { [] } | default [])
        | each { |v| $"($k.label):($v)" }
    } | flatten)
    if ($sans | is-empty) { "(none)" } else { $sans | str join ", " }
}

# ── Certificate ↔ Secret indexes ──────────────────────────────────────────────

# {ns::secretName → Certificate name}. `upsert` rather than `insert` so two
# Certificates claiming one Secret do not abort the run.
def cert_name_index [certs] {
    $certs | reduce -f {} { |c, acc|
        $acc | upsert (secret_key $c.metadata.namespace ($c.spec.secretName? | default "")) $c.metadata.name
    }
}

# {ns::secretName → rendered subject}
def cert_subject_index [certs] {
    $certs | reduce -f {} { |c, acc|
        $acc | upsert (secret_key $c.metadata.namespace ($c.spec.secretName? | default "")) (cert_subject $c)
    }
}

# ── Consumer collection ───────────────────────────────────────────────────────
#
# Both collectors emit rows carrying a `Keys` list of "ns::secretName" values
# naming the cert-manager Secrets that row consumes. `Keys` is never rendered as
# a column; it is what the usage report joins on. An empty `Keys` means the row
# consumes no Secret the tool can attribute to a Certificate.

# Resources in the workload plane that reference a cert-manager Secret:
# Pod volumes (secret, projected, cert-manager CSI), Pod env, Ingress TLS, and
# Argo Events EventBus JetStream TLS.
def collect_workload_consumers [r: record, w: record] {
    let cert_names    = (cert_name_index $r.certs)
    let cert_subjects = (cert_subject_index $r.certs)
    let pods          = (try { $w.pods } catch { [] } | default [])
    let ingresses     = (try { $w.ingresses } catch { [] } | default [])
    let eventbuses    = (try { $w.eventbuses } catch { [] } | default [])

    # Pods: secret and projected-secret volumes referencing cert-managed secrets
    let secret_vol_rows = (
        $pods
        | each { |pod|
            let ns   = $pod.metadata.namespace
            let vols = (try { $pod.spec.volumes } catch { [] } | default [])
            let direct = (
                $vols
                | each { |v|
                    let n = (try { $v.secret.secretName } catch { "" })
                    if ($n | is-empty) { [] } else { [{ name: $n, via: "secret-vol" }] }
                }
                | flatten
            )
            let projected = (
                $vols
                | each { |v|
                    (try { $v.projected.sources } catch { [] } | default [])
                    | each { |s|
                        let n = (try { $s.secret.name } catch { "" })
                        if ($n | is-empty) { [] } else { [{ name: $n, via: "projected-vol" }] }
                    }
                    | flatten
                }
                | flatten
            )
            ([$direct $projected] | flatten)
            | where { |x| (secret_key $ns $x.name) in $cert_names }
            | each { |x|
                let key = (secret_key $ns $x.name)
                {
                    Namespace: $ns
                    Kind:      "Pod"
                    Name:      $pod.metadata.name
                    Subject:   (rget $cert_subjects $key)
                    Ref:       $x.name
                    Cert:      (rget $cert_names $key)
                    Via:       $x.via
                    Keys:      [$key]
                }
            }
        }
        | flatten
        | uniq
    )

    # Pods: env and envFrom references to cert-managed secrets
    let env_rows = (
        $pods
        | each { |pod|
            let ns = $pod.metadata.namespace
            let containers = ([
                (try { $pod.spec.containers } catch { [] } | default [])
                (try { $pod.spec.initContainers } catch { [] } | default [])
            ] | flatten)
            $containers
            | each { |ct|
                let from_env = (
                    (try { $ct.env } catch { [] } | default [])
                    | each { |e|
                        let n = (try { $e.valueFrom.secretKeyRef.name } catch { "" })
                        if ($n | is-empty) { [] } else { [{ name: $n, via: "env-secretKeyRef" }] }
                    }
                    | flatten
                )
                let from_envfrom = (
                    (try { $ct.envFrom } catch { [] } | default [])
                    | each { |e|
                        let n = (try { $e.secretRef.name } catch { "" })
                        if ($n | is-empty) { [] } else { [{ name: $n, via: "env-envFrom" }] }
                    }
                    | flatten
                )
                ([$from_env $from_envfrom] | flatten)
                | where { |x| (secret_key $ns $x.name) in $cert_names }
                | each { |x|
                    let key = (secret_key $ns $x.name)
                    {
                        Namespace: $ns
                        Kind:      "Pod"
                        Name:      $pod.metadata.name
                        Subject:   (rget $cert_subjects $key)
                        Ref:       $x.name
                        Cert:      (rget $cert_names $key)
                        Via:       $x.via
                        Keys:      [$key]
                    }
                }
            }
            | flatten
        }
        | flatten
        | uniq
    )

    # Pods: cert-manager CSI driver volumes. These mint a certificate into the
    # Pod directly, so they reference no Secret and carry no Keys.
    let csi_vol_rows = (
        $pods
        | each { |pod|
            let ns   = $pod.metadata.namespace
            let vols = (try { $pod.spec.volumes } catch { [] } | default [])
            $vols
            | where { |v| "csi" in $v and (try { $v.csi.driver } catch { "" }) == "csi.cert-manager.io" }
            | each { |v|
                let attrs = (try { $v.csi.volumeAttributes } catch { {} } | default {})
                let iname = (rget $attrs "csi.cert-manager.io/issuer-name")
                let ikind = (rget $attrs "csi.cert-manager.io/issuer-kind")
                let dns   = (rget $attrs "csi.cert-manager.io/dns-names")
                let cn    = (rget $attrs "csi.cert-manager.io/common-name")
                {
                    Namespace: $ns
                    Kind:      "Pod"
                    Name:      $pod.metadata.name
                    Subject:   (if ($cn | is-empty) { "(no subject)" } else { $"CN=($cn)" })
                    Ref:       (if ($dns | is-empty) { "(none)" } else { $dns })
                    Cert:      $"(if ($ikind | is-empty) { 'Issuer' } else { $ikind })/($iname)"
                    Via:       "csi-vol"
                    Keys:      []
                }
            }
        }
        | flatten
    )

    # Ingresses: cert-manager annotations
    let ingress_rows = (
        $ingresses
        | where { |i|
            let keys = (try { $i.metadata.annotations | columns } catch { [] } | default [])
            $keys | any { |k| $k | str starts-with "cert-manager.io/" }
        }
        | each { |i|
            let ann  = (try { $i.metadata.annotations } catch { {} } | default {})
            let keys = ($ann | columns)
            let ns   = $i.metadata.namespace
            let issuer = if "cert-manager.io/cluster-issuer" in $keys {
                $"ClusterIssuer/(rget $ann 'cert-manager.io/cluster-issuer')"
            } else if "cert-manager.io/issuer" in $keys {
                $"Issuer/(rget $ann 'cert-manager.io/issuer')"
            } else {
                ""
            }
            let cert_name   = (rget $ann "cert-manager.io/certificate-name")
            let tls_names = (
                (try { $i.spec.tls } catch { [] } | default [])
                | each { |t| $t.secretName? | default "" }
                | where { |s| not ($s | is-empty) }
            )
            let tls_secrets = ($tls_names | str join ", ")
            let matched = ($tls_names | where { |s| (secret_key $ns $s) in $cert_names })
            {
                Namespace: $ns
                Kind:      "Ingress"
                Name:      $i.metadata.name
                Subject:   (if ($matched | is-empty) { "(no Certificate manages this Secret)" } else { rget $cert_subjects (secret_key $ns ($matched | first)) })
                Ref:       $tls_secrets
                Cert:      (if ($cert_name | is-empty) { $issuer } else { $cert_name })
                Via:       "cm-annotation"
                Keys:      ($matched | each { |s| secret_key $ns $s })
            }
        }
    )

    # Argo Events EventBus: JetStream client/CA material referenced by Secret
    # name. These are the resources that declare WHY the generated EventSource
    # and Sensor Deployments mount a cert Secret at all.
    let eventbus_rows = (
        $eventbuses
        | each { |eb|
            let ns  = $eb.metadata.namespace
            let tls = (try { $eb.spec.jetstreamExotic.tls } catch { {} } | default {})
            let fields = [
                { field: "caCertSecret",     label: "caCert" }
                { field: "clientCertSecret", label: "clientCert" }
                { field: "clientKeySecret",  label: "clientKey" }
            ]
            let refs = ($fields | each { |f|
                let n = (try { $tls | get $f.field | get name } catch { "" })
                if ($n | is-empty) { [] } else { [{ name: $n, label: $f.label }] }
            } | flatten)
            $refs
            | each { |x| $x.name }
            | uniq
            | each { |n|
                let key    = (secret_key $ns $n)
                let labels = ($refs | where name == $n | each { |x| $x.label } | str join ",")
                let known  = ($key in $cert_names)
                {
                    Namespace: $ns
                    Kind:      "EventBus"
                    Name:      $eb.metadata.name
                    Subject:   (if $known { rget $cert_subjects $key } else { "(no Certificate manages this Secret)" })
                    Ref:       $n
                    Cert:      (if $known { rget $cert_names $key } else { "" })
                    Via:       $"eventbus-tls\(($labels)\)"
                    Keys:      (if $known { [$key] } else { [] })
                }
            }
        }
        | flatten
    )

    [$secret_vol_rows $env_rows $csi_vol_rows $ingress_rows $eventbus_rows] | flatten
}

# Resources in the PKI control plane that reference a cert-manager Secret:
# Issuer / ClusterIssuer CA backing and trust-manager Bundle sources. These are
# why an intermediate CA is in use even when no Pod ever mounts it.
def collect_pki_consumers [r: record, w: record] {
    let cert_names    = (cert_name_index $r.certs)
    let cert_subjects = (cert_subject_index $r.certs)
    let bundles       = (try { $w.bundles } catch { [] } | default [])

    # ClusterIssuers resolve their CA Secret in cert-manager's cluster resource
    # namespace, which this tool does not read. Match on Secret name across all
    # namespaces, mirroring `build_chain`.
    let ci_rows = (
        $r.cluster_issuers
        | where { |ci| "ca" in $ci.spec }
        | each { |ci|
            let sn   = ($ci.spec.ca.secretName? | default "")
            let keys = (
                $r.certs
                | where { |c| ($c.spec.secretName? | default "") == $sn }
                | each { |c| secret_key $c.metadata.namespace $sn }
            )
            {
                Namespace: "(cluster)"
                Kind:      "ClusterIssuer"
                Name:      $ci.metadata.name
                Subject:   (if ($keys | is-empty) { "(no Certificate manages this Secret)" } else { rget $cert_subjects ($keys | first) })
                Ref:       $sn
                Cert:      (if ($keys | is-empty) { "" } else { rget $cert_names ($keys | first) })
                Via:       "issuer-ca"
                Keys:      $keys
            }
        }
    )

    let issuer_rows = (
        $r.issuers
        | where { |i| "ca" in $i.spec }
        | each { |i|
            let ns    = $i.metadata.namespace
            let sn    = ($i.spec.ca.secretName? | default "")
            let key   = (secret_key $ns $sn)
            let known = ($key in $cert_names)
            {
                Namespace: $ns
                Kind:      "Issuer"
                Name:      $i.metadata.name
                Subject:   (if $known { rget $cert_subjects $key } else { "(no Certificate manages this Secret)" })
                Ref:       $sn
                Cert:      (if $known { rget $cert_names $key } else { "" })
                Via:       "issuer-ca"
                Keys:      (if $known { [$key] } else { [] })
            }
        }
    )

    # trust-manager Bundles distribute a CA from a Secret source. Selector-based
    # sources name no Secret and are not resolvable here.
    let bundle_rows = (
        $bundles
        | each { |b|
            let ns = ($b.metadata.namespace? | default "(cluster)")
            (try { $b.spec.sources } catch { [] } | default [])
            | each { |s|
                let n = (try { $s.secret.name } catch { "" })
                if ($n | is-empty) { [] } else { [$n] }
            }
            | flatten
            | uniq
            | each { |n|
                let keys = (
                    $r.certs
                    | where { |c| ($c.spec.secretName? | default "") == $n }
                    | each { |c| secret_key $c.metadata.namespace $n }
                )
                {
                    Namespace: $ns
                    Kind:      "Bundle"
                    Name:      $b.metadata.name
                    Subject:   (if ($keys | is-empty) { "(no Certificate manages this Secret)" } else { rget $cert_subjects ($keys | first) })
                    Ref:       $n
                    Cert:      (if ($keys | is-empty) { "" } else { rget $cert_names ($keys | first) })
                    Via:       "bundle-source"
                    Keys:      $keys
                }
            }
        }
        | flatten
    )

    [$ci_rows $issuer_rows $bundle_rows] | flatten
}
