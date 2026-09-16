#!/usr/bin/env nu
# main.nu — cert-manager PKI inspector
#
# Fetches from the currently selected kubectl context (read-only),
# caches raw data to .tmp/, and generates one markdown report per view.
#
# Usage:
#   nu hack/pki-status/main.nu              # use cache if fresh
#   nu hack/pki-status/main.nu --refresh    # force re-fetch

source ./lib/helpers.nu
source ./reports/report-issuers.nu
source ./reports/report-certs.nu
source ./reports/report-leaves.nu
source ./reports/report-workloads.nu
source ./reports/report-usage.nu
source ./reports/report-readme.nu

const CACHE_MAX_AGE_HOURS = 24

# ── Cache helpers ─────────────────────────────────────────────────────────────

def get_cache_dir [] {
    $env.CURRENT_FILE | path dirname | path join ".tmp"
}

def get_pki_file [] {
    get_cache_dir | path join "pki.json"
}

def get_workloads_file [] {
    get_cache_dir | path join "workloads.json"
}

def get_metadata_file [] {
    get_cache_dir | path join "metadata.json"
}

def cache_is_fresh [] {
    let f = (get_pki_file)
    if not ($f | path exists) { return false }
    if not ((get_workloads_file) | path exists) { return false }
    # A cache written by an older revision has no eventbuses/bundles collections.
    # Treat it as stale rather than silently reporting those consumers as absent.
    let cols = (try { open (get_workloads_file) | columns } catch { [] } | default [])
    if not ("eventbuses" in $cols and "bundles" in $cols) { return false }
    let age_hours = (
        (date now | into int) - (ls -l $f | first | get modified | into int)
    ) / 1_000_000_000 / 3600
    $age_hours < $CACHE_MAX_AGE_HOURS
}

# ── Fetch and cache ───────────────────────────────────────────────────────────

def fetch_and_cache [] {
    let ctx = (kubectl config current-context | str trim)
    print $"(ansi cyan)Fetching PKI resources from context: (ansi yellow)($ctx)(ansi reset)"

    let certs = try {
        kubectl get certificates --all-namespaces -o json | from json | get items? | default []
    } catch { print $"(ansi yellow)  certificates: none or unavailable(ansi reset)"; [] }

    let cluster_issuers = try {
        kubectl get clusterissuers -o json | from json | get items? | default []
    } catch { print $"(ansi yellow)  clusterissuers: none or unavailable(ansi reset)"; [] }

    let issuers = try {
        kubectl get issuers --all-namespaces -o json | from json | get items? | default []
    } catch { print $"(ansi yellow)  issuers: none or unavailable(ansi reset)"; [] }

    let pods = try {
        kubectl get pods --all-namespaces -o json | from json | get items? | default []
    } catch { print $"(ansi yellow)  pods: none or unavailable(ansi reset)"; [] }

    let ingresses = try {
        kubectl get ingresses --all-namespaces -o json | from json | get items? | default []
    } catch { print $"(ansi yellow)  ingresses: none or unavailable(ansi reset)"; [] }

    # Argo Events and trust-manager are optional. Their CRDs are absent on plenty
    # of clusters; kubectl exits non-zero and the catch degrades to an empty list.
    let eventbuses = try {
        kubectl get eventbus.argoproj.io --all-namespaces -o json | from json | get items? | default []
    } catch { print $"(ansi yellow)  eventbus: none or unavailable \(Argo Events not installed?\)(ansi reset)"; [] }

    let bundles = try {
        kubectl get bundles.trust.cert-manager.io -o json | from json | get items? | default []
    } catch { print $"(ansi yellow)  bundles: none or unavailable \(trust-manager not installed?\)(ansi reset)"; [] }

    let pki       = { certs: $certs, cluster_issuers: $cluster_issuers, issuers: $issuers }
    let workloads = { pods: $pods, ingresses: $ingresses, eventbuses: $eventbuses, bundles: $bundles }

    mkdir (get_cache_dir)
    $pki       | to json | save -f (get_pki_file)
    $workloads | to json | save -f (get_workloads_file)
    {
        created: (date now | format date "%Y-%m-%d %H:%M:%S"),
        context: $ctx
    } | to json | save -f (get_metadata_file)

    print $"(ansi green)Cache written to: (get_cache_dir)(ansi reset)"

    { pki: $pki, workloads: $workloads, context: $ctx }
}

# ── Main ──────────────────────────────────────────────────────────────────────

def main [--refresh (-r)] {
    mkdir (get_cache_dir)

    # Resolve data — from cache or fresh fetch
    let data = if $refresh or not (cache_is_fresh) {
        if $refresh {
            print $"(ansi yellow)Forcing cache refresh...(ansi reset)"
        } else {
            print $"(ansi yellow)Cache stale or missing. Fetching...(ansi reset)"
        }
        print ""
        fetch_and_cache
    } else {
        let meta = (open (get_metadata_file))
        print $"(ansi cyan)Using cache from: ($meta.created) · context: ($meta.context)(ansi reset)"
        {
            pki:       (open (get_pki_file)),
            workloads: (open (get_workloads_file)),
            context:   $meta.context
        }
    }

    let scanned = $"(date now | format date '%Y-%m-%d %H:%M:%S') · context: ($data.context)"
    let cache   = (get_cache_dir)

    # Generate reports
    print ""
    let report_issuers   = ($cache | path join "issuers.md")
    let report_certs     = ($cache | path join "certs.md")
    let report_leaves    = ($cache | path join "leaves.md")
    let report_workloads = ($cache | path join "workloads.md")
    let report_usage     = ($cache | path join "usage.md")
    let report_summary   = ($cache | path join "README.md")

    write_issuers_report   $data.pki $report_issuers   $scanned
    write_certs_report     $data.pki $report_certs      $scanned
    write_leaves_report    $data.pki $report_leaves     $scanned
    write_workloads_report $data.pki $data.workloads $report_workloads $scanned
    write_usage_report     $data.pki $data.workloads $report_usage     $scanned

    # README / summary report
    write_readme_report $data.pki $data.workloads $report_summary $scanned

    # List generated files
    print $"(ansi white_bold)Generated reports:(ansi reset)"
    for f in [$report_summary $report_issuers $report_certs $report_leaves $report_workloads $report_usage] {
        let size = (ls -l $f | first | get size)
        print $"  ($f)  (ansi dark_gray)($size)(ansi reset)"
    }
}
