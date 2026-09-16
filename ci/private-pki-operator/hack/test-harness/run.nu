#!/usr/bin/env nu
# PKI Operator In-Cluster Test Harness
#
# Usage:
#   nu run.nu                      # run all scenarios
#   nu run.nu --scenario 0         # verify-state only (non-destructive)
#   nu run.nu --scenario 1         # root CA rotation
#   nu run.nu --scenario 2         # independent intermediate cascade (chaos-mesh)
#   nu run.nu --scenario 3         # root + intermediate interlock (triggers root rotation)
#   nu run.nu --scenario 4         # all individual intermediate CA cascades

use lib.nu *

def run_scenario [id: int, label: string, script: string] {
    print $"\n━━━ Running Scenario ($id): ($label) ━━━"
    let result = do { nu $script } | complete
    if $result.exit_code == 0 {
        print $"✓ Scenario ($id) PASSED"
        {id: $id, label: $label, result: "PASS"}
    } else {
        print $"✗ Scenario ($id) FAILED"
        print $result.stderr
        {id: $id, label: $label, result: "FAIL"}
    }
}

def main [--scenario: int = -1] {
    let harness_dir = ($env.CURRENT_FILE | path dirname)

    print "═══════════════════════════════════════════════════════════════"
    print "  PKI Operator In-Cluster Test Harness"
    print $"  Context: ($CONTEXT)"
    print $"  Time:    (date now | format date '%Y-%m-%dT%H:%M:%SZ')"
    print "═══════════════════════════════════════════════════════════════"

    let all = $scenario == -1
    mut results = []

    if $all or $scenario == 0 {
        $results = ($results | append (run_scenario 0 "Verify Clean State" ($harness_dir | path join "verify-state.nu")))
    }
    if $all or $scenario == 1 {
        $results = ($results | append (run_scenario 1 "Root CA Rotation" ($harness_dir | path join "root-rotation.nu")))
    }
    if $all or $scenario == 2 {
        if $all { run_scenario 0 "Re-verify State" ($harness_dir | path join "verify-state.nu") | ignore }
        $results = ($results | append (run_scenario 2 "Independent Intermediate Cascade" ($harness_dir | path join "intermediate-cascade.nu")))
    }
    if $all or $scenario == 3 {
        if $all { run_scenario 0 "Re-verify State" ($harness_dir | path join "verify-state.nu") | ignore }
        $results = ($results | append (run_scenario 3 "Root + Intermediate Interlock" ($harness_dir | path join "interlock.nu")))
    }
    if $all or $scenario == 4 {
        if $all { run_scenario 0 "Re-verify State" ($harness_dir | path join "verify-state.nu") | ignore }
        $results = ($results | append (run_scenario 4 "All Individual Intermediate Cascades" ($harness_dir | path join "all-intermediates.nu")))
    }

    let passed = ($results | where result == "PASS" | length)
    let failed = ($results | where result == "FAIL" | length)

    print "\n═══════════════════════════════════════════════════════════════"
    print $"  Results: ($passed) passed, ($failed) failed"
    for r in $results {
        let icon = if $r.result == "PASS" { "✓" } else { "✗" }
        print $"  ($icon) Scenario ($r.id): ($r.label)"
    }
    print "═══════════════════════════════════════════════════════════════"

    if $failed > 0 { exit 1 }
}
