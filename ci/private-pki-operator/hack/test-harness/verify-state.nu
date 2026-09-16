#!/usr/bin/env nu
# Scenario 0: Verify clean baseline state before running destructive tests.

use lib.nu *

export def main [] {
    print_header "Scenario 0: Verify Clean State"

    # Root must be Idle.
    assert_phase $ROOT_PKIR "Idle"

    # Operator pod must be running.
    let running = (
        ^kubectl --context $CONTEXT get pods -n $ROOT_CA_NS
            -l "app.kubernetes.io/name=private-pki-operator"
            -o "jsonpath={.items[*].status.phase}"
        | split row " "
        | where {|p| $p == "Running"}
        | length
    )
    if $running == 0 {
        error make {msg: "FAIL: private-pki-operator pod not Running"}
    }
    print $"  ✓ operator: ($running) pods Running"

    # All IntermediateCA CRs must have SKIDs bootstrapped.
    let children = (pkir_list | where role == "IntermediateCA")
    if ($children | length) == 0 {
        error make {msg: "FAIL: no IntermediateCA PKIRotation CRs found — run root rotation first"}
    }
    for c in $children {
        if $c.skid == "" {
            error make {msg: $"FAIL: ($c.name) has no currentSKID"}
        }
        let phase_note = if $c.phase == "" { " (phase empty — Idle semantics)" } else { "" }
        print $"  ✓ ($c.name) skid=($c.skid | str substring 0..17)…($phase_note)"
    }

    print "\nScenario 0: PASS ✓"
}
