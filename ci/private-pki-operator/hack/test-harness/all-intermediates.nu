#!/usr/bin/env nu
# Scenario 4: All individual intermediate CA cascades.
#
# Discovers every IntermediateCA PKIRotation CR at runtime and triggers a full
# cascade for each one sequentially:
#   - Deletes the intermediate CA Secret (cert-manager reissues it)
#   - Waits for the operator to complete the cascade state machine:
#     AwaitingReissuance → VerifyingChain → Complete → Idle
#   - Asserts ChainVerified=True and SKID updated for each
#
# This proves the cascade controller functionality works end-to-end in cluster
# for every managed intermediate CA, not just chaos-mesh.
#
# Root CA must be Idle before and after each cascade.

use lib.nu *

export def main [] {
    print_header "Scenario 4: All Individual Intermediate CA Cascades"

    assert_phase $ROOT_PKIR "Idle"

    let intermediates = (pkir_list | where role == "IntermediateCA")
    if ($intermediates | length) == 0 {
        error make {msg: "FAIL: no IntermediateCA PKIRotation CRs found — operator may not have bootstrapped them yet"}
    }
    let count = ($intermediates | length)
    print $"  found ($count) intermediate CAs to test\n"

    for it in $intermediates {
        if $it.int_ns == "" or $it.int_cert == "" {
            print $"  ⚠  ($it.name): missing intermediateCA spec — skipping"
            continue
        }

        run_intermediate_cascade $it.name $it.int_ns $it.int_cert

        # Root must remain Idle after each individual cascade.
        let root_phase = (pkir_phase $ROOT_PKIR)
        if $root_phase != "Idle" and $root_phase != "" {
            error make {msg: $"FAIL: root CA left Idle after cascade of ($it.name): phase=($root_phase)"}
        }
        print $"  ✓ root still Idle\n"
    }

    print "Scenario 4: PASS ✓"
}
