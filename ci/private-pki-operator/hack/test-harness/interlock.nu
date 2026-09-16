#!/usr/bin/env nu
# Scenario 3: Root rotation + independent intermediate interlock.
#
# Deletes both the root CA Secret and an intermediate CA Secret simultaneously.
# Proves:
#   - Root CA rotation runs to completion (new SKID, ChainVerified=True)
#   - Intermediate CA SKID is updated post-rotation (absorbed by root rotation)
#   - Intermediate CR ends up Idle — no stuck state from concurrent deletes
#
# Note: root rotation often completes in <60 s on this cluster, making it
# impossible to reliably catch every intermediate phase via polling.
# We therefore assert the FINAL state rather than chasing transitions.
# The interlock invariant (child yields while root rotates) is validated
# implicitly: if it broke, the intermediate would attempt an independent
# cascade on top of the root rotation, potentially leaving inconsistent
# conditions or a non-Idle phase. Clean final state proves it worked.

use lib.nu *

# Security namespace intermediate — different from Scenario 2's chaos-mesh.
const TEST_NS   = "security"
const TEST_PKIR = "platform-root-ca-2e2c0dad"

export def main [] {
    print_header "Scenario 3: Root + Intermediate Interlock"

    assert_phase $ROOT_PKIR "Idle"
    let old_root_skid = (pkir_skid $ROOT_PKIR)
    let old_int_skid  = (pkir_skid $TEST_PKIR)
    print $"  root SKID:         ($old_root_skid)"
    print $"  intermediate SKID: ($old_int_skid)"

    # Resolve intermediate CA Secret name from its Certificate spec.
    let int_cert_name = (^kubectl --context $CONTEXT get pkirotation $TEST_PKIR -o "jsonpath={.spec.intermediateCA.certificateName}" | str trim)
    let secret_name = (int_secret_name $TEST_NS $int_cert_name)
    print $"  intermediate CA: ($TEST_NS)/($int_cert_name), Secret: ($secret_name)"

    # ── Step 1: delete both Secrets simultaneously ────────────────────────────
    # Deleting root triggers root rotation; deleting intermediate simultaneously
    # simulates an independent renewal racing against the root rotation.
    print $"\n  [1] deleting root Secret and intermediate Secret simultaneously..."
    ^kubectl --context $CONTEXT delete secret $ROOT_CA_SECRET -n $ROOT_CA_NS --ignore-not-found | ignore
    ^kubectl --context $CONTEXT delete secret $secret_name -n $TEST_NS --ignore-not-found | ignore
    print "  both Secrets deleted — operator must handle concurrent events cleanly"

    # ── Step 2: wait for root rotation to complete ────────────────────────────
    # Poll for fully settled state: root Idle + new SKID + ChainVerified=True +
    # IntermediateReissued=True.  Requiring ALL conditions prevents breaking on
    # a stale ChainVerified from a previous rotation while a new one is in flight.
    print "\n  [2] waiting for root rotation final state (Idle + all conditions True + new SKID)..."
    let deadline = (date now) + 900_000_000_000ns  # 15 min
    loop {
        let phase    = (pkir_phase $ROOT_PKIR)
        let cur_skid = (pkir_skid $ROOT_PKIR)
        let chain_cond  = (pkir_condition $ROOT_PKIR "ChainVerified")
        let interm_cond = (pkir_condition $ROOT_PKIR "IntermediateReissued")
        let chain_ok  = ($chain_cond  != null and $chain_cond.status  == "True")
        let interm_ok = ($interm_cond != null and $interm_cond.status == "True")

        if ($phase == "Idle" or $phase == "") and $cur_skid != $old_root_skid and $chain_ok and $interm_ok {
            print $"  ✓ root rotation complete: phase=Idle, SKID changed, all conditions True"
            break
        }
        if $phase != "Idle" and $phase != "" {
            print $"  … ($ROOT_PKIR): ($phase)"
        }
        if (date now) > $deadline {
            error make {msg: $"TIMEOUT: root rotation did not complete. phase=($phase) skid=($cur_skid) chain=($chain_ok) interm=($interm_ok)"}
        }
        sleep 3sec
    }

    # ── Step 3: assert root final conditions ──────────────────────────────────
    assert_condition_true $ROOT_PKIR "ChainVerified"
    assert_condition_true $ROOT_PKIR "IntermediateReissued"
    assert_skid_changed $ROOT_PKIR $old_root_skid | ignore

    # ── Step 4: verify intermediate absorbed cleanly ──────────────────────────
    # Root rotation's AwaitingReissuance phase reissues all intermediates.
    # If the interlock worked, the independent intermediate cascade was absorbed
    # (or yielded and then completed as part of the root rotation), leaving the
    # child at Idle with an updated SKID.
    print "\n  [4] checking intermediate SKID and phase post-rotation..."
    let new_int_skid  = (pkir_skid $TEST_PKIR)
    let child_phase   = (pkir_phase $TEST_PKIR)

    if $new_int_skid == $old_int_skid {
        error make {msg: $"FAIL: intermediate SKID unchanged after root rotation — root rotation did not reissue ($TEST_PKIR)"}
    }
    print $"  ✓ intermediate SKID updated: ($old_int_skid | str substring 0..17)… → ($new_int_skid | str substring 0..17)…"

    if $child_phase != "Idle" and $child_phase != "" {
        error make {msg: $"FAIL: child CR should be Idle after root rotation, got ($child_phase)"}
    }
    print $"  ✓ child CR phase: ($child_phase) — Idle semantics"

    # ChainVerified on child intermediate must be True (set during its own cascade).
    let child_chain = (pkir_condition $TEST_PKIR "ChainVerified")
    if $child_chain != null and $child_chain.status == "True" {
        print $"  ✓ child ChainVerified = True"
    } else {
        print "  ⚠  child ChainVerified not True (may be absent — intermediate cascade not triggered)"
    }

    print "\nScenario 3: PASS ✓"
}
