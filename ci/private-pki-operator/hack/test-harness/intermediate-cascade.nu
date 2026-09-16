#!/usr/bin/env nu
# Scenario 2: Independent intermediate CA cascade.
# Deletes one intermediate CA Secret to simulate cert-manager independently renewing it.
# Proves:
#   - Parent (platform-root-ca) stays Idle throughout
#   - Child IntermediateCA CR drives the cascade state machine:
#     AwaitingReissuance → VerifyingChain → Complete → Idle
#   - ChainVerified=True on completion; SKID updated
#
# Note: the cascade may complete faster than polling intervals, so we assert
# the final state (Idle + ChainVerified=True + new SKID) rather than trying
# to catch every intermediate phase transition.

use lib.nu *

# chaos-mesh-ca — isolated namespace, fewest downstream certs.
const TEST_NS   = "chaos-mesh"
const TEST_CERT = "chaos-mesh-ca"
const TEST_PKIR = "platform-root-ca-f05c2fbd"

export def main [] {
    print_header "Scenario 2: Independent Intermediate Cascade"

    assert_phase $ROOT_PKIR "Idle"

    run_intermediate_cascade $TEST_PKIR $TEST_NS $TEST_CERT

    assert_phase $ROOT_PKIR "Idle"

    print "\nScenario 2: PASS ✓"
}
