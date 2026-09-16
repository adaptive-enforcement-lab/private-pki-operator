# Shared helpers for the PKI operator in-cluster test harness.
#
# CONTEXT is a plain kubectl context name only — these scripts don't pass
# --kubeconfig. If your cluster's context lives in a separate kubeconfig file
# (e.g. homelab's ~/.kube/homelab.yaml), merge/import it or add --kubeconfig
# to the `^kubectl --context $CONTEXT` call sites in this directory.

export const CONTEXT = "<set-me>"
export const ROOT_PKIR = "platform-root-ca"
export const ROOT_CA_SECRET = "private-root-ca"
export const ROOT_CA_NS = "cert-manager"

# ─── kubectl wrappers ────────────────────────────────────────────────────────

# Get PKIRotation status.phase (empty string if unset).
export def pkir_phase [name: string] {
    ^kubectl --context $CONTEXT get pkirotation $name -o "jsonpath={.status.phase}" | str trim
}

# Get PKIRotation status.currentSKID.
export def pkir_skid [name: string] {
    ^kubectl --context $CONTEXT get pkirotation $name -o "jsonpath={.status.currentSKID}" | str trim
}

# Get all PKIRotation CRs as structured records.
export def pkir_list [] {
    ^kubectl --context $CONTEXT get pkirotation -o json | from json | get items | each {|it| {
        name:     $it.metadata.name,
        role:     ($it.spec.role? | default "RootCA"),
        phase:    ($it.status?.phase? | default ""),
        skid:     ($it.status?.currentSKID? | default ""),
        int_ns:   ($it.spec.intermediateCA?.certificateNamespace? | default ""),
        int_cert: ($it.spec.intermediateCA?.certificateName? | default ""),
    }}
}

# Get a specific condition from a PKIRotation status.
export def pkir_condition [name: string, ctype: string] {
    let conditions = (^kubectl --context $CONTEXT get pkirotation $name -o json | from json | get status.conditions? | default [])
    $conditions | where type == $ctype | get 0?
}

# Get the Secret name for an intermediate CA Certificate.
export def int_secret_name [ns: string, cert_name: string] {
    ^kubectl --context $CONTEXT get certificate $cert_name -n $ns -o "jsonpath={.spec.secretName}" | str trim
}

# ─── assertions ──────────────────────────────────────────────────────────────

export def assert_phase [name: string, expected: string] {
    let got = (pkir_phase $name)
    if $got != $expected {
        error make {msg: $"FAIL: ($name) expected phase=($expected) got=($got)"}
    }
    print $"  ✓ ($name): phase=($got)"
}

export def assert_condition_true [name: string, ctype: string] {
    let c = (pkir_condition $name $ctype)
    if $c == null {
        error make {msg: $"FAIL: ($name) condition ($ctype) not found"}
    }
    if $c.status != "True" {
        error make {msg: $"FAIL: ($name) ($ctype)=($c.status): ($c.message?)"}
    }
    print $"  ✓ ($name).($ctype) = True"
}

export def assert_skid_changed [name: string, old_skid: string] {
    let new_skid = (pkir_skid $name)
    if $new_skid == $old_skid {
        error make {msg: $"FAIL: ($name) SKID unchanged after rotation: ($old_skid)"}
    }
    print $"  ✓ ($name) SKID rotated"
    $new_skid
}

# ─── polling ─────────────────────────────────────────────────────────────────

# Wait for a root CA rotation to complete: SKID must change from old_skid and
# phase must return to Idle. Handles rotations that complete faster than the
# 3-second poll interval (individual phases may be sub-second and unobservable).
export def wait_rotation_complete [name: string, old_skid: string, timeout_sec: int = 600] {
    let deadline = (date now) + (($timeout_sec * 1_000_000_000) | into duration)
    loop {
        let phase = (pkir_phase $name)
        let skid  = (pkir_skid $name)
        if ($phase == "Idle" or $phase == "") and $skid != $old_skid {
            print $"  ✓ ($name) rotation complete: Idle, SKID changed (($skid))"
            return
        }
        if $phase != "Idle" and $phase != "" {
            print $"  … ($name): ($phase)"
        }
        if (date now) > $deadline {
            error make {msg: $"TIMEOUT ($timeout_sec)s: ($name) rotation did not complete. phase=($phase) skid=($skid) expected SKID != ($old_skid)"}
        }
        sleep 3sec
    }
}

# Wait for a PKIRotation to reach expected phase within timeout_sec seconds.
export def wait_phase [name: string, expected: string, timeout_sec: int = 600] {
    let deadline = (date now) + (($timeout_sec * 1_000_000_000) | into duration)
    loop {
        let phase = (pkir_phase $name)
        if $phase == $expected {
            print $"  ✓ ($name) → ($phase)"
            return
        }
        if (date now) > $deadline {
            error make {msg: $"TIMEOUT ($timeout_sec)s: ($name) waiting for ($expected), currently ($phase)"}
        }
        sleep 3sec
    }
}

# For duration_sec seconds, assert a PKIRotation stays in expected phase (or empty).
# Raises immediately if it leaves.
export def assert_stays_phase [name: string, expected: string, duration_sec: int] {
    let deadline = (date now) + (($duration_sec * 1_000_000_000) | into duration)
    loop {
        let phase = (pkir_phase $name)
        if $phase != $expected and $phase != "" {
            error make {msg: $"FAIL (interlock): ($name) left ($expected) → ($phase) while root was rotating"}
        }
        if (date now) > $deadline { return }
        sleep 3sec
    }
}

# ─── intermediate cascade helper ─────────────────────────────────────────────

# Run the full intermediate CA cascade for one IntermediateCA PKIRotation CR:
#   1. Record old SKID
#   2. Delete the intermediate CA Secret (triggers cert-manager reissuance)
#   3. Wait for cascade completion: Idle + ChainVerified=True + new SKID
#   4. Assert final conditions
#
# Parameters:
#   pkir_name  — name of the IntermediateCA PKIRotation CR
#   int_ns     — namespace containing the intermediate CA Certificate
#   int_cert   — name of the intermediate CA Certificate
#   timeout_ns — (optional) deadline duration in nanoseconds (default: 600s)
export def run_intermediate_cascade [
    pkir_name: string,
    int_ns: string,
    int_cert: string,
    timeout_ns: int = 600_000_000_000
] {
    print $"  ── ($pkir_name) ──────────────────────────────────────────"
    let old_skid = (pkir_skid $pkir_name)
    print $"  SKID before: ($old_skid)"

    let secret_name = (int_secret_name $int_ns $int_cert)
    print $"  deleting ($int_ns)/($secret_name) — cert-manager will reissue..."
    ^kubectl --context $CONTEXT delete secret $secret_name -n $int_ns --ignore-not-found | ignore

    let deadline = (date now) + ($timeout_ns | into duration)
    loop {
        let phase     = (pkir_phase $pkir_name)
        let cur_skid  = (pkir_skid $pkir_name)
        let chain_cond = (pkir_condition $pkir_name "ChainVerified")
        let chain_ok  = ($chain_cond != null and $chain_cond.status == "True")

        if ($phase == "Idle" or $phase == "") and $cur_skid != $old_skid and $chain_ok {
            print $"  ✓ cascade complete: Idle, SKID changed, ChainVerified=True"
            break
        }
        if $phase != "Idle" and $phase != "" {
            print $"  … ($pkir_name): ($phase)"
        }
        if (date now) > $deadline {
            error make {msg: $"TIMEOUT: ($pkir_name) cascade did not complete. phase=($phase) skid=($cur_skid) chain_ok=($chain_ok)"}
        }
        sleep 3sec
    }

    assert_condition_true $pkir_name "ChainVerified"
    assert_skid_changed $pkir_name $old_skid | ignore
    print $"  ✓ ($pkir_name): cascade verified"
}

# ─── formatting ──────────────────────────────────────────────────────────────

export def print_header [title: string] {
    let bar = "════════════════════════════════════════════════════════════════"
    print $"\n($bar)\n  ($title)\n($bar)"
}
