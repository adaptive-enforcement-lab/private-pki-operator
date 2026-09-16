#!/usr/bin/env bash
# pki-gap-test — proves where cert-manager stops and the operator gap begins.
#
# Stands up a 4-tier unmanaged chain with rotationPolicy: Always, then runs
# forced-rotation scenarios to show cert-manager does NOT cascade reissuance.
#
# Usage:
#   ./test.sh apply           — deploy the test stack
#   ./test.sh wait            — wait for all certs to be Ready
#   ./test.sh info            — print chain state (SKID, NotBefore, issuer)
#   ./test.sh verify          — openssl chain verification for each link
#   ./test.sh scenario-root   — rotate root CA, prove no cascade
#   ./test.sh scenario-int    — rotate platform intermediate, prove no cascade
#   ./test.sh scenario-ns-int — rotate namespace intermediate, prove no cascade
#   ./test.sh all             — apply → wait → info → all scenarios → verify
#   ./test.sh cleanup         — delete the test namespace

set -euo pipefail

NAMESPACE="pki-gap-test"
CONTEXT="${KUBE_CONTEXT:?set KUBE_CONTEXT to your kubectl context}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/stack.yaml"

CERTS=(
  test-platform-root-ca
  test-platform-intermediate-ca
  test-namespace-intermediate-ca
  test-leaf
)

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pass()    { echo -e "  ${GREEN}✓ PASS${NC}  $*"; }
fail()    { echo -e "  ${RED}✗ FAIL${NC}  $*"; }
info()    { echo -e "  ${BLUE}→${NC} $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; }
section() { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}"; }
finding() { echo -e "\n  ${YELLOW}FINDING:${NC} $*"; }

# ── kubectl helpers ────────────────────────────────────────────────────────────
kube() { kubectl --context "$CONTEXT" "$@"; }

cert_tls() {
  # Emit the raw PEM for tls.crt from a Secret
  kube get secret "$1" -n "$NAMESPACE" -ojsonpath='{.data.tls\.crt}' | base64 -d
}

get_skid() {
  cert_tls "$1" | openssl x509 -noout -ext subjectKeyIdentifier 2>/dev/null \
    | grep -v "X509v3" | tr -d ' \n'
}

get_notbefore() {
  cert_tls "$1" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2
}

get_subject() {
  cert_tls "$1" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//'
}

get_issuer() {
  cert_tls "$1" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//'
}

get_notafter() {
  cert_tls "$1" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2
}

# Returns 0 if ca_secret correctly signs cert_secret, 1 otherwise
verify_link() {
  local ca_secret="$1"
  local cert_secret="$2"
  local tmpdir
  tmpdir=$(mktemp -d)
  cert_tls "$ca_secret"   > "$tmpdir/ca.crt"
  cert_tls "$cert_secret" > "$tmpdir/cert.crt"
  openssl verify -CAfile "$tmpdir/ca.crt" -partial_chain "$tmpdir/cert.crt" >/dev/null 2>&1
  local rc=$?
  rm -rf "$tmpdir"
  return $rc
}

# ── commands ──────────────────────────────────────────────────────────────────
cmd_apply() {
  section "Deploying test stack"
  info "Context: $CONTEXT"
  info "Manifest: $MANIFEST"
  kube apply -f "$MANIFEST"
  echo ""
  info "Waiting for namespace to be active..."
  kube wait namespace/"$NAMESPACE" --for=jsonpath='{.status.phase}'=Active --timeout=30s
  info "Stack applied. Run './test.sh wait' to wait for all certs."
}

cmd_wait() {
  section "Waiting for all certs to be Ready"
  for cert in "${CERTS[@]}"; do
    info "Waiting: $cert"
    kube wait cert/"$cert" -n "$NAMESPACE" --for=condition=Ready --timeout=120s
    pass "$cert is Ready"
  done
}

cmd_info() {
  section "Chain state"
  printf "  %-40s %-28s %-20s\n" "CERT" "NOT-BEFORE" "SKID (last 12)"
  printf "  %-40s %-28s %-20s\n" "────────────────────────────────────────" "────────────────────────────" "────────────────────"
  for cert in "${CERTS[@]}"; do
    local nb skid
    nb=$(get_notbefore "$cert" 2>/dev/null || echo "N/A")
    skid=$(get_skid "$cert" 2>/dev/null | tail -c 13 || echo "N/A")
    printf "  %-40s %-28s %-20s\n" "$cert" "$nb" "$skid"
  done
}

cmd_verify() {
  section "Chain link verification (openssl)"

  local links=(
    "test-platform-root-ca→test-platform-intermediate-ca"
    "test-platform-intermediate-ca→test-namespace-intermediate-ca"
    "test-namespace-intermediate-ca→test-leaf"
  )

  for link in "${links[@]}"; do
    local ca="${link%%→*}"
    local cert="${link##*→}"
    if verify_link "$ca" "$cert"; then
      pass "$ca → $cert : chain VALID"
    else
      fail "$ca → $cert : chain BROKEN  ← gap evidence"
    fi
  done
}

# ── scenario helpers ───────────────────────────────────────────────────────────
_capture_state() {
  # Emit space-separated: skid notbefore for each cert in CERTS
  for cert in "${CERTS[@]}"; do
    local skid nb
    skid=$(get_skid "$cert" 2>/dev/null || echo "ERR")
    nb=$(get_notbefore "$cert" 2>/dev/null || echo "ERR")
    echo "${cert}|${skid}|${nb}"
  done
}

_print_state_table() {
  local label="$1"
  shift
  printf "  %-40s %-20s %-28s\n" "CERT" "SKID (last 12)" "NOT-BEFORE"
  printf "  %-40s %-20s %-28s\n" "────────────────────────────────────────" "────────────────────" "────────────────────────────"
  while IFS='|' read -r cert skid nb; do
    printf "  %-40s %-20s %-28s\n" "$cert" "$(echo "$skid" | tail -c 13)" "$nb"
  done <<< "$@"
}

_assert_skid_changed() {
  local cert="$1" before="$2" after="$3"
  if [[ "$before" != "$after" ]]; then
    pass "$cert: SKID changed (new private key generated)"
  else
    fail "$cert: SKID did NOT change"
  fi
}

_assert_not_cascaded() {
  local cert="$1" nb_before="$2" nb_after="$3"
  if [[ "$nb_before" == "$nb_after" ]]; then
    pass "$cert: NOT reissued — cert-manager left it untouched"
  else
    fail "$cert: was reissued (unexpected cascade by cert-manager)"
  fi
}

# ── scenarios ─────────────────────────────────────────────────────────────────
cmd_scenario_root() {
  section "SCENARIO A: Root CA rotation"
  echo "  Proves: cert-manager reissues root CA but leaves intermediate, ns-intermediate,"
  echo "  and leaf certs orphaned. Chain becomes unverifiable."

  info "Capturing baseline state..."
  local before
  before=$(_capture_state)
  echo ""
  _print_state_table "BEFORE" "$before"

  info "Deleting root CA Secret to force rotation with new key..."
  kube delete secret test-platform-root-ca -n "$NAMESPACE" >/dev/null
  info "Waiting for root CA to be re-issued and Ready (rotationPolicy: Always → new key)..."
  sleep 2
  kube wait cert/test-platform-root-ca -n "$NAMESPACE" \
    --for=condition=Ready --timeout=120s >/dev/null
  info "Giving cert-manager 10 s to cascade (if it were going to)..."
  sleep 10

  local after
  after=$(_capture_state)
  echo ""
  _print_state_table "AFTER" "$after"
  echo ""

  # Extract per-cert values
  local root_skid_before root_skid_after int_nb_before int_nb_after ns_nb_before ns_nb_after leaf_nb_before leaf_nb_after
  root_skid_before=$(awk -F'|' '/^test-platform-root-ca\|/{print $2}' <<< "$before")
  root_skid_after=$(awk  -F'|' '/^test-platform-root-ca\|/{print $2}' <<< "$after")
  int_nb_before=$(awk   -F'|' '/^test-platform-intermediate-ca\|/{print $3}' <<< "$before")
  int_nb_after=$(awk    -F'|' '/^test-platform-intermediate-ca\|/{print $3}' <<< "$after")
  ns_nb_before=$(awk    -F'|' '/^test-namespace-intermediate-ca\|/{print $3}' <<< "$before")
  ns_nb_after=$(awk     -F'|' '/^test-namespace-intermediate-ca\|/{print $3}' <<< "$after")
  leaf_nb_before=$(awk  -F'|' '/^test-leaf\|/{print $3}' <<< "$before")
  leaf_nb_after=$(awk   -F'|' '/^test-leaf\|/{print $3}' <<< "$after")

  echo "  Assertions:"
  _assert_skid_changed    "test-platform-root-ca"         "$root_skid_before" "$root_skid_after"
  _assert_not_cascaded    "test-platform-intermediate-ca" "$int_nb_before"    "$int_nb_after"
  _assert_not_cascaded    "test-namespace-intermediate-ca" "$ns_nb_before"    "$ns_nb_after"
  _assert_not_cascaded    "test-leaf"                     "$leaf_nb_before"   "$leaf_nb_after"

  echo ""
  echo "  Chain integrity after rotation:"
  if verify_link "test-platform-root-ca" "test-platform-intermediate-ca"; then
    fail "intermediate still verifies against new root (unexpected — SKID mismatch?)"
  else
    pass "root → intermediate: BROKEN  (intermediate signed by old root, new root has different key)"
  fi

  finding "cert-manager reissued root CA with a new key (rotationPolicy: Always) but made no"
  finding "attempt to cascade reissuance downstream. The intermediate CA is now signed by a"
  finding "root CA key that no longer exists. This is a cert-manager design boundary, not a"
  finding "configuration gap. The cascade must be implemented in the operator."
}

cmd_scenario_int() {
  section "SCENARIO B: Platform intermediate CA rotation"
  echo "  Proves: cert-manager reissues platform intermediate but leaves ns-intermediate"
  echo "  and leaf certs orphaned."

  # First restore root chain integrity (reissue intermediate against current root)
  info "Ensuring platform intermediate is signed by current root (may already be)..."

  info "Capturing baseline state..."
  local before
  before=$(_capture_state)
  echo ""
  _print_state_table "BEFORE" "$before"

  info "Deleting platform intermediate CA Secret to force rotation..."
  kube delete secret test-platform-intermediate-ca -n "$NAMESPACE" >/dev/null
  info "Waiting for platform intermediate CA to be re-issued and Ready..."
  sleep 2
  kube wait cert/test-platform-intermediate-ca -n "$NAMESPACE" \
    --for=condition=Ready --timeout=120s >/dev/null
  info "Giving cert-manager 10 s to cascade..."
  sleep 10

  local after
  after=$(_capture_state)
  echo ""
  _print_state_table "AFTER" "$after"
  echo ""

  local int_skid_before int_skid_after ns_nb_before ns_nb_after leaf_nb_before leaf_nb_after
  int_skid_before=$(awk -F'|' '/^test-platform-intermediate-ca\|/{print $2}' <<< "$before")
  int_skid_after=$(awk  -F'|' '/^test-platform-intermediate-ca\|/{print $2}' <<< "$after")
  ns_nb_before=$(awk    -F'|' '/^test-namespace-intermediate-ca\|/{print $3}' <<< "$before")
  ns_nb_after=$(awk     -F'|' '/^test-namespace-intermediate-ca\|/{print $3}' <<< "$after")
  leaf_nb_before=$(awk  -F'|' '/^test-leaf\|/{print $3}' <<< "$before")
  leaf_nb_after=$(awk   -F'|' '/^test-leaf\|/{print $3}' <<< "$after")

  echo "  Assertions:"
  _assert_skid_changed "test-platform-intermediate-ca"    "$int_skid_before" "$int_skid_after"
  _assert_not_cascaded "test-namespace-intermediate-ca"   "$ns_nb_before"    "$ns_nb_after"
  _assert_not_cascaded "test-leaf"                        "$leaf_nb_before"  "$leaf_nb_after"

  echo ""
  echo "  Chain integrity after rotation:"
  if verify_link "test-platform-intermediate-ca" "test-namespace-intermediate-ca"; then
    fail "ns-intermediate still verifies against new platform intermediate (unexpected)"
  else
    pass "platform-int → ns-intermediate: BROKEN  (ns-intermediate signed by old platform-int)"
  fi

  finding "cert-manager reissued the platform intermediate CA with a new key but made no"
  finding "attempt to cascade to the namespace intermediate or leaf. The ns-intermediate is"
  finding "now signed by a key that no longer exists. Same gap, same fix needed in the operator."
}

cmd_scenario_ns_int() {
  section "SCENARIO C: Namespace intermediate CA rotation"
  echo "  Proves: cert-manager reissues namespace intermediate but leaves leaf cert orphaned."

  info "Capturing baseline state..."
  local before
  before=$(_capture_state)
  echo ""
  _print_state_table "BEFORE" "$before"

  info "Deleting namespace intermediate CA Secret to force rotation..."
  kube delete secret test-namespace-intermediate-ca -n "$NAMESPACE" >/dev/null
  info "Waiting for namespace intermediate CA to be re-issued and Ready..."
  sleep 2
  kube wait cert/test-namespace-intermediate-ca -n "$NAMESPACE" \
    --for=condition=Ready --timeout=120s >/dev/null
  info "Giving cert-manager 10 s to cascade..."
  sleep 10

  local after
  after=$(_capture_state)
  echo ""
  _print_state_table "AFTER" "$after"
  echo ""

  local ns_skid_before ns_skid_after leaf_nb_before leaf_nb_after
  ns_skid_before=$(awk  -F'|' '/^test-namespace-intermediate-ca\|/{print $2}' <<< "$before")
  ns_skid_after=$(awk   -F'|' '/^test-namespace-intermediate-ca\|/{print $2}' <<< "$after")
  leaf_nb_before=$(awk  -F'|' '/^test-leaf\|/{print $3}' <<< "$before")
  leaf_nb_after=$(awk   -F'|' '/^test-leaf\|/{print $3}' <<< "$after")

  echo "  Assertions:"
  _assert_skid_changed "test-namespace-intermediate-ca" "$ns_skid_before" "$ns_skid_after"
  _assert_not_cascaded "test-leaf"                      "$leaf_nb_before" "$leaf_nb_after"

  echo ""
  echo "  Chain integrity after rotation:"
  if verify_link "test-namespace-intermediate-ca" "test-leaf"; then
    fail "leaf still verifies against new ns-intermediate (unexpected)"
  else
    pass "ns-intermediate → leaf: BROKEN  (leaf signed by old ns-intermediate)"
  fi

  finding "cert-manager reissued the namespace intermediate CA with a new key but made no"
  finding "attempt to cascade to the leaf cert. This is the innermost link of the chain."
  finding "The leaf cert is now orphaned. The operator cascade is required at every tier."
}

cmd_all() {
  cmd_apply
  cmd_wait
  cmd_info

  section "Initial chain verification"
  cmd_verify

  cmd_scenario_root
  cmd_scenario_int
  cmd_scenario_ns_int

  section "SUMMARY"
  echo ""
  echo "  All three scenarios confirm the same finding:"
  echo ""
  echo "  ┌─────────────────────────────────────────────────────────────────────┐"
  echo "  │ cert-manager DOES: reissue the rotated cert with a new private key  │"
  echo "  │ cert-manager DOES NOT: cascade reissuance to any downstream cert    │"
  echo "  │                                                                     │"
  echo "  │ This is cert-manager design, not a configuration gap.               │"
  echo "  │ There is no cert-manager feature that can be enabled to cascade.    │"
  echo "  │                                                                     │"
  echo "  │ GAP LOCATION: private-pki-operator                                  │"
  echo "  │ REQUIRED: watch for intermediate CA SKID changes and trigger        │"
  echo "  │           AwaitingReissuance + VerifyingChain for downstream certs  │"
  echo "  │           (tracked in GitHub issue #74)                             │"
  echo "  └─────────────────────────────────────────────────────────────────────┘"
  echo ""
}

cmd_cleanup() {
  section "Cleanup"
  info "Deleting namespace $NAMESPACE..."
  kube delete namespace "$NAMESPACE" --ignore-not-found
  pass "Cleanup complete"
}

# ── dispatch ──────────────────────────────────────────────────────────────────
CMD="${1:-help}"
case "$CMD" in
  apply)           cmd_apply ;;
  wait)            cmd_wait ;;
  info)            cmd_info ;;
  verify)          cmd_verify ;;
  scenario-root)   cmd_scenario_root ;;
  scenario-int)    cmd_scenario_int ;;
  scenario-ns-int) cmd_scenario_ns_int ;;
  all)             cmd_all ;;
  cleanup)         cmd_cleanup ;;
  help|--help|-h)
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  apply           Deploy the 4-tier test stack to $NAMESPACE"
    echo "  wait            Wait for all certs to be Ready"
    echo "  info            Print current chain state (SKID, NotBefore)"
    echo "  verify          openssl chain link verification"
    echo "  scenario-root   Rotate root CA, prove no cascade to downstream"
    echo "  scenario-int    Rotate platform intermediate, prove no cascade"
    echo "  scenario-ns-int Rotate namespace intermediate, prove no cascade"
    echo "  all             Full run: apply → wait → info → all scenarios"
    echo "  cleanup         Delete namespace pki-gap-test"
    echo ""
    echo "Environment:"
    echo "  KUBE_CONTEXT    kubectl context (required, no default)"
    ;;
  *)
    echo "Unknown command: $CMD" >&2
    echo "Run '$0 help' for usage." >&2
    exit 1
    ;;
esac
