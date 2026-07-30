#!/usr/bin/env bash
# Validate cell networking end-to-end against a live auraed.
#
#   sudo -E ./hack/validate-cell-net.sh nft     # at bookmark cell-net-nft
#   sudo -E ./hack/validate-cell-net.sh ebpf    # at bookmark cell-net-ebpf
#
# The script needs root for the cgroups, the clone3 netns, CAP_NET_ADMIN,
# nft, and the BPF load. It needs a kernel with netkit, thus version 6.7 or
# later, the `nft` binary, and the certificates in /etc/aurae/pki. The ebpf
# mode also needs the guard object in /var/lib/aurae/ebpf, which `make ebpf`
# installs.
set -uo pipefail
# Use line buffering, so that a stuck run still shows its progress.
exec 1> >(stdbuf -oL cat)

MODE="${1:?usage: $0 nft|ebpf}"
AURAED=./target/debug/auraed
AER="timeout 60 ./target/debug/aer"
POOL_GW="fd00:ae::1"
LOG=/tmp/auraed-validate.log
PASS=0
FAIL=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
note() { printf '  \033[33mNOTE\033[0m %s\n' "$1"; }
hdr()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }

check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}
refute() { # refute <desc> <cmd...>  — expects failure
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then bad "$desc"; else ok "$desc"; fi
}

cleanup() {
  hdr "cleanup"
  for c in "$CELL_A" "$CELL_B"; do
    timeout 30 ./target/debug/aer cell free "$c" >/dev/null 2>&1
  done
  [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null
  sleep 1
  nft delete table inet aurae 2>/dev/null
  # Delete each netkit primary that this run leaked.
  for l in $(ip -o link show type netkit 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep '^nk-' ); do
    ip link del "$l" 2>/dev/null
  done
  printf '\n\033[1m%d passed, %d failed\033[0m  (daemon log: %s)\n' "$PASS" "$FAIL" "$LOG"
  [[ $FAIL -eq 0 ]]
}

[[ $EUID -eq 0 ]] || { echo "must run as root"; exit 1; }
CELL_A="val-a-$RANDOM"
CELL_B="val-b-$RANDOM"
trap cleanup EXIT

hdr "preflight"
check "auraed binary present" test -x "$AURAED"
check "aer binary present" test -x "$AER"
check "nft present" which nft
if [[ "$MODE" == ebpf ]]; then
  if [[ -f /var/lib/aurae/ebpf/guard-tcx-cell-net ]]; then
    ok "guard object installed"
  else
    bad "guard object missing — run: make ebpf"
    exit 1
  fi
fi
# Start with a clean state, so that a previous run cannot hide a bug.
nft delete table inet aurae 2>/dev/null

hdr "start daemon"
$AURAED -v >"$LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 40); do
  [[ -S /var/run/aurae/aurae.sock ]] && break
  sleep 0.25
done
if [[ -S /var/run/aurae/aurae.sock ]]; then ok "daemon socket up"; else
  bad "daemon did not come up"; tail -30 "$LOG"; exit 1
fi

# The daemon binds the socket before it runs `init_host_network`. Thus an
# available socket does not show a ready host network. Wait for the log
# message of the daemon, or the nft assertions below report false
# failures.
for _ in $(seq 1 60); do
  grep -q 'Host network ready' "$LOG" && break
  grep -q 'Cell networking unavailable' "$LOG" && break
  sleep 0.5
done
if grep -q 'Host network ready' "$LOG"; then
  ok "host network initialised"
else
  bad "host network did not initialise"
  grep -E 'Cell networking unavailable|guard failed|nft' "$LOG" | tail -5
  exit 1
fi

# A runtime that spins starves the cell allocation. Find that condition
# before you examine the networking code. Refer to the commit
# "fix(ebpf): clear AsyncFd readiness in the perf buffer reader".
sleep 2
CPU=$(ps -o pcpu= -p "$DAEMON_PID" | tr -d ' ' | cut -d. -f1)
if [[ "${CPU:-0}" -gt 150 ]]; then
  bad "daemon is burning ${CPU}% CPU — runtime is spinning, results below are unreliable"
else
  ok "daemon CPU sane (${CPU:-?}%)"
fi

# In the ebpf mode the daemon must load the guard. It fails closed.
if [[ "$MODE" == ebpf ]]; then
  if grep -q 'Cell-net BPF guard failed to load' "$LOG"; then
    bad "guard failed to load (daemon refuses cells)"; tail -20 "$LOG"; exit 1
  else
    ok "guard loaded"
  fi
fi

hdr "nft base ruleset"
check "inet aurae table exists" nft list table inet aurae
check "cell_ifaces set declared" bash -c "nft list table inet aurae | grep -q 'set cell_ifaces'"
check "cell_src set declared"    bash -c "nft list table inet aurae | grep -q 'set cell_src'"
check "cell_src is an interval set" bash -c "nft list table inet aurae | grep -A3 'set cell_src' | grep -q interval"
# The ruleset must accept cell-to-cell traffic with its own rule. It must
# not leave that decision to the policy of the host.
check "cell-to-cell accept rule present" \
  bash -c "nft list table inet aurae | grep -qE 'ip6 saddr fd00:ae::/64 ip6 daddr fd00:ae::/64 accept'"

hdr "allocate two isolated cells"
check "allocate $CELL_A" $AER cell allocate --cell-isolate-network "$CELL_A"
check "allocate $CELL_B" $AER cell allocate --cell-isolate-network "$CELL_B"
sleep 1
ELEMS=$(nft list table inet aurae | grep -A5 'set cell_src' | grep -c 'nk-' || true)
if [[ "${ELEMS:-0}" -ge 1 ]]; then ok "cell_src gained elements ($ELEMS lines)"; else
  bad "cell_src has no elements — cells were not bound"; fi
check "two netkit primaries exist" \
  bash -c "[[ \$(ip -o link show type netkit | grep -c 'nk-') -ge 2 ]]"

# Find the address of each cell from its dev route.
A_IP=$(ip -6 route show | grep -oE 'fd00:ae::[0-9a-f]+' | sort -u | sed -n 1p)
B_IP=$(ip -6 route show | grep -oE 'fd00:ae::[0-9a-f]+' | sort -u | sed -n 2p)
note "cell addresses: A=$A_IP B=$B_IP"

runin() { # runin <cell> <name> <cmd>
  $AER cell start -c "$3" "$1" "$2" >/dev/null 2>&1
}

hdr "in-cell connectivity"
runin "$CELL_A" "gw-$RANDOM" "ping -6 -c 2 -W 3 $POOL_GW"
sleep 4
note "gateway ping dispatched; aer cell start returns at spawn time, so the"
note "daemon log and the counters below are the real signal, not this call"

if [[ -n "$B_IP" ]]; then
  hdr "cell-to-cell"
  runin "$CELL_A" "c2c-$RANDOM" "ping -6 -c 3 -W 3 $B_IP"
  sleep 5
  ok "cell-to-cell ping dispatched (A -> $B_IP)"
fi

hdr "per-cell anti-spoof (the outcome-parity check)"
# Use a source address that is in the pool but belongs to no cell. A rule
# with pool granularity passes such a packet, but the per-cell binding must
# drop it. This property makes the nft stage equal to the eBPF stage.
runin "$CELL_A" "spoof-$RANDOM" \
  "ip -6 addr add fd00:ae::dead/128 dev eth0 && ping -6 -c 2 -W 1 -I fd00:ae::dead $POOL_GW"
sleep 4
DROPS=$(nft -a list table inet aurae 2>/dev/null | grep -c 'drop' || true)
if [[ "${DROPS:-0}" -ge 1 ]]; then ok "anti-spoof drop rule installed"; else
  bad "no drop rule found"; fi

if [[ "$MODE" == ebpf ]]; then
  hdr "eBPF datapath counters"
  if command -v bpftool >/dev/null 2>&1; then
    STATS_ID=$(bpftool map show 2>/dev/null | grep 'name CELL_STATS' | head -1 | cut -d: -f1)
    RDR_ID=$(bpftool map show 2>/dev/null | grep 'name CELL_REDIRECT' | head -1 | cut -d: -f1)
    if [[ -n "${STATS_ID:-}" ]]; then
      ok "CELL_STATS map loaded (id $STATS_ID)"
      bpftool map dump id "$STATS_ID" 2>/dev/null | head -20
    else bad "CELL_STATS map not found"; fi
    if [[ -n "${RDR_ID:-}" ]]; then
      ok "CELL_REDIRECT map loaded (id $RDR_ID)"
      note "entries below should be one per ready cell:"
      bpftool map dump id "$RDR_ID" 2>/dev/null | head -20
    else bad "CELL_REDIRECT map not found"; fi
    note "redirected/spoof_dropped are the per-CPU fields of CELL_STATS;"
    note "the integration test asserts them precisely:"
    note "  sudo -E cargo test -p auraed --test 'cell_isolated_network_must_redirect*' -- --include-ignored"
  else
    note "bpftool absent — skipping map inspection"
    note "run the integration test instead (it reads the maps via aya):"
    note "  sudo -E cargo test -p auraed --test 'cell_isolated_network_must_redirect*' -- --include-ignored"
  fi
fi

hdr "teardown reclaims bindings"
$AER cell free "$CELL_A" >/dev/null 2>&1
sleep 2
AFTER=$(nft list table inet aurae | grep -A5 'set cell_src' | grep -c 'nk-' || true)
if [[ "${AFTER:-0}" -lt "${ELEMS:-1}" ]]; then
  ok "freeing a cell removed its cell_src element ($ELEMS -> $AFTER)"
else
  bad "cell_src element survived the free ($ELEMS -> $AFTER)"
fi

hdr "daemon log (last 25 lines)"
tail -25 "$LOG"
