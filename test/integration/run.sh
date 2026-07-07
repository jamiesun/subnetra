#!/usr/bin/env bash
#
# Subnetra local integration / preflight harness.
#
# Runs INSIDE the Linux dev container (see .devcontainer/). It is the automated
# guardian of Subnetra's hard release constraints and the staging ground for the
# end-to-end tunnel test.
#
# What it does TODAY (all of this is real and must pass):
#   1. Build the static musl binary on the container's NATIVE arch.
#   2. Enforce iron law #6: fully static (no ELF INTERP) and binary <= 512 KB.
#   3. Smoke-run the daemon config sanity path (`subnetrad --check`).
#   4. Cross-compile the OTHER musl arch and re-check static + size (build-only;
#      it is not executed, to avoid qemu-user emulation skewing results).
#   5. Run the unit test suite (`zig build test`).
#   6. The multi-point + relay tunnel test: a 3-node hub-and-spoke star across
#      network namespaces (one Hub relay + two Spokes). It asserts end-to-end
#      delivery spoke-A -> Hub(relay) -> spoke-B, on-wire encryption (no
#      plaintext marker on the underlay), a non-stalling RCU policy hot-update
#      under load, honest drop-counter observability (an unrouted overlay packet
#      bumps `tun: no_route`), resilience under underlay packet loss (netem) with
#      full recovery, and endpoint roaming / NAT remap (the Hub relearns a spoke
#      that moves to a new underlay address, with no handshake or restart).
#      Requires --privileged + /dev/net/tun + tcpdump (netem step needs tc).
#   7. Active-probe / stealth: unsolicited junk + an unauthenticated forgery sent
#      to the live relay's UDP port must be PERFECTLY dropped — zero reply on the
#      wire (proven by capture) — while the honest udp:unknown_peer /
#      udp:auth_or_invalid drop counters rise and the daemon stays up (PRD §5.2).
#   8. Memory soak + perf: sustained large-packet relay load; the relay's RSS must
#      stay flat (iron law #2: zero data-plane allocation) and a rough relayed
#      throughput baseline is recorded (PRD §5.2). The soak window is short by
#      default (SUBNETRA_SOAK_SECS, default 15s); the PRD's 10-minute run is the
#      manual/release acceptance target.
#
# Usage (from repo root, on the host):
#   docker build -t subnetra-dev -f .devcontainer/Dockerfile .
#   docker run --rm --privileged --device=/dev/net/tun -v "$PWD":/workspace \
#       subnetra-dev test/integration/run.sh
set -euo pipefail

readonly SIZE_BUDGET=524288   # 512 KiB, iron law #6
PASS=0
SKIP=0
# Release-gate mode (issue #26): when SUBNETRA_RELEASE_GATE=1 the harness is
# guarding a release candidate, so a SKIP is a HARD FAILURE — a release must be
# proven by the live privileged e2e, never by an absent prerequisite.
RELEASE_GATE="${SUBNETRA_RELEASE_GATE:-0}"
E2E_RAN=0          # set to 1 once the live netns relay e2e actually executes
EV_UNIT="not-run"  # unit-test result captured for the release evidence block

log()  { printf '\033[1;34m[ii]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
skip() {
  if [ "$RELEASE_GATE" = "1" ]; then
    die "release gate: required step was SKIPPED, which is not acceptable for a release candidate: $*"
  fi
  printf '\033[1;33m[skip]\033[0m %s\n' "$*"; SKIP=$((SKIP + 1));
}
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo /workspace)"

# --- arch matrix -----------------------------------------------------------
# NATIVE target runs; FOREIGN target is cross-build-only.
case "$(uname -m)" in
  x86_64|amd64)  NATIVE_TARGET=x86_64-linux-musl;  FOREIGN_TARGET=aarch64-linux-musl ;;
  aarch64|arm64) NATIVE_TARGET=aarch64-linux-musl; FOREIGN_TARGET=x86_64-linux-musl  ;;
  *) die "unsupported host arch: $(uname -m)" ;;
esac
log "native target: $NATIVE_TARGET   foreign target: $FOREIGN_TARGET"
log "zig: $(zig version)"

# --- helpers ---------------------------------------------------------------
assert_static() {
  # No PT_INTERP program header == statically linked, on any architecture.
  # (ldd is unreliable for foreign-arch binaries, so we read the ELF directly.)
  local bin="$1"
  if readelf -l "$bin" 2>/dev/null | grep -q INTERP; then
    die "$bin is dynamically linked (found PT_INTERP) — violates iron law #6"
  fi
}

assert_size() {
  local bin="$1" size
  size=$(stat -c %s "$bin")
  if [ "$size" -gt "$SIZE_BUDGET" ]; then
    die "$bin is ${size} bytes (> ${SIZE_BUDGET} budget) — violates iron law #6"
  fi
  printf '%s' "$size"
}

build_target() {
  local target="$1"
  rm -rf zig-out
  zig build -Dtarget="$target" >/dev/null
  [ -x zig-out/bin/subnetrad ] || die "build for $target produced no subnetrad binary"
}

# --- 1+2+3: native build, constraints, smoke run ---------------------------
log "building native ($NATIVE_TARGET) ReleaseSmall ..."
build_target "$NATIVE_TARGET"
assert_static zig-out/bin/subnetrad
nsize=$(assert_size zig-out/bin/subnetrad)
ok "native binary is static and ${nsize} bytes (<= ${SIZE_BUDGET})"

log "smoke-running the daemon ..."
# v1 mandates a non-zero per-peer PSK (iron law #5, issue #13): the zero-peer
# default is non-runnable, so the smoke run provisions one throwaway peer with a
# private PSK via config.json.
smoke_dir=$(mktemp -d)
cp zig-out/bin/subnetrad "$smoke_dir/subnetrad"
printf '{ "local_id": 1, "peers": [ { "id": 2, "endpoint": "203.0.113.2:51820", "psk": "%s" } ] }' \
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
  > "$smoke_dir/config.json"
if ! out=$(cd "$smoke_dir" && ./subnetrad --check 2>&1); then
  rm -rf "$smoke_dir"
  die "daemon exited non-zero:\n$out"
fi
rm -rf "$smoke_dir"
grep -q "subnetra v" <<<"$out" || die "unexpected daemon output:\n$out"
ok "daemon smoke run: $(head -n1 <<<"$out")"

# --- 4: foreign cross-build (build-only) -----------------------------------
log "cross-building foreign ($FOREIGN_TARGET) ReleaseSmall ..."
build_target "$FOREIGN_TARGET"
assert_static zig-out/bin/subnetrad
fsize=$(assert_size zig-out/bin/subnetrad)
ok "foreign binary is static and ${fsize} bytes (<= ${SIZE_BUDGET})"

# --- 5: unit tests ---------------------------------------------------------
log "running unit tests (zig build test) ..."
zig build test >/dev/null || die "zig build test failed"
EV_UNIT="pass"
ok "unit tests green"

# --- 6: end-to-end netns tunnel test ---------------------------------------
# A 3-node hub-and-spoke star in separate network namespaces — one Hub (relay)
# and two Spokes — exercising BOTH capabilities the PRD calls for:
#   * multi-point: every spoke reaches the Hub over its own encrypted UDP
#     tunnel and joins the virtual 10.0.0.0/24 overlay;
#   * relay: a packet from spoke-A destined for spoke-B is forwarded (relayed)
#     by the Hub per `policy ... --action forward --target <B>` rules — spokes
#     never talk directly and share no key.
#
# Topology (underlay /24s are point-to-point veth pairs):
#   bt_a  10.100.1.2 <--veth--> 10.100.1.1  bt_hub  10.100.2.1 <--veth--> 10.100.2.2  bt_b
#   overlay snr0:  a = 10.0.0.2/24   hub = (relay, no overlay IP)   b = 10.0.0.3/24
#
# Mesh ids: hub=1, a=2, b=3. Per-link private PSKs (issue #13):
#   PSK_A is shared ONLY by the hub<->a link; PSK_B ONLY by the hub<->b link.
# Routing/key trace:
#   a->b: a seals derive(PSK_A,2,1) -> hub; hub rx derive(PSK_A,2,1), relays
#         derive(PSK_B,1,3) -> b; b rx derive(PSK_B,1,3) -> LOCAL. Reply mirrors.
#   Spokes a and b never share a key, so neither can read or forge the other's
#   hub link — the per-peer isolation #13 establishes.
#
# Policy match is destination-only in v1 (PolicyEntry.src is parsed but unused),
# so every rule uses --src 0.0.0.0/0; the Hub's per-spoke /32 allowed_src in the
# config is what actually exercises inner-source binding.
#
# Assertions:
#   1. Delivery: bt_a ping 10.0.0.3 (spoke-B) succeeds via the Hub relay.
#   2. Encryption: a plaintext marker in the ICMP payload is ABSENT from the
#      underlay UDP capture but PRESENT on spoke-B's decrypted snr0 (positive
#      control), proving the tunnel is the only thing carrying it.
#   3. Hot-update: an RCU `subnetra policy add` injected mid-stream does not stall
#      a backgrounded ping (anti-replay drops are covered by unit tests).

# Distinct private PSK per hub link (issue #13): sharing one across links would
# be rejected by validate (DuplicatePsk) and defeat per-peer isolation.
PSK_A="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PSK_B="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
E2E_NS=(bt_hub bt_a bt_b bt2_hub bt2_a bt2_b bt_probe)
declare -a E2E_PIDS=()
E2E_TMP=""
E2E_TMP2=""
HUB_PID=""           # hub relay daemon PID (set in e2e_netns; used by soak/probe)
A_PID=""             # spoke-A daemon PID
B_PID=""             # spoke-B daemon PID
PROBE_RAN=0          # set to 1 once the active-probe / stealth scenario executes
SOAK_RAN=0           # set to 1 once the memory-soak scenario executes
SOAK_RSS_BASE="-"    # hub RSS (kB) sampled after warmup
SOAK_RSS_FINAL="-"   # hub RSS (kB) sampled after the sustained-load window
SOAK_PPS="-"         # relayed echo packets/sec observed during the soak

e2e_cleanup() {
  set +e
  for p in "${E2E_PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" >/dev/null 2>&1
  done
  # Let the daemons/tcpdump actually exit before deleting their namespaces,
  # otherwise `ip netns del` can fail and leak the namespace.
  for p in "${E2E_PIDS[@]:-}"; do
    [ -n "$p" ] && wait "$p" 2>/dev/null
  done
  for ns in "${E2E_NS[@]}"; do
    ip netns del "$ns" >/dev/null 2>&1
  done
  # Best-effort: reap any root-namespace veth ends left by a partial setup
  # (a veth survives in the root ns if `ip link set ... netns` failed mid-way).
  for link in veth_ha veth_ah veth_hb veth_bh veth2_ha veth2_ah veth2_hb veth2_bh veth_hp veth_ph; do
    ip link del "$link" >/dev/null 2>&1
  done
  [ -n "$E2E_TMP" ] && rm -rf "$E2E_TMP"
  [ -n "$E2E_TMP2" ] && rm -rf "$E2E_TMP2"
}

# wait_until <timeout_s> <cmd...> : poll cmd at 10 Hz until it succeeds.
wait_until() {
  local deadline=$(( $1 * 10 )); shift
  local i=0
  while [ "$i" -lt "$deadline" ]; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.1; i=$((i + 1))
  done
  return 1
}

policy_has() { # policy_has <ns> <sock> <needle>
  ip netns exec "$1" env SUBNETRA_SOCK="$2" "$SUBNETRA_BIN" policy show 2>/dev/null | grep -qF "$3"
}

subnetra_in() { # subnetra_in <ns> <sock> <args...>
  local ns="$1" sock="$2"; shift 2
  ip netns exec "$ns" env SUBNETRA_SOCK="$sock" "$SUBNETRA_BIN" "$@"
}

# Extract a `<key>=<number>` value from the subnetra-status line matched by a fixed
# string. Echoes the number (empty if absent). The line filter disambiguates
# keys that recur across sections (e.g. `no_route=` on both the tun and udp
# drop lines).
status_counter() { # status_counter <ns> <sock> <line-match> <key>
  ip netns exec "$1" env SUBNETRA_SOCK="$2" "$SUBNETRA_BIN" status 2>/dev/null \
    | grep -F "$3" | grep -oE "$4=[0-9]+" | head -n1 | cut -d= -f2
}

write_config() { # write_config <dir> <local_id> <peers-json>
  # Pin the listen port: the default moved OFF 51820 to a multi-port set
  # (18020/18023/18026), but this harness's endpoints, tcpdump filter, roaming
  # source-port check and active-probe sends are all wired to 51820. An explicit
  # single port keeps the relay/roaming/stealth mechanics on one deterministic
  # socket (multi-port binding itself is covered by os/udp unit tests).
  cat > "$1/config.json" <<EOF
{ "local_id": $2, "listen_ports": [51820], "peers": $3 }
EOF
}

start_daemon() { # start_daemon <ns> <dir> <sock> -> records PID
  ip netns exec "$1" bash -c "cd '$2' && exec env SUBNETRA_SOCK='$3' ./subnetrad" \
    >"$2/daemon.log" 2>&1 &
  E2E_PIDS+=("$!")
}

e2e_netns() {
  # Pre-flight: the privileged netns e2e needs real CAP_NET_ADMIN + tooling.
  # Missing pieces SKIP (never fake); a misconfigured run still fails loudly.
  if [ "$(id -u)" -ne 0 ]; then
    skip "multi-point + relay e2e: not running as root (need CAP_NET_ADMIN)"
    return 0
  fi
  for tool in ip tcpdump ping; do
    command -v "$tool" >/dev/null 2>&1 || { skip "multi-point + relay e2e: '$tool' not available"; return 0; }
  done
  if [ ! -c /dev/net/tun ]; then
    skip "multi-point + relay e2e: /dev/net/tun missing (run with --device=/dev/net/tun)"
    return 0
  fi

  log "multi-point + relay e2e: building native daemon + subnetra ..."
  # Step 4 left a FOREIGN-arch binary in zig-out; rebuild NATIVE before running.
  build_target "$NATIVE_TARGET"
  SUBNETRA_BIN="$PWD/zig-out/bin/subnetra"
  [ -x "$SUBNETRA_BIN" ] || die "native build produced no subnetra binary"

  trap e2e_cleanup EXIT
  # Clean any leftovers from an aborted previous run before (re)creating.
  for ns in "${E2E_NS[@]}"; do ip netns del "$ns" >/dev/null 2>&1 || true; done
  E2E_TMP=$(mktemp -d)
  mkdir -p "$E2E_TMP/hub" "$E2E_TMP/a" "$E2E_TMP/b"
  for d in hub a b; do cp zig-out/bin/subnetrad "$E2E_TMP/$d/subnetrad"; done

  # --- namespaces + underlay veth pairs ---
  for ns in "${E2E_NS[@]}"; do ip netns add "$ns"; done
  ip link add veth_ha type veth peer name veth_ah
  ip link set veth_ha netns bt_hub
  ip link set veth_ah netns bt_a
  ip link add veth_hb type veth peer name veth_bh
  ip link set veth_hb netns bt_hub
  ip link set veth_bh netns bt_b

  ip netns exec bt_hub ip addr add 10.100.1.1/24 dev veth_ha
  ip netns exec bt_hub ip addr add 10.100.2.1/24 dev veth_hb
  ip netns exec bt_a   ip addr add 10.100.1.2/24 dev veth_ah
  ip netns exec bt_b   ip addr add 10.100.2.2/24 dev veth_bh
  ip netns exec bt_hub ip link set veth_ha up
  ip netns exec bt_hub ip link set veth_hb up
  ip netns exec bt_a   ip link set veth_ah up
  ip netns exec bt_b   ip link set veth_bh up
  for ns in "${E2E_NS[@]}"; do ip netns exec "$ns" ip link set lo up; done

  # --- per-node config (endpoints are the directly-connected veth addresses) ---
  # Each link carries its OWN private PSK (issue #13): hub<->a uses PSK_A on
  # both ends, hub<->b uses PSK_B; the two differ so spokes share no key.
  write_config "$E2E_TMP/hub" 1 \
    "[ {\"id\":2,\"endpoint\":\"10.100.1.2:51820\",\"allowed_src\":\"10.0.0.2/32\",\"psk\":\"$PSK_A\"},
       {\"id\":3,\"endpoint\":\"10.100.2.2:51820\",\"allowed_src\":\"10.0.0.3/32\",\"psk\":\"$PSK_B\"} ]"
  write_config "$E2E_TMP/a" 2 \
    "[ {\"id\":1,\"endpoint\":\"10.100.1.1:51820\",\"allowed_src\":\"10.0.0.0/24\",\"psk\":\"$PSK_A\"} ]"
  write_config "$E2E_TMP/b" 3 \
    "[ {\"id\":1,\"endpoint\":\"10.100.2.1:51820\",\"allowed_src\":\"10.0.0.0/24\",\"psk\":\"$PSK_B\"} ]"

  local hub_sock="$E2E_TMP/hub.sock" a_sock="$E2E_TMP/a.sock" b_sock="$E2E_TMP/b.sock"
  start_daemon bt_hub "$E2E_TMP/hub" "$hub_sock"; HUB_PID="${E2E_PIDS[-1]}"
  start_daemon bt_a   "$E2E_TMP/a"   "$a_sock";   A_PID="${E2E_PIDS[-1]}"
  start_daemon bt_b   "$E2E_TMP/b"   "$b_sock";   B_PID="${E2E_PIDS[-1]}"

  # --- wait for each daemon to create snr0, then bring up the overlay ---
  wait_until 5 ip netns exec bt_hub ip link show snr0 || die "hub snr0 never appeared:\n$(cat "$E2E_TMP/hub/daemon.log")"
  wait_until 5 ip netns exec bt_a   ip link show snr0 || die "spoke-a snr0 never appeared:\n$(cat "$E2E_TMP/a/daemon.log")"
  wait_until 5 ip netns exec bt_b   ip link show snr0 || die "spoke-b snr0 never appeared:\n$(cat "$E2E_TMP/b/daemon.log")"

  # MTU 1400: inner 1452 + hdr 12 + tag 16 + outer 28 would exceed the 1500 veth.
  ip netns exec bt_hub ip link set snr0 mtu 1400 up
  ip netns exec bt_a   ip link set snr0 mtu 1400 up
  ip netns exec bt_b   ip link set snr0 mtu 1400 up
  ip netns exec bt_a   ip addr add 10.0.0.2/24 dev snr0
  ip netns exec bt_b   ip addr add 10.0.0.3/24 dev snr0

  # --- inject routing policy (destination-only match; LOCAL target = 0) ---
  # subnetra must run INSIDE the daemon's netns: the client's reply socket is an
  # abstract AF_UNIX address, and that namespace is per-netns.
  subnetra_in bt_hub "$hub_sock" policy add --src 0.0.0.0/0 --dst 10.0.0.2/32 --action forward --target 2
  subnetra_in bt_hub "$hub_sock" policy add --src 0.0.0.0/0 --dst 10.0.0.3/32 --action forward --target 3
  subnetra_in bt_a   "$a_sock"   policy add --src 0.0.0.0/0 --dst 10.0.0.3/32 --action forward --target 1
  subnetra_in bt_a   "$a_sock"   policy add --src 0.0.0.0/0 --dst 10.0.0.2/32 --action forward --target 0
  subnetra_in bt_b   "$b_sock"   policy add --src 0.0.0.0/0 --dst 10.0.0.2/32 --action forward --target 1
  subnetra_in bt_b   "$b_sock"   policy add --src 0.0.0.0/0 --dst 10.0.0.3/32 --action forward --target 0

  # `policy add` is fire-and-forget: poll `policy show` (a full reactor
  # round-trip) until the rules land — this also proves each UDS is bound and
  # the reactor is servicing the control plane.
  wait_until 5 policy_has bt_hub "$hub_sock" "10.0.0.3/32" || die "hub policy never applied (reactor not servicing control?)"
  wait_until 5 policy_has bt_a   "$a_sock"   "10.0.0.3/32" || die "spoke-a policy never applied"
  wait_until 5 policy_has bt_b   "$b_sock"   "10.0.0.2/32" || die "spoke-b policy never applied"

  # --- assertion 1: end-to-end delivery via the Hub relay ---
  if ip netns exec bt_a ping -c3 -W2 10.0.0.3 >/dev/null 2>&1; then
    ok "e2e delivery: spoke-A -> Hub(relay) -> spoke-B (ping 10.0.0.3)"
  else
    die "spoke-A could not reach spoke-B through the Hub relay\nhub:$(cat "$E2E_TMP/hub/daemon.log")\na:$(cat "$E2E_TMP/a/daemon.log")\nb:$(cat "$E2E_TMP/b/daemon.log")"
  fi

  # --- assertion 2: on-wire encryption (no plaintext marker on the underlay) ---
  # Marker 0x4c45414b4d524b21 == ASCII "LEAKMRK!"; it rides in the ICMP payload.
  local under_pcap="$E2E_TMP/under.pcap" over_pcap="$E2E_TMP/over.pcap"
  ip netns exec bt_a tcpdump -i veth_ah -s0 -U -w "$under_pcap" udp port 51820 >/dev/null 2>&1 &
  E2E_PIDS+=("$!"); local td_under=$!
  ip netns exec bt_b tcpdump -i snr0 -s0 -U -w "$over_pcap" icmp >/dev/null 2>&1 &
  E2E_PIDS+=("$!"); local td_over=$!
  sleep 0.5  # let both captures attach before generating traffic
  ip netns exec bt_a ping -c5 -W2 -p 4c45414b4d524b21 10.0.0.3 >/dev/null 2>&1 || true
  sleep 0.3
  kill "$td_under" "$td_over" >/dev/null 2>&1 || true
  wait "$td_under" "$td_over" 2>/dev/null || true
  # Guard against a false green: if the underlay capture is empty (tcpdump never
  # attached, wrong iface, ...), "marker absent" would be trivially true.
  local under_pkts
  under_pkts=$(tcpdump -r "$under_pcap" 2>/dev/null | grep -c . || true)
  if [ "${under_pkts:-0}" -lt 1 ]; then
    die "underlay capture is empty — cannot prove encryption (tcpdump attach failed?)"
  fi
  if grep -aq "LEAKMRK" "$under_pcap"; then
    die "plaintext marker leaked onto the underlay — traffic is NOT encrypted"
  fi
  if ! grep -aq "LEAKMRK" "$over_pcap"; then
    die "positive control failed: marker never reached spoke-B's decrypted snr0"
  fi
  ok "on-wire encryption: ${under_pkts} tunnel pkt(s) on underlay, marker absent there, present on decrypted overlay"

  # --- assertion 3: RCU policy hot-update does not stall in-flight traffic ---
  local ping_log="$E2E_TMP/hotping.log"
  ip netns exec bt_a ping -i0.2 -c20 -W1 10.0.0.3 >"$ping_log" 2>&1 &
  local hot_ping=$!
  sleep 1
  # The injection must succeed AND visibly land (proves the control plane really
  # processed a hot-update), not merely "ping kept flowing regardless".
  subnetra_in bt_hub "$hub_sock" policy add --src 0.0.0.0/0 --dst 10.50.0.0/16 --action drop
  wait_until 5 policy_has bt_hub "$hub_sock" "10.50.0.0/16" || die "mid-stream policy hot-update never applied"
  wait "$hot_ping" 2>/dev/null || true
  local recv
  recv=$(grep -oE '[0-9]+ (packets )?received' "$ping_log" | grep -oE '^[0-9]+' | head -n1 || true)
  if [ "${recv:-0}" -ge 18 ]; then
    ok "RCU hot-update: ${recv}/20 pings delivered while injecting a rule mid-stream"
  else
    die "policy hot-update stalled the data plane (${recv:-0}/20 received)\n$(cat "$ping_log")"
  fi

  # --- assertion 4: observability — drop counters are honest ----------------
  # An overlay packet to a destination with NO policy route must be dropped AND
  # increment exactly the `tun: no_route` counter operators rely on for triage.
  # Delta vs. a baseline (the counter may already be nonzero from earlier retries).
  local nr_base nr_now
  nr_base=$(status_counter bt_a "$a_sock" "tun:" "no_route"); nr_base=${nr_base:-0}
  ip netns exec bt_a ping -c1 -W1 10.0.0.99 >/dev/null 2>&1 || true
  no_route_rose() { local v; v=$(status_counter bt_a "$a_sock" "tun:" "no_route"); [ "${v:-0}" -gt "$nr_base" ]; }
  if wait_until 5 no_route_rose; then
    nr_now=$(status_counter bt_a "$a_sock" "tun:" "no_route")
    ok "observability: unrouted overlay packet bumped tun:no_route ${nr_base} -> ${nr_now}"
  else
    die "tun:no_route did not increment for an unrouted overlay destination (counter broken?)"
  fi

  # --- assertion 5: resilience under underlay packet loss --------------------
  # raw_direct has NO ARQ (iron law: stateless transport), so loss IS expected to
  # cost packets — we only assert the tunnel keeps delivering under impairment and
  # fully recovers once it clears. Lenient threshold + SKIP when tc/netem absent so
  # the gate never flakes on a kernel without sch_netem.
  if command -v tc >/dev/null 2>&1 && \
     ip netns exec bt_hub tc qdisc add dev veth_ha root netem loss 10% delay 20ms 2>/dev/null; then
    local loss_log="$E2E_TMP/loss.log" lrecv
    ip netns exec bt_a ping -i0.1 -c20 -W2 10.0.0.3 >"$loss_log" 2>&1 || true
    ip netns exec bt_hub tc qdisc del dev veth_ha root 2>/dev/null || true
    lrecv=$(grep -oE '[0-9]+ (packets )?received' "$loss_log" | grep -oE '^[0-9]+' | head -n1 || true)
    if [ "${lrecv:-0}" -ge 10 ]; then
      ok "resilience: ${lrecv}/20 pings delivered under 10% underlay loss + 20ms delay"
    else
      die "tunnel delivered only ${lrecv:-0}/20 under modest underlay loss\n$(cat "$loss_log")"
    fi
    if ip netns exec bt_a ping -c3 -W2 10.0.0.3 >/dev/null 2>&1; then
      ok "resilience: clean delivery resumes after the impairment is removed"
    else
      die "tunnel wedged after the netem qdisc was removed\nhub:$(cat "$E2E_TMP/hub/daemon.log")"
    fi
  else
    skip "resilience under loss: tc/netem unavailable"
  fi

  # --- assertion 6: endpoint roaming / NAT remap (issue #34) -----------------
  # Move spoke-A's underlay source 10.100.1.2 -> .3 (same /24; the Hub stays at
  # .1). The spoke daemon's UDP socket is bound to 0.0.0.0, so its next datagram
  # carries the new source. The Hub must RELEARN spoke-A's endpoint from the
  # authenticated datagram (identity is keyed on header key_id, not the address)
  # and resume delivery — with no handshake and no restart.
  local lrn_base lrn_now
  lrn_base=$(status_counter bt_hub "$hub_sock" "endpoint_learned" "endpoint_learned"); lrn_base=${lrn_base:-0}
  ip netns exec bt_a ip addr flush dev veth_ah
  ip netns exec bt_a ip addr add 10.100.1.3/24 dev veth_ah
  ip netns exec bt_a ip link set veth_ah up
  ip netns exec bt_a   ip neigh flush dev veth_ah >/dev/null 2>&1 || true
  ip netns exec bt_hub ip neigh flush dev veth_ha >/dev/null 2>&1 || true
  # Generate fresh A->B traffic so the Hub sees spoke-A at its new endpoint.
  ip netns exec bt_a ping -i0.2 -c10 -W2 10.0.0.3 >/dev/null 2>&1 || true
  hub_relearned() {
    subnetra_in bt_hub "$hub_sock" status 2>/dev/null | grep -qF "id=2 endpoint=10.100.1.3:51820"
  }
  if wait_until 5 hub_relearned; then
    lrn_now=$(status_counter bt_hub "$hub_sock" "endpoint_learned" "endpoint_learned"); lrn_now=${lrn_now:-0}
    [ "${lrn_now}" -gt "${lrn_base}" ] || die "Hub endpoint reads .3 but endpoint_learned did not rise (${lrn_base} -> ${lrn_now})"
    ok "roaming: Hub relearned spoke-A at 10.100.1.3 (endpoint_learned ${lrn_base} -> ${lrn_now})"
  else
    die "Hub never relearned spoke-A's roamed endpoint\nhub:$(subnetra_in bt_hub "$hub_sock" status 2>/dev/null)\n$(cat "$E2E_TMP/hub/daemon.log")"
  fi
  # Delivery must work end-to-end over the new endpoint.
  if ip netns exec bt_a ping -c3 -W2 10.0.0.3 >/dev/null 2>&1; then
    ok "roaming: end-to-end delivery resumes after the endpoint move"
  else
    die "delivery did not resume after spoke-A roamed to 10.100.1.3"
  fi

  E2E_RAN=1   # the live privileged relay e2e actually executed (release evidence)
}
e2e_netns

# --- scenario 2: role-based config auto-derives the relay/local policy --------
# Issue #21. SAME star topology, but each node ships ONLY a `role` + routes and
# NO `subnetra policy add`: the daemon must derive the full forwarding table from
# config at boot. We assert (a) the auto-policy is visible via `policy show` on
# the hub and a spoke, and (b) end-to-end delivery works with zero runtime
# policy injection. The deeper encryption/hot-update invariants are already
# proven by scenario 1, so this stays focused on the derivation contract.
e2e_netns_role() {
  if [ "$(id -u)" -ne 0 ]; then return 0; fi   # scenario 1 already emitted the skip
  for tool in ip ping; do command -v "$tool" >/dev/null 2>&1 || return 0; done
  [ -c /dev/net/tun ] || return 0

  log "role-config e2e (#21): same star, policy derived from config (no subnetra) ..."
  # Scenario 1 owns the native rebuild, the EXIT trap, and $SUBNETRA_BIN. If it skipped
  # (e.g. tcpdump missing) none of those exist, so don't run half-set-up.
  [ -n "${SUBNETRA_BIN:-}" ] || { skip "role-config e2e (#21): scenario 1 setup did not run"; return 0; }
  for ns in bt2_hub bt2_a bt2_b; do ip netns del "$ns" >/dev/null 2>&1 || true; done
  E2E_TMP2=$(mktemp -d)
  mkdir -p "$E2E_TMP2/hub" "$E2E_TMP2/a" "$E2E_TMP2/b"
  for d in hub a b; do cp zig-out/bin/subnetrad "$E2E_TMP2/$d/subnetrad"; done

  for ns in bt2_hub bt2_a bt2_b; do ip netns add "$ns"; done
  ip link add veth2_ha type veth peer name veth2_ah
  ip link set veth2_ha netns bt2_hub
  ip link set veth2_ah netns bt2_a
  ip link add veth2_hb type veth peer name veth2_bh
  ip link set veth2_hb netns bt2_hub
  ip link set veth2_bh netns bt2_b
  ip netns exec bt2_hub ip addr add 10.100.1.1/24 dev veth2_ha
  ip netns exec bt2_hub ip addr add 10.100.2.1/24 dev veth2_hb
  ip netns exec bt2_a   ip addr add 10.100.1.2/24 dev veth2_ah
  ip netns exec bt2_b   ip addr add 10.100.2.2/24 dev veth2_bh
  ip netns exec bt2_hub ip link set veth2_ha up
  ip netns exec bt2_hub ip link set veth2_hb up
  ip netns exec bt2_a   ip link set veth2_ah up
  ip netns exec bt2_b   ip link set veth2_bh up
  for ns in bt2_hub bt2_a bt2_b; do ip netns exec "$ns" ip link set lo up; done

  # role=hub: per-spoke allowed_src becomes a forward rule to that peer id.
  cat > "$E2E_TMP2/hub/config.json" <<EOF
{ "role": "hub", "virtual_subnet": "10.0.0.0/24", "local_id": 1, "listen_ports": [51820], "peers":
  [ {"id":2,"endpoint":"10.100.1.2:51820","allowed_src":"10.0.0.2/32","psk":"$PSK_A"},
    {"id":3,"endpoint":"10.100.2.2:51820","allowed_src":"10.0.0.3/32","psk":"$PSK_B"} ] }
EOF
  # role=spoke: local_routes -> LOCAL, remote (virtual_subnet) -> the one hub.
  cat > "$E2E_TMP2/a/config.json" <<EOF
{ "role": "spoke", "virtual_subnet": "10.0.0.0/24", "local_id": 2, "listen_ports": [51820],
  "local_tun_ip": "10.0.0.2/24", "local_routes": ["10.0.0.2/32"], "peers":
  [ {"id":1,"endpoint":"10.100.1.1:51820","allowed_src":"10.0.0.0/24","psk":"$PSK_A"} ] }
EOF
  cat > "$E2E_TMP2/b/config.json" <<EOF
{ "role": "spoke", "virtual_subnet": "10.0.0.0/24", "local_id": 3, "listen_ports": [51820],
  "local_tun_ip": "10.0.0.3/24", "local_routes": ["10.0.0.3/32"], "peers":
  [ {"id":1,"endpoint":"10.100.2.1:51820","allowed_src":"10.0.0.0/24","psk":"$PSK_B"} ] }
EOF

  local hub_sock="$E2E_TMP2/hub.sock" a_sock="$E2E_TMP2/a.sock" b_sock="$E2E_TMP2/b.sock"
  start_daemon bt2_hub "$E2E_TMP2/hub" "$hub_sock"
  start_daemon bt2_a   "$E2E_TMP2/a"   "$a_sock"
  start_daemon bt2_b   "$E2E_TMP2/b"   "$b_sock"

  wait_until 5 ip netns exec bt2_hub ip link show snr0 || die "role hub snr0 never appeared:\n$(cat "$E2E_TMP2/hub/daemon.log")"
  wait_until 5 ip netns exec bt2_a   ip link show snr0 || die "role spoke-a snr0 never appeared:\n$(cat "$E2E_TMP2/a/daemon.log")"
  wait_until 5 ip netns exec bt2_b   ip link show snr0 || die "role spoke-b snr0 never appeared:\n$(cat "$E2E_TMP2/b/daemon.log")"

  ip netns exec bt2_hub ip link set snr0 mtu 1400 up
  ip netns exec bt2_a   ip link set snr0 mtu 1400 up
  ip netns exec bt2_b   ip link set snr0 mtu 1400 up
  ip netns exec bt2_a   ip addr add 10.0.0.2/24 dev snr0
  ip netns exec bt2_b   ip addr add 10.0.0.3/24 dev snr0

  # --- assertion: the policy was DERIVED FROM CONFIG, not injected at runtime ---
  wait_until 5 policy_has bt2_hub "$hub_sock" "10.0.0.3/32" || die "role hub did not auto-derive the spoke-B relay rule:\n$(subnetra_in bt2_hub "$hub_sock" policy show 2>&1)"
  if policy_has bt2_hub "$hub_sock" "target 3" && policy_has bt2_a "$a_sock" "10.0.0.0/24"; then
    ok "role-config (#21): hub auto-derived per-spoke relay rules, spoke auto-derived its hub route"
  else
    die "role auto-derivation incomplete\nhub:\n$(subnetra_in bt2_hub "$hub_sock" policy show 2>&1)\na:\n$(subnetra_in bt2_a "$a_sock" policy show 2>&1)"
  fi

  # --- assertion: delivery works end-to-end with NO subnetra policy injection ---
  if ip netns exec bt2_a ping -c3 -W2 10.0.0.3 >/dev/null 2>&1; then
    ok "role-config (#21): spoke-A -> Hub(relay) -> spoke-B with zero runtime policy commands"
  else
    die "role-config delivery failed\nhub:$(cat "$E2E_TMP2/hub/daemon.log")\na:$(cat "$E2E_TMP2/a/daemon.log")\nb:$(cat "$E2E_TMP2/b/daemon.log")"
  fi
}
e2e_netns_role

# --- scenario 3: active-probe / stealth (PRD §5.2 probe-resistance) ----------
# The stealth contract: a hostile party that sprays the relay's UDP port with
# garbage (and with a structurally-valid-looking but unauthenticated forgery) must
# get NOTHING back — no TCP reset, no ICMP, no UDP — and must not perturb the
# daemon. A dedicated prober on its own underlay subnet (the Hub has NO peer for
# it) lets us assert, unambiguously, that the Hub emits ZERO packets toward it.
# Honest observability is asserted too: under the default header obfuscation the
# per-peer selector is MASKED, so any outsider datagram that matches no peer's link
# key — random junk OR a full-length frame naming a real id in the clear — bumps
# udp:unknown_peer, while a runt too short to hold an obfuscated header + tag bumps
# udp:auth_or_invalid. Bit-exact replay rejection is covered by the crypto
# sliding-window unit tests; this layer proves the on-wire silence they cannot
# observe. Reuses scenario 1's still-live star (cleanup happens at script EXIT).
e2e_active_probe() {
  if [ "$(id -u)" -ne 0 ]; then return 0; fi   # scenario 1 already emitted the skip
  [ -n "${SUBNETRA_BIN:-}" ] || { skip "active-probe e2e: scenario 1 setup did not run"; return 0; }
  { [ -n "${HUB_PID:-}" ] && kill -0 "$HUB_PID" 2>/dev/null; } || { skip "active-probe e2e: hub daemon not alive"; return 0; }
  command -v tcpdump >/dev/null 2>&1 || { skip "active-probe e2e: tcpdump unavailable"; return 0; }

  log "active-probe / stealth e2e: unsolicited junk to the relay must be perfectly dropped (no reply) ..."
  local hub_sock="$E2E_TMP/hub.sock"

  # Dedicated prober on a third underlay subnet; the Hub has no peer for 10.100.3.x.
  ip link add veth_hp type veth peer name veth_ph
  ip link set veth_hp netns bt_hub
  ip link set veth_ph netns bt_probe
  ip netns exec bt_hub   ip addr add 10.100.3.1/24 dev veth_hp
  ip netns exec bt_hub   ip link set veth_hp up
  ip netns exec bt_probe ip addr add 10.100.3.2/24 dev veth_ph
  ip netns exec bt_probe ip link set veth_ph up
  ip netns exec bt_probe ip link set lo up

  # Capture everything on the prober link: any UDP from 10.100.3.1 is a reply == fail.
  local probe_pcap="$E2E_TMP/probe.pcap"
  ip netns exec bt_probe tcpdump -i veth_ph -s0 -U -w "$probe_pcap" >/dev/null 2>&1 &
  E2E_PIDS+=("$!"); local td_probe=$!
  sleep 0.5

  local up_base ai_base up_now ai_now
  up_base=$(status_counter bt_hub "$hub_sock" "udp:" "unknown_peer"); up_base=${up_base:-0}
  ai_base=$(status_counter bt_hub "$hub_sock" "udp:" "auth_or_invalid"); ai_base=${ai_base:-0}

  # The dev image has no netcat, so send via bash's /dev/udp redirection.
  local n=20 i
  # (a) pure garbage (a full-length blob) — matches no peer's link key under the
  #     masked selector -> unknown_peer.
  for ((i = 0; i < n; i++)); do
    ip netns exec bt_probe bash -c 'printf "%s" "NOT-A-SUBNETRA-DATAGRAM-PURE-GARBAGE-0123456789" > /dev/udp/10.100.3.1/51820' 2>/dev/null || true
  done
  # (b) structured "forgery": a full frame that names a real id (key_id=2) in the
  #     clear. With header obfuscation on (the default) the selector is masked, so
  #     this is indistinguishable from junk — it also fails trial-deobfuscation
  #     against every peer -> unknown_peer. Kept to prove the relay stays silent
  #     even to a plausibly-shaped frame.
  for ((i = 0; i < n; i++)); do
    ip netns exec bt_probe bash -c 'printf "\x01\x00\x02\x00\x11\x22\x33\x44\x55\x66\x77\x88\x01\x02\x03\x04\x05\x06\x07\x08\xde\xad\xbe\xef\xca\xfe\xba\xbe\x0f\x1e\x2d\x3c\x4b\x5a\x69\x78" > /dev/udp/10.100.3.1/51820' 2>/dev/null || true
  done
  # (c) runt: too short to hold an obfuscated header + tag -> auth_or_invalid. This
  #     is the only drop bucket an outsider can reach once the selector is masked.
  for ((i = 0; i < n; i++)); do
    ip netns exec bt_probe bash -c 'printf "\x01\x00\x02" > /dev/udp/10.100.3.1/51820' 2>/dev/null || true
  done
  sleep 0.5
  kill "$td_probe" >/dev/null 2>&1 || true; wait "$td_probe" 2>/dev/null || true

  # --- stealth assertion: zero replies from the relay to the prober ---
  local total reply
  total=$(tcpdump -r "$probe_pcap" 2>/dev/null | grep -c . || true)
  [ "${total:-0}" -ge 1 ] || die "active-probe: prober capture is empty (tcpdump attach failed?)"
  reply=$(tcpdump -r "$probe_pcap" 'udp and src host 10.100.3.1' 2>/dev/null | grep -c . || true)
  if [ "${reply:-0}" -eq 0 ]; then
    ok "stealth: relay sent ZERO UDP replies to ${total} captured probe frame(s) — perfect silent drop"
  else
    die "STEALTH VIOLATION: relay returned ${reply} packet(s) to an unauthenticated prober:\n$(tcpdump -r "$probe_pcap" 'udp and src host 10.100.3.1' 2>/dev/null)"
  fi

  # --- observability assertion: the silent drops are honestly counted ---
  up_now=$(status_counter bt_hub "$hub_sock" "udp:" "unknown_peer"); up_now=${up_now:-0}
  ai_now=$(status_counter bt_hub "$hub_sock" "udp:" "auth_or_invalid"); ai_now=${ai_now:-0}
  [ "${up_now}" -gt "${up_base}" ] || die "udp:unknown_peer did not rise for unsolicited junk (${up_base} -> ${up_now}) — drop accounting broken"
  [ "${ai_now}" -gt "${ai_base}" ] || die "udp:auth_or_invalid did not rise for an unauthenticated forgery (${ai_base} -> ${ai_now})"
  ok "observability: junk bumped udp:unknown_peer ${up_base}->${up_now}, forgery bumped udp:auth_or_invalid ${ai_base}->${ai_now}"

  # --- liveness assertion: hostile traffic did not crash or wedge the relay ---
  kill -0 "$HUB_PID" 2>/dev/null || die "active-probe: hub relay daemon died while absorbing junk\n$(cat "$E2E_TMP/hub/daemon.log")"
  ok "active-probe: hub relay survived $((2 * n)) hostile datagrams and kept serving its control socket"
  PROBE_RAN=1
}
e2e_active_probe

# --- scenario 4: memory soak + perf baseline (PRD §5.2 RSS-flat) -------------
# Iron law #2 says the data plane is strictly allocation-free, so under sustained
# load the relay's resident memory must be a flat line. We flood max-size packets
# spoke-A -> Hub(relay) -> spoke-B, sample the Hub daemon's VmRSS after a warmup
# and again at the end, and assert it did not grow (a per-packet leak would scale
# with the packet count and blow far past the page-granularity tolerance). The
# same flood yields a rough relayed-throughput baseline. The window is short by
# default; the PRD's 10-minute gigabit run is the manual/release acceptance step.
e2e_soak() {
  if [ "$(id -u)" -ne 0 ]; then return 0; fi   # scenario 1 already emitted the skip
  [ -n "${SUBNETRA_BIN:-}" ] || { skip "memory-soak e2e: scenario 1 setup did not run"; return 0; }
  { [ -n "${HUB_PID:-}" ] && kill -0 "$HUB_PID" 2>/dev/null; } || { skip "memory-soak e2e: hub daemon not alive"; return 0; }
  command -v ping >/dev/null 2>&1 || { skip "memory-soak e2e: ping unavailable"; return 0; }

  local secs="${SUBNETRA_SOAK_SECS:-15}" tol="${SUBNETRA_SOAK_RSS_TOL_KB:-64}"
  log "memory-soak e2e: ${secs}s sustained max-size relay load; the relay RSS must stay flat (iron law #2) ..."

  rss_kb() { awk '/^VmRSS:/{print $2}' "/proc/$1/status" 2>/dev/null; }

  # Warm the relay path so first-touch pages are resident, then snapshot baseline.
  # -s 1372 => 1372 payload + 8 ICMP + 20 IP = 1400 inner, exactly the snr0 MTU.
  ip netns exec bt_a ping -f -s 1372 -w 3 10.0.0.3 >/dev/null 2>&1 || true
  local rss_base; rss_base=$(rss_kb "$HUB_PID"); rss_base=${rss_base:-0}
  [ "${rss_base}" -gt 0 ] || { skip "memory-soak e2e: could not read hub RSS (/proc/${HUB_PID}/status)"; return 0; }

  # Sustained flood for the full window; capture the delivery count for the baseline.
  local soak_log="$E2E_TMP/soak.log"
  ip netns exec bt_a ping -f -s 1372 -w "$secs" 10.0.0.3 >"$soak_log" 2>&1 || true
  local rss_final; rss_final=$(rss_kb "$HUB_PID"); rss_final=${rss_final:-0}

  kill -0 "$HUB_PID" 2>/dev/null || die "memory-soak: hub relay daemon died under load\n$(cat "$E2E_TMP/hub/daemon.log")"

  local delta=$(( rss_final - rss_base ))
  SOAK_RSS_BASE="$rss_base"; SOAK_RSS_FINAL="$rss_final"; SOAK_RAN=1
  if [ "${delta}" -le "${tol}" ]; then
    ok "memory-soak: relay RSS flat under load (${rss_base}kB -> ${rss_final}kB, delta ${delta}kB <= ${tol}kB tol, ${secs}s)"
  else
    die "memory-soak: relay RSS GREW ${delta}kB (${rss_base} -> ${rss_final}) over ${secs}s — possible data-plane leak\n$(cat "$E2E_TMP/hub/daemon.log")"
  fi

  # Perf baseline: relayed echo packets per second (round-trips through the Hub).
  local rx_pkts
  rx_pkts=$(grep -oE '[0-9]+ received' "$soak_log" | grep -oE '^[0-9]+' | head -n1 || true)
  if [ -n "${rx_pkts:-}" ] && [ "${secs}" -gt 0 ]; then SOAK_PPS=$(( rx_pkts / secs )); fi
  ok "perf baseline: ~${SOAK_PPS} relayed echo pkt/s (${rx_pkts:-0} in ${secs}s, 1400B inner, spoke-A<->Hub<->spoke-B)"
}
e2e_soak

# --- release gate + evidence (issue #26) -----------------------------------
# In release-gate mode every SKIP already aborts via skip(); this is the final
# backstop: a release MUST have actually run the live privileged e2e.
if [ "$RELEASE_GATE" = "1" ]; then
  [ "$SKIP" -eq 0 ] || die "release gate: ${SKIP} step(s) skipped — not acceptable for a release"
  [ "$E2E_RAN" -eq 1 ] || die "release gate: the live netns relay e2e did not run — cannot certify this release"
  [ "$PROBE_RAN" -eq 1 ] || die "release gate: the active-probe / stealth scenario did not run — cannot certify this release"
  [ "$SOAK_RAN" -eq 1 ] || die "release gate: the memory-soak scenario did not run — cannot certify this release"
fi

# Machine-readable evidence block: native build, foreign cross-build,
# static-link status, sizes, unit tests, and the live e2e result.
git_commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
zig_ver=$(zig version 2>/dev/null || echo unknown)
e2e_result=$([ "$E2E_RAN" -eq 1 ] && echo pass || echo skipped)
probe_result=$([ "$PROBE_RAN" -eq 1 ] && echo pass || echo skipped)
soak_result=$([ "$SOAK_RAN" -eq 1 ] && echo pass || echo skipped)
evidence=$(cat <<EOF
release_gate=${RELEASE_GATE}
git_commit=${git_commit}
zig_version=${zig_ver}
native_target=${NATIVE_TARGET}
native_size_bytes=${nsize}
native_static=yes
foreign_target=${FOREIGN_TARGET}
foreign_size_bytes=${fsize}
foreign_static=yes
size_budget_bytes=${SIZE_BUDGET}
unit_tests=${EV_UNIT}
netns_e2e=${e2e_result}
active_probe=${probe_result}
memory_soak=${soak_result}
soak_hub_rss_kb_base=${SOAK_RSS_BASE}
soak_hub_rss_kb_final=${SOAK_RSS_FINAL}
soak_relay_pps=${SOAK_PPS}
EOF
)

printf '\n'
log "release evidence (issue #26):"
printf '%s\n' "$evidence" | sed 's/^/    /'

# Surface the same evidence in the GitHub Actions job summary when present.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Subnetra release-gate evidence"
    echo ""
    echo '```'
    printf '%s\n' "$evidence"
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi

# --- summary ---------------------------------------------------------------
printf '\n'
log "integration summary: ${PASS} passed, ${SKIP} skipped"
