# macOS spoke — manual real-machine acceptance runbook

> This runbook tracks the macOS spoke MVP epic (#72) and the RFC
> [`macos-spoke-rfc.md`](macos-spoke-rfc.md) §8.

## Why this is a manual runbook (and the honest release gate)

Subnetra's automated acceptance harness ([`test/integration/run.sh`](../test/integration/run.sh))
drives the data plane through **privileged Linux network namespaces**. macOS has
no netns, and GitHub's hosted-mac runners cannot create a `utun` without elevated
privileges/entitlements — so **macOS cannot be gated by CI** the way Linux is.

Therefore:

- **macOS is _runbook-certified_:** a real Mac, running the steps below against a
  reachable Linux/RouterOS subnetra hub, is the acceptance gate for the macOS
  spoke artifact.
- **The automated release gate stays Linux-only** (static musl binary, size
  budget, netns relay e2e — iron law #7) until a hosted-mac acceptance path
  exists. A macOS build is shipped only after this runbook passes on real
  hardware. No macOS release asset is published from CI.

This runbook certifies a macOS host acting as a **spoke** that dials an existing
Linux/RouterOS **hub**. macOS hub, `launchd` integration, `kqueue`, and automatic
route mutation are explicitly out of scope for the MVP (RFC §9).

## 0. Prerequisites

- A real Mac (Apple Silicon or Intel) with administrator (`sudo`) access. `utun`
  creation requires root.
- **Zig 0.16.0+** to build, or a locally built `subnetrad`/`subnetra` pair.
- A **reachable, already-working** Linux or RouterOS subnetra hub with a stable
  underlay endpoint (e.g. `203.0.113.1:18020`) and a per-peer **PSK** issued for
  this Mac.
- At least one **remote overlay target** to ping across the tunnel — another
  spoke's overlay IP (e.g. `10.0.0.3`) or a LAN host published behind the hub.

> The macOS binary is **minimal-dynamic** — it links only `libSystem` (still zero
> third-party deps), so it is _not_ a static executable. Do **not** run the
> Linux-only `ldd → not a dynamic executable` check against it (RFC §2, iron law
> #6 amendment).

## 1. Build

```bash
zig build -Doptimize=ReleaseSmall
sudo install -m 0755 zig-out/bin/subnetrad /usr/local/bin/subnetrad
sudo install -m 0755 zig-out/bin/subnetra  /usr/local/bin/subnetra
```

## 2. Configure the spoke

Start from [`deploy/spoke-a.json`](../deploy/spoke-a.json) and set: your real
`psk`, the hub's `endpoint`, this Mac's overlay `local_tun_ip`/`local_id`, and
the `allowed_src` subnet reachable through the tunnel.

```bash
sudo mkdir -p /etc/subnetra
sudo install -m 0600 deploy/spoke-a.json /etc/subnetra/config.json
sudo $EDITOR /etc/subnetra/config.json
```

`SUBNETRA_TUN` is **ignored on macOS** — `utun` interface names are kernel-assigned
(`utunN`); the daemon reports the resolved name at startup (step 5).

## 3. Pre-flight: config sanity check

```bash
subnetrad --check --config /etc/subnetra/config.json
```

**Expect** a single line, exit 0, e.g.:

```text
subnetra vX.Y.Z (mtu=1400, udp_ports={ 18020 }, mode=raw_direct, local_id=2, peers=1) [config ok]
```

A non-zero exit (`InvalidPsk`, `InvalidConfig`, …) means the config is wrong —
fix it before continuing. This step needs no privileges and creates no `utun`.

## 4. Print the host network plan (macOS recipe)

```bash
subnetrad --print-network-plan --config /etc/subnetra/config.json
# behind PPPoE / another VPN, assume a smaller underlay:
subnetrad --print-network-plan --config /etc/subnetra/config.json --path-mtu 1420
```

**Expect** a macOS `ifconfig`/`route` recipe (not Linux `ip …`), print-only:

```text
# subnetra network plan for interface 'utunN'
...
ifconfig utunN inet 10.0.0.2 10.0.0.2 mtu 1400 up
# routes to remote subnets reachable via the tunnel:
route add -net 10.0.0.0/24 -interface utunN
...
```

`utunN` is a **placeholder** — substitute the real name from step 5. The daemon
never applies these commands; you run them by hand in step 6.

## 5. Start the daemon (creates the `utun`)

`utun` creation needs root. Run in the foreground in a dedicated terminal:

```bash
sudo subnetrad --config /etc/subnetra/config.json
```

**Expect** a `[ready]` banner naming the kernel-assigned interface:

```text
subnetra vX.Y.Z (mtu=1400, udp_ports={ 18020 }, mode=raw_direct, local_id=2, peers=1) tun=utun4 sock=/var/run/subnetra.sock [ready]
```

Note the real name (here `utun4`). **Checkpoint A — `utun` came up:**

```bash
ifconfig utun4        # the name from the banner
```

**Expect** the interface to exist and be `UP` (an address appears after step 6).
If the daemon exits with `AccessDenied`, you are not root. If it exits with
`SocketFailed`/`ConnectFailed`, capture the line and stop — that is a real fault.

## 6. Apply the host network plan

In a second terminal, run the recipe from step 4 with the **real** interface
name and your overlay address/MTU/subnets:

```bash
sudo ifconfig utun4 inet 10.0.0.2 10.0.0.2 mtu 1400 up
sudo route add -net 10.0.0.0/24 -interface utun4
```

## 7. Wire the local delivery policy

Deliver tunnelled traffic destined for this Mac's overlay address to the local
TUN (target `0` = local). The hub also needs a policy/route back to this spoke
(see [`deployment.md`](deployment.md) §5).

```bash
sudo subnetra policy add --src 0.0.0.0/0 --dst 10.0.0.2/32 --action forward --target 0
sudo subnetra policy show
```

## 8. Acceptance checks

### Checkpoint B — ping across the tunnel

Ping a remote overlay target (another spoke or a host behind the hub):

```bash
ping -c 5 10.0.0.3
```

**Expect** replies with 0% packet loss.

### Checkpoint C — path MTU / large packet (no fragmentation)

With inner MTU 1400, the largest unfragmented ICMP payload is `1400 − 28 = 1372`.
On macOS `-D` sets the Don't-Fragment bit:

```bash
ping -c 3 -D -s 1372 10.0.0.3     # inner packet = 1400 (= tunnel MTU): expect success
ping -c 3 -D -s 1373 10.0.0.3     # inner packet = 1401 (> tunnel MTU): expect "Message too long"
```

**Expect** `-s 1372` to succeed and `-s 1373` to fail immediately with `Message
too long` — the local `utun` MTU (set to 1400 in step 6) refuses the oversized
packet under DF, proving the tunnel MTU is honoured rather than silently
fragmenting.

### Checkpoint D — `subnetra status` counters

```bash
sudo subnetra status
```

**Expect:**

- exit 0 (non-zero ⇒ daemon down);
- the peer listed with `tun=utun4` and the configured `local_id`/port;
- `udp_tx_packets` / `udp_rx_packets` and `tun_rx_packets` / `tun_tx_packets`
  **rising** while the ping runs;
- the drop counters **flat** on valid traffic — in particular
  `drop_udp_auth_or_invalid` and `drop_udp_unknown_peer` must **not** grow. (A
  one-time `udp_endpoint_learned` bump as the peer is first observed is normal;
  see issue #34.)

Rising `drop_udp_auth_or_invalid` ⇒ PSK/epoch/wire mismatch with the hub; rising
`drop_udp_unknown_peer` ⇒ the header `key_id` matches no configured peer; rising
`drop_udp_spoof` ⇒ inner source outside `allowed_src`.

### Checkpoint E — restart re-establishment (issue #152)

A macOS spoke must sample a **fresh wall-clock boot epoch** on every lifetime so a
restart re-keys the session and the hub adopts the newer epoch (resetting its
replay window). The pre-#152 build short-circuited macOS to a **constant** epoch,
which (a) silently reused `(session_key, nonce)` pairs across restarts and (b)
locked the restarted spoke out of the hub's replay window. This checkpoint proves
the fix on real hardware (single-process unit tests cannot).

With Checkpoint B currently passing (ping flowing) and the **hub left running
untouched**:

```bash
# 1. Stop the spoke daemon (Ctrl-C in its terminal). On macOS this also tears
#    down utun4 and its route (see §9), so re-create them on restart.
# 2. Restart the spoke exactly as in §5, then re-apply the route as in §6.
# 3. Re-run the ping from Checkpoint B.
ping -c 5 10.0.0.3
sudo subnetra status
```

**Expect:**

- ping **resumes within a few seconds** of the restart (no manual hub action);
- `drop_udp_auth_or_invalid` may tick **once** as the hub first sees the new
  epoch, then stays **flat** — it must **not** climb packet-for-packet (a
  persistent climb is the lockout symptom of a constant/replayed epoch);
- `udp_rx_packets` on the spoke rises again, confirming the hub accepted the
  re-keyed session.

A spoke that **cannot** re-establish after restart (every packet dropped, ping
never resumes) indicates the constant-epoch regression has returned.

## 9. Teardown

Stopping the daemon (Ctrl-C in its terminal) closes the `utun` control socket, so
the kernel **removes the `utun4` interface automatically** — and the
interface-scoped route goes with it. To tear down while the daemon is still
running, remove the route first:

```bash
sudo route delete -net 10.0.0.0/24 -interface utun4
```

## 10. Pass / fail

**PASS** when all five checkpoints hold: (A) `utun` came up, (B) ping succeeds,
(C) the path-MTU large-packet behaviour is correct, (D) `subnetra status`
shows the peer up with rising traffic counters and **no** growth in
`drop_udp_auth_or_invalid` / `drop_udp_unknown_peer` on valid traffic, and
(E) the spoke re-establishes with the hub after a restart (issue #152).

Record the macOS version, arch, Zig version, `subnetrad --version`, and the hub
type (Linux/RouterOS) alongside the result. A PASS certifies the macOS spoke
artifact for that commit; the automated release gate remains Linux-only.
