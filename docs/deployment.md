# Subnetra production deployment guide

This guide deploys a public **Hub** and two NATed **Spokes** so that hosts on the
spokes' private LANs can reach each other through the Hub relay. Subnetra ships as
a single static binary with no runtime dependencies, so deployment is mostly
about config, capabilities, and host networking.

For MikroTik/RouterOS Container deployments, read
[`routeros-container.md`](routeros-container.md) in addition to this guide. The
RouterOS model needs dedicated veth routing and container-side forwarding.

To bring up a **macOS host as a spoke** (native `utun`), the service setup is in
§4 (launchd) below, and the end-to-end real-machine acceptance walkthrough is the
manual runbook in [`macos-spoke-acceptance.md`](macos-spoke-acceptance.md). The
hub and relay stay Linux/RouterOS; macOS is supported as a **spoke** only.

> Topology (v1): single-hub hub-and-spoke. The Hub relays between spokes; spokes
> do not relay. Peer **identity** is the per-peer PSK selected by the header
> `key_id` (issue #34), not the source endpoint: a spoke's UDP endpoint is the
> configured **bootstrap** value but is re-learned at runtime once an
> authenticated datagram arrives, so a NATed/roaming spoke recovers without
> operator action. The Hub must still have a stable, reachable endpoint that
> every spoke can reach.

## 0. Components

| Node     | Mesh id | Overlay IP   | Underlay endpoint     | Private LAN        |
|----------|---------|--------------|-----------------------|--------------------|
| Hub      | 1       | (relay only) | `203.0.113.1:18020`   | —                  |
| Spoke A  | 2       | `10.0.0.2/24`| behind NAT            | `192.168.10.0/24`  |
| Spoke B  | 3       | `10.0.0.3/24`| behind NAT            | `192.168.31.0/24`  |

Example configs live next to this guide:
[`deploy/hub.json`](../deploy/hub.json),
[`deploy/spoke-a.json`](../deploy/spoke-a.json),
[`deploy/spoke-b.json`](../deploy/spoke-b.json).

## 1. Install the binary

Build (or download a release) and install the static binary plus the control
tool:

```bash
zig build -Doptimize=ReleaseSmall
sudo install -m 0755 zig-out/bin/subnetrad /usr/local/bin/subnetrad
sudo install -m 0755 zig-out/bin/subnetra  /usr/local/bin/subnetra
```

`ldd /usr/local/bin/subnetrad` should report *not a dynamic executable*.

> **macOS:** download `subnetra-<ver>-macos-<arch>.tar.gz` from the
> [release](https://github.com/jamiesun/subnetra/releases/latest) (or `zig build`),
> `sudo install -m 0755` both binaries into `/usr/local/bin`, then clear the
> Gatekeeper quarantine:
> `sudo xattr -d com.apple.quarantine /usr/local/bin/subnetrad /usr/local/bin/subnetra`.
> macOS binaries are *minimal-dynamic* (Apple ships no static libc), so use
> `otool -L` instead of `ldd` — it must show only `/usr/lib/libSystem.B.dylib`.

## 2. Provision per-node config and secrets

Each **link** between the Hub and a Spoke has its **own** private PSK (a single
shared mesh key is rejected). Generate one 32-byte key per link:

```bash
openssl rand -hex 32   # 64 hex chars; run once per Hub<->Spoke link
```

- Link Hub(1)<->Spoke A(2): the SAME value goes in the Hub's `peers[id=2].psk`
  and Spoke A's `peers[id=1].psk`.
- Link Hub(1)<->Spoke B(3): a DIFFERENT value, in the Hub's `peers[id=3].psk`
  and Spoke B's `peers[id=1].psk`.

Reusing one PSK across links is rejected (`DuplicatePsk`); a missing or non-hex
PSK is rejected (`InvalidPsk`). The example configs contain obviously-fake
placeholder keys (`aaaa…`, `bbbb…`) **only so they pass `--check`** — replace
every one before deploying.

Install each node's config as `/etc/subnetra/config.json`:

```bash
sudo mkdir -p /etc/subnetra
sudo install -m 0600 -o root -g root deploy/spoke-a.json /etc/subnetra/config.json
```

> **Secrets handling (required):** config files carry private PSKs. They MUST be
> root-owned and `0600` (not world-readable). `/etc/subnetra` itself should be
> `0700`. Never commit a real config to source control.

Validate before starting:

```bash
sudo subnetrad --check --config /etc/subnetra/config.json
# subnetra v… (mtu=1400, udp_ports={ 18020 }, mode=raw_direct, local_id=2, peers=1) [config ok]
```

`--config` is optional; without it the daemon reads `./config.json` from its
working directory (or `$SUBNETRA_CONFIG`). `subnetrad --version` and `subnetrad --help`
work without a config; an unrecognized flag is rejected rather than ignored.

## 3. Host networking

subnetrad creates the TUN device but **prints** (never applies) the host setup, so
you keep the zero-dependency guarantee and stay in control of routing. Generate
the plan per node:

```bash
sudo subnetrad --print-network-plan           # assumes a 1500-byte underlay
sudo subnetrad --print-network-plan --path-mtu 1420   # e.g. behind PPPoE/another VPN
```

Apply the printed `ip` commands (or paste them into the `ExecStartPost` hooks of
the systemd unit). The plan also reports the **safe tunnel MTU** for the path and
warns if `local_tun_mtu` is too large — fixing that prevents the classic
"small packets work, large transfers stall" failure. To let LAN-to-LAN TCP
survive a smaller path MTU, apply the printed MSS-clamp rule.

`--print-network-plan` *assumes* a 1500-byte underlay. To measure the **real**
path MTU between two nodes — including when ICMP is filtered, so kernel PMTU
discovery silently fails — use the in-tree `mtu-probe` tool (run the responder on
one node, the prober on the other); it probes actively over UDP with the
Don't-Fragment bit and prints the `local_tun_mtu` to configure:

```bash
zig build tool:mtu-probe
zig-out/tools/mtu-probe --listen 18020              # on the far node
zig-out/tools/mtu-probe --probe 203.0.113.9:18020   # on the near node
```


For LAN-to-LAN reachability you typically also enable forwarding and route the
remote LAN via the overlay on each spoke:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
# On Spoke A, reach Spoke B's LAN through the tunnel:
sudo ip route add 192.168.31.0/24 dev snr0
```

> **macOS:** `subnetrad --print-network-plan` emits an `ifconfig`/`route` recipe
> instead of `ip …`. The `utun` name is **kernel-assigned** (`utunN`), so apply
> the plan *after* the daemon is up, substituting the real name from the `[ready]`
> banner (see §4 — launchd — and the runbook). subnetra never mutates routes
> itself on any platform.

## 4. Run as a service

### Linux — systemd

Install the unit and start the daemon:

```bash
sudo install -m 0644 deploy/subnetrad.service /etc/systemd/system/subnetrad.service
sudo systemctl daemon-reload
sudo systemctl enable --now subnetra
```

The unit requests only `CAP_NET_ADMIN`, grants `/dev/net/tun`, runs
`subnetrad --check` as `ExecStartPre`, restarts on failure, and is otherwise
sandboxed (`ProtectSystem=strict`, `NoNewPrivileges`, restricted address
families, etc.). Edit the commented `ExecStartPost` lines to match your
`--print-network-plan` output.

Logs go to the journal:

```bash
journalctl -u subnetrad -f
```

### macOS — launchd

On a macOS spoke, run the daemon under `launchd`. Because creating a `utun` needs
root, it is a **system** daemon (`/Library/LaunchDaemons`, runs as root) — not a
per-user LaunchAgent. Install
[`deploy/net.subnetra.subnetrad.plist`](../deploy/net.subnetra.subnetrad.plist)
(provision the config exactly as in §2 — `/etc/subnetra/config.json`, root-owned
`0600`):

```bash
sudo install -m 0644 deploy/net.subnetra.subnetrad.plist \
    /Library/LaunchDaemons/net.subnetra.subnetrad.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/net.subnetra.subnetrad.plist
sudo launchctl enable  system/net.subnetra.subnetrad
# older macOS: sudo launchctl load -w /Library/LaunchDaemons/net.subnetra.subnetrad.plist
```

The job runs `subnetrad --config /etc/subnetra/config.json` as root, restarts on
abnormal exit (`KeepAlive.SuccessfulExit=false`, throttled — the analogue of
`Restart=on-failure`), and logs to `/var/log/subnetrad.log`. Validate the config
with `subnetrad --check` first so a bad config does not crash-loop. Read the
kernel-assigned interface from the `[ready]` banner in the log:

```bash
sudo tail -f /var/log/subnetrad.log
# subnetra v… (… mode=raw_direct …) tun=utun4 sock=/var/run/subnetra.sock [ready]
```

**Apply the host network plan separately.** As on every platform the daemon only
*prints* the plan; on macOS the `utunN` name is kernel-assigned, so apply it
*after* the daemon is up, substituting the real name from the banner:

```bash
subnetrad --print-network-plan --config /etc/subnetra/config.json   # ifconfig/route recipe
sudo ifconfig utun4 inet 10.0.0.2 10.0.0.2 mtu 1400 up
sudo route add -net 10.0.0.0/24 -interface utun4
```

> `KeepAlive` may restart the daemon onto a **different** `utunN`; re-read the
> banner and re-apply the plan. subnetra deliberately leaves routing to you (no
> automatic route mutation), and macOS is a **spoke** only. Manage the job with
> `sudo launchctl kickstart -k system/net.subnetra.subnetrad` (restart) and
> `sudo launchctl bootout system/net.subnetra.subnetrad` (stop + unload). For the
> full real-machine acceptance procedure see
> [`macos-spoke-acceptance.md`](macos-spoke-acceptance.md).

## 5. Install the relay policy (Hub)

> **Shortcut (recommended):** the example configs in [`../deploy/`](../deploy/)
> set `"role": "hub"` / `"role": "spoke"`, so the daemon **derives this entire
> policy from config at boot** — you can skip this whole section. See
> [README → Roles](../README.md#roles-auto-derive-the-policy-from-config-role).
> The manual steps below apply to `"role": "manual"` configs, or when you want to
> layer extra rules on top of a derived table.

The Hub starts with an empty policy tree; install the relay/delivery rules at
runtime over the local control socket (hot-swapped, no restart). On Linux the
CLI default already matches the daemon (`/run/subnetra/subnetra.sock`), so no
`SUBNETRA_SOCK` is needed — set it only for a custom path:

```bash
# Deliver/relay overlay traffic to the right spoke:
sudo subnetra policy add --src 0.0.0.0/0 --dst 10.0.0.2/32 --action forward --target 2
sudo subnetra policy add --src 0.0.0.0/0 --dst 10.0.0.3/32 --action forward --target 3
sudo subnetra policy show
sudo subnetra save        # persist a replayable snapshot
```

On each Spoke, deliver tunnelled traffic destined for the local overlay address
to the local TUN (target `0` = local):

```bash
sudo subnetra policy add --src 0.0.0.0/0 --dst 10.0.0.2/32 --action forward --target 0
```

## 6. Inspect, troubleshoot, upgrade

```bash
sudo -E subnetra status      # peers, traffic counters, and per-reason drop counters
```

`subnetra status` exits non-zero if the daemon is down. Rising drop counters point
straight at the cause: `unknown_peer` (header `key_id` matches no configured
peer), `auth_or_invalid` (PSK/epoch/wire mismatch), `spoof` (inner source outside
`allowed_src`), or `no_route` (no matching policy). The `endpoint_learned`
counter rises whenever an authenticated peer is observed at a new UDP endpoint
(roaming/NAT remap — see issue #34). The `keepalive rx`/`tx` line counts the
built-in NAT keepalives (§7): `tx` rises on a spoke that emits them, `rx` on the
hub that receives them. PSKs are never printed.

### Machine-readable status (`--json`)

For monitoring, alerting, and automation, `subnetra status --json` emits the same
data as a single stable, versioned JSON object (no text scraping). The same
invariant holds: **PSKs and derived keys are never serialized.**

```bash
subnetra status --json | jq .
```

```jsonc
{
  "schema_version": 1,                 // bumped only on a breaking schema change
  "version": "0.9.0",
  "mode": "raw_direct",
  "local_id": 1,
  "listen_port": 18020,
  "tun": "snr0",
  "peers": [
    {
      "id": 2,
      "endpoint": "203.0.113.7:51822",
      "name": "bj-office-gw",               // optional operator label ("" when unset)
      "allowed_src": "10.66.0.2/32",
      "last_seen_wall_ns": 1700000095000000000,
      "last_seen_age_seconds": 5,      // null if the peer has never authenticated
      "online": true                   // last_seen within the freshness window (~90s)
    }
  ],
  "counters": { "tun_rx_packets": 3, "udp_tx_packets": 0, /* …every data-plane counter… */ }
}
```

- `peers[].name` is an **optional** human-readable label (e.g. `bj-office-gw`,
  `colo-hub`) set per peer in `config.json` (`peers[].name`). It is **metadata
  only** — never an identity/auth/routing input (key derivation, the wire
  `key_id`, and peer matching stay keyed on the numeric `id`) — and is bounded to
  printable ASCII so it is safe to echo in `subnetra status`. Omitted → empty
  string in JSON and id-only in the human view (unchanged from before).
- `peers[].online` is `true` when the peer's last authenticated packet is within
  the freshness window of ~90 s — long enough to tolerate a few missed keepalives
  (§7) without flapping. Use it (or `last_seen_age_seconds`) for a per-peer
  health/heartbeat alert.
- `counters` carries **every** counter from the human view (traffic + the full
  drop taxonomy), so a scrape never misses a field — it is the source for the
  Prometheus textfile exporter below.
- Pin `schema_version` in your monitor; it increments only on a
  breaking change (a removed/renamed key or a changed type).

### Prometheus textfile exporter

To alert on node health, [`deploy/subnetra-textfile-exporter.sh`](../deploy/subnetra-textfile-exporter.sh)
turns `subnetra status --json` into [node_exporter **textfile collector**](https://github.com/prometheus/node_exporter#textfile-collector)
metrics. There is deliberately **no HTTP server in the daemon** (an extra listening
socket + attack surface, against the single-binary ethos): the script writes one
`.prom` file and your existing `node_exporter` scrapes it. The only prerequisite is
`jq`.

```bash
sudo install -m 0755 deploy/subnetra-textfile-exporter.sh /usr/local/bin/
sudo install -m 0644 deploy/subnetra-textfile-exporter.service /etc/systemd/system/
sudo install -m 0644 deploy/subnetra-textfile-exporter.timer   /etc/systemd/system/
# set OUTPUT in the .service to your collector dir, then:
sudo systemctl enable --now subnetra-textfile-exporter.timer
```

It emits (atomically; never a half-written file):

| Metric | Type | Notes |
| --- | --- | --- |
| `subnetra_up` | gauge | `1` if status was read, `0` if the daemon is down/unbound — alertable on its own. |
| `subnetra_build_info{version,mode,tun,local_id,listen_port}` | gauge | constant `1`; identity in labels. |
| `subnetra_peer_online{id,allowed_src}` | gauge | `1` within the freshness window, else `0`. |
| `subnetra_peer_last_seen_age_seconds{id,allowed_src}` | gauge | omitted for a peer that never authenticated. |
| `subnetra_<counter>_total` | counter | **every** `counters` field (traffic + drops), drift-proof. |

Sample alert rules:

```yaml
groups:
  - name: subnetra
    rules:
      - alert: SubnetraDaemonDown
        expr: subnetra_up == 0 or absent(subnetra_up)
        for: 1m
        annotations: { summary: "subnetra daemon down or status unavailable on {{ $labels.instance }}" }
      - alert: SubnetraPeerOffline
        expr: subnetra_peer_online == 0
        for: 2m
        annotations: { summary: "subnetra peer id={{ $labels.id }} offline on {{ $labels.instance }}" }
      - alert: SubnetraPeerStale            # earlier warning than fully offline
        expr: subnetra_peer_last_seen_age_seconds > 120
        for: 1m
        annotations: { summary: "subnetra peer id={{ $labels.id }} last_seen {{ $value }}s ago" }
      - alert: SubnetraAuthDropsClimbing    # PSK/epoch/wire mismatch (key rotation skew, §6; wire break)
        expr: rate(subnetra_drop_udp_auth_or_invalid_total[5m]) > 0
        for: 10m
        annotations: { summary: "subnetra auth_or_invalid drops climbing on {{ $labels.instance }}" }
      - alert: SubnetraSpoofDrops           # inner source outside a peer's allowed_src
        expr: rate(subnetra_drop_udp_spoof_total[5m]) > 0
        for: 10m
        annotations: { summary: "subnetra spoof drops on {{ $labels.instance }}" }
```

### Upgrade & rollback runbook

Subnetra is a single static binary with no persistent on-disk data-plane state,
so the mechanical step is "swap the binary and restart." The real risk is **wire
compatibility**: an upgrade that crosses a wire-breaking boundary leaves the
upgraded nodes unable to authenticate the not-yet-upgraded ones, and because the
transport is **fail-closed** (a datagram that fails AEAD auth is silently
dropped), a half-upgraded mesh **silently partitions** — there is no error, only
a climbing `auth_or_invalid` drop counter.

**Wire-compatibility matrix**

| Boundary | Wire compatible? | Notes |
|---|---|---|
| `v0.5.0` ↔ `v0.5.1` | ✅ Yes | Identical key schedule (`subnetra-v1-*`) and 20-byte header; `wire_version = 1`. Upgrade nodes in any order. |
| `v0.5.1` ↔ current `main` (post-#96 keepalive) | ✅ Yes | `KEEPALIVE` (`flags` bit 0) is additive and did **not** bump `wire_version`; an older node simply drops keepalives, and the data path is unchanged. |
| `≤ v0.4.x` ↔ `≥ v0.5.0` | ❌ **No — hard break** | v0.5.0 renamed the HKDF crypto label `btunnel-v1-*` → `subnetra-v1-*` (the project rename, #82). Derived link/session keys differ, so **every** cross-version datagram fails AEAD auth. The `version` byte is still `1` on both sides, so the header check cannot see it — the only symptom is the `auth_or_invalid` drop counter climbing. |

> **Rule of thumb:** within `v0.5.x` (and forward onto current `main`) upgrades
> are rolling and order-independent. **Any jump across the `v0.4.x → v0.5.0` line
> is a coordinated, all-at-once-per-mesh cutover.** When in doubt, treat a version
> jump as breaking and cut the whole mesh over together.

**1. Pre-flight — before touching any running node.** Validate the *new* binary
against each node's *real* config; this catches a config the new version would
reject before you restart anything:

```bash
/path/to/new/subnetrad --check --config /etc/subnetra/config.json
# subnetra vX.Y.Z (mtu=…, mode=raw_direct, local_id=…, peers=…) [config ok]
```

**2a. Compatible upgrade (within `v0.5.x` → `main`).** Roll one node at a time;
no coordination needed. Keep the outgoing binary so you can roll back (step 4):

```bash
sudo cp -a /usr/local/bin/subnetrad /usr/local/bin/subnetrad.prev
sudo install -m 0755 zig-out/bin/subnetrad /usr/local/bin/subnetrad
sudo systemctl restart subnetrad
```

After each node, confirm on **a peer** that the link recovered (*Verify* below)
before moving to the next.

**2b. Breaking upgrade (across `v0.4.x → v0.5.0`).** A rolling upgrade here **will**
partition the mesh, so cut over together:

- Stage and `--check` the new binary on every node (step 1).
- In a maintenance window, restart **all** nodes onto the new binary as close
  together as possible. The mesh is down for that window — expected and bounded.
- Hub-first vs spokes-first does not matter: nothing interoperates across the
  boundary, so minimise the window rather than ordering it.

**3. Verify — tie every step to an observable signal, never "looks fine."** On the
restarted node and at least one of its peers:

```bash
sudo -E subnetra status
```

- Each peer's `last_seen` is **advancing** (recent, not frozen) → the link is
  authenticating and carrying traffic.
- The `udp … auth_or_invalid` drop counter is **flat** (not climbing) → no
  key/wire mismatch. A climbing `auth_or_invalid` right after an upgrade is the
  unmistakable signature of a **wire mismatch** — you crossed a breaking boundary
  while a node was still on the old binary.
- Traffic counters (`tun_tx` / `udp_tx`) advance under real load.

**4. Rollback.** Keep the previous binary on disk (the `subnetrad.prev` copy from
step 2a). To roll back:

```bash
sudo install -m 0755 /usr/local/bin/subnetrad.prev /usr/local/bin/subnetrad
sudo systemctl restart subnetrad
```

Re-apply the saved policy snapshot if the rollback target predates a policy you
added (`subnetra policy add …`, §5). Roll back the **same scope** you upgraded:
a single node for a compatible upgrade, the **whole mesh** for a breaking one (a
lone rolled-back node across a wire break is just as partitioned as a lone
upgraded one). Verify with `subnetra status` exactly as in step 3.

> **Time synchronization (required).** The fresh-epoch-per-restart property above
> relies on a sane wall clock: the session key is derived from a boot epoch
> sampled from `CLOCK_REALTIME` at startup, and a receiver orders sessions
> **forward-only** (a newer epoch supersedes an older one). The daemon fails
> closed if the clock reads earlier than 2024-01-01, but it **cannot** detect a
> clock that runs *backward across a restart*. If a node restarts with a wall
> clock earlier than its previous boot (e.g. no battery-backed RTC and NTP has
> not synced yet), its new, lower epoch is rejected by every peer until their
> clocks advance past the old value — the link silently blackholes and the peer's
> `auth_or_invalid` drop counter (above) climbs. **Mitigation:** run a time
> daemon (`chrony` / `systemd-timesyncd`); on hardware without an RTC, order
> `subnetrad.service` after `time-sync.target` (`After=time-sync.target` +
> `Wants=time-sync.target`) so the clock is monotonic across restarts. If a clock
> did jump backward, restart **both** ends of the affected link to force a fresh
> epoch on each side. This is an accepted, permanent trade-off of the
> stateless, handshake-free transport (iron law #8): there is no in-protocol
> epoch exchange to repair it, so the fix is operational (keep the clock synced).

### Key rotation runbook

Rotate a link PSK on a schedule, or immediately after a suspected compromise. A
link key lives only in `config.json` and is read **at startup**; there is no
online rekey command (the control plane is policy-only). Because authentication
**fails closed**, a naive rotation — change one end and hope — silently drops that
link's traffic until both ends agree (the `auth_or_invalid` drop counter climbs,
§6). The procedure below keeps the disruption to a single link and to the few
seconds between the two restarts.

**What you are changing.** A PSK is *per link* (§2): rotating the Hub↔Spoke A key
means writing the **same** new value into the Hub's `peers[id=2].psk` **and**
Spoke A's `peers[id=1].psk`. No endpoints change — the Hub re-learns each spoke's
endpoint from its next authenticated datagram (issue #34), so there is nothing to
re-plumb. **Rotate one link at a time** so any mistake can only affect that one
spoke.

1. **Generate a fresh per-link key** (offline, fails closed if no secure entropy):

   ```bash
   zig build tool:keygen && zig-out/tools/keygen   # 64-char hex; or: openssl rand -hex 32
   ```

2. **Record the current key** for rollback (copy the old `psk` value somewhere
   safe before you overwrite it).

3. **Stage the new key on both ends — do not restart yet.** Edit the Hub's
   `peers[id=2].psk` and Spoke A's `peers[id=1].psk` to the new value and validate
   each offline; a typo caught here costs nothing:

   ```bash
   sudo subnetrad --check --config /etc/subnetra/config.json   # run on Hub and on Spoke A
   ```

4. **Cut over back-to-back.** Restart the two ends as close together as possible
   (script it / open two SSH sessions); the rotated link is down only for the skew
   between the two restarts:

   ```bash
   sudo systemctl restart subnetrad     # on Spoke A
   sudo systemctl restart subnetrad     # on the Hub
   ```

   Restarting the Hub re-reads **every** peer, so the other spokes' links re-auth
   on their next packet (stateless, sub-second — their keys did not change). Only
   the rotated link sees a real gap.

5. **Verify** with `subnetra status` (or `--json`, §6) on the Hub: the rotated
   peer's `last_seen` advances (`last_seen_age_seconds` small / `online: true`) and
   `udp: auth_or_invalid` **stops climbing**. Confirm with an overlay ping across
   the link. A still-climbing `auth_or_invalid` with a stale `last_seen` means the
   two ends disagree — recheck that the new `psk` is byte-identical on both.

6. **Rollback:** restore the saved old key in **both** configs and restart **both**
   ends (same back-to-back cutover). Because the change is operator-driven static
   config, rollback is symmetric with step 4.

> **Red line (iron law #8).** Rotation stays operator-driven via static config and
> a coordinated restart; subnetra will **never** grow an in-protocol key-exchange
> or handshake to negotiate keys online. The brief per-link window in step 4 is the
> accepted cost of the stateless, handshake-free transport. A truly make-before-break
> (zero-window) rotation would require an optional second per-peer key *slot* — the
> daemon would accept the outgoing-old and incoming-new key during an overlap window
> so the two ends rotate independently. That enhancement is tracked as the optional
> path in issue #107 and is **not** part of today's mechanism.

## 7. Firewall / NAT requirements

- The **Hub** must accept inbound UDP on all configured `listen_ports` from the
  internet. The default is the explicit set `18020, 18023, 18026` (not a range),
  avoiding WireGuard's well-known port fingerprint and keeping the node reachable
  if one port is blocked or throttled.
- Each **Spoke** only needs **outbound** UDP reachability to the Hub's
  `ip:port`; no inbound port-forwarding is required (the spoke initiates). A spoke
  therefore only needs **one** listen port (the role-aware default binds just
  `[18020]`); multiple `listen_ports` are a hub-side feature.
- If a spoke's NAT mapping changes, the Hub re-learns the spoke's new endpoint
  from its next authenticated datagram (issue #34), so replies follow it
  automatically. Keep the **Hub** endpoint stable; spokes always initiate.

### NAT keepalive (built-in)

A NAT/stateful-firewall mapping for an **idle** spoke eventually times out (often
~30 s for UDP), after which the Hub can no longer reach that spoke until it sends
again — inbound relays to an idle spoke silently blackhole. To prevent this,
`role=spoke` nodes run a **built-in keepalive** (issue #96): every
`keepalive_secs` the spoke emits one tiny authenticated datagram to its Hub,
holding the pinhole open and keeping the Hub's learned endpoint (issue #34) fresh.

- It is **on by default** for `role=spoke` (default `keepalive_secs = 20`, under
  the typical NAT timeout). `role=hub`/`role=manual` default to `0` (disabled).
- Set `keepalive_secs` explicitly to tune the interval, or to `0` to disable it
  (e.g. a spoke that is not behind NAT, or one that always has host traffic):

  ```json
  { "role": "spoke", "local_id": 2, "keepalive_secs": 20, "peers": [ … ] }
  ```

- It is allocation-free and adds no thread or external process: one ~36-byte
  datagram per interval, driven by the reactor's own poll timeout. Confirm it on
  the spoke with `subnetra status` (the `keepalive tx` counter rises) and on the
  Hub (`keepalive rx` rises). This **replaces** the external pinger/`netwatch`
  sidecars that earlier deployments used purely to hold the pinhole open.

### Hub on a dynamic IP (DDNS)

Endpoint config is a numeric `IP:port`, and endpoint learning is **one-way** — the
Hub learns a roaming spoke, but a spoke cannot discover a Hub that moved (it needs
a correct destination to send its first packet). The daemon therefore does **not**
resolve hostnames or re-resolve them at runtime: a live in-daemon DNS client would
pull a resolver/threads/state into the deliberately minimal, zero-dependency,
single-threaded data plane (iron laws #1/#3).

The normal answer is to give the Hub a **stable public IP** (a small VPS). If you
must run the Hub behind a **dynamic** address, solve it operationally on each spoke
with a tiny DDNS watcher — no daemon changes. A restart is **stateless and cheap**
(a fresh session epoch is derived each lifetime), so re-pointing is just a config
edit plus restart:

```bash
# /usr/local/bin/subnetrad-ddns.sh  — run from a systemd timer every ~60s on each spoke
new=$(getent hosts hub.example.com | awk '{print $1}')
cur=$(grep -oE '[0-9.]+:[0-9]+' /etc/subnetra/config.json | head -1 | cut -d: -f1)
[ -n "$new" ] && [ "$new" != "$cur" ] && {
  sed -i "s/$cur/$new/" /etc/subnetra/config.json
  systemctl restart subnetrad        # stateless restart: a fresh epoch is derived
}
```

Resolving the name only once at boot would **not** be DDNS — it would miss any
address change after startup, which is exactly the case this watcher handles.

## 8. High availability / failover

v1 is **single-hub** hub-and-spoke (`PROTOCOL.md`): a hub loss partitions the mesh.
The instinctive fix — an automatic in-daemon health-probe that switches paths — is
**forbidden by design** (iron law #8; the data plane is stateless, handshake-free,
and **single-path** — see §9, "never an auto-switching path manager"). So HA is
achieved with **redundant hubs plus a failover decision made outside the daemon**,
not with a new daemon state machine. The daemon stays single-path; the host /
network / operator picks which live hub a spoke uses.

**Pattern A — shared hub VIP (network-driven failover).** Run two hub instances
behind **one** virtual address — a VRRP/`keepalived` VIP on a shared LAN, or an
anycast prefix across two sites. Every spoke dials that single stable `endpoint`;
the host/network moves the address to the surviving hub on failure, and the spoke's
next datagram lands on it with **no spoke reconfiguration** (the endpoint never
changed). The two hubs must be **indistinguishable** to a spoke: same `local_id`,
the **same** per-spoke PSKs, and the same relay policy (§5).

> **Epoch caveat (required reading).** A receiver orders sessions **forward-only**
> by boot epoch (§6, "Time synchronization"). On takeover the surviving hub must not
> present a **lower** epoch than the one the spokes last accepted, or spokes reject
> it until their stored epoch is surpassed (the link silently blackholes and
> `auth_or_invalid` climbs). Keep both hubs disciplined by NTP/`chrony`; the safest
> shape is **active/standby where the standby is (re)started at takeover** so it
> boots with a fresh, highest epoch. If you need symmetric/active-active failover
> without this coupling, use Pattern B.

**Pattern B — static multi-hub, distinct identities (no epoch coupling).** Run two
fully independent hubs, each with its **own** `local_id` and its **own** per-spoke
PSKs. Each spoke lists **both** hubs as peers:

```jsonc
// spoke config — two hub peers; one active next-hop for the overlay, one standby
"peers": [
  { "id": 1,  "endpoint": "hub-a.example:18020", "allowed_src": "10.66.0.0/24", "psk": "…A…" },
  { "id": 11, "endpoint": "hub-b.example:18020", "allowed_src": "10.66.0.0/24", "psk": "…B…" }
]
```

Because each hub is a **distinct session** (distinct `key_id`), there is no epoch
confusion. The single-path data plane will **not** auto-pick between two overlapping
next-hops, so failover is an **external** decision: an OS route metric over the two
tunnels, split overlay prefixes per hub, or an operator/script that repoints traffic
to the standby. (`config-gen` can emit the per-spoke peer entries; keep each link's
PSK unique per §2.)

**Observe-only health (what drives the switch).** Read each hub's liveness with
`subnetra status` / `subnetra status --json` (§6) — `last_seen` / `last_seen_age_seconds`
/ `online` per peer, and a flat `auth_or_invalid` — and feed that into whichever
external mechanism you chose: a `keepalived` health-check script, an anycast route
health check, or a cron that repoints a host route. The read is **non-mutating**;
the daemon makes **no** failover decision itself.

**Non-goal (explicit).** subnetra will **not** add an in-daemon health-probe /
liveness-driven path-switch / packet-striping state machine. The data plane is
single-path and handshake-free on purpose (iron law #8; §9); failover policy belongs
where it has full network context (the host, router, or anycast fabric), not inside
an allocation-free packet pump. Changing this is a v2 / **RFC amending the iron
law**, not a feature PR — and is intentionally not on the backlog.

## 9. Cross-ISP / cross-region traffic shaping

On long, cross-ISP or cross-region links, the dominant cause of jitter and loss is
**not** that the tunnel is "detected" — it is the underlay: ISP interconnect
congestion, last-mile queueing, single-flow rate caps, and bursty UDP. Subnetra is
intentionally a **stateless, handshake-free, allocation-free data plane** (iron
laws #2, #3, #8): it does **not** ship an in-tunnel scheduler, an adaptive rate
controller, or an auto-switching path manager, and it never will. All of the
shaping below is done **at the OS layer with `tc`** and standard kernel tooling —
**no daemon changes, no protocol changes**. The kernel already sees the real inner
five-tuples on the cleartext `snr0` device, so let it do the work it is good at.

> Everything here is **optional host tuning**. Measure first (Section 6,
> `subnetra status` drop counters and the counters your monitoring scrapes), change
> one thing at a time, and keep a rollback. Do not enable all of it blindly.

**1. Cap the egress, don't let the ISP cap it for you.** A tunnel that fires UDP
at line rate looks exactly like the thing carrier QoS punishes. Shape your own
egress to ~60–80% of the link's *stable* throughput (measure it; don't trust the
sales figure). For a link that holds ~80 Mbit/s, start at 50–60 Mbit/s:

```bash
# Smooth bursts and pin a precise rate on the physical uplink.
sudo tc qdisc replace dev eth0 root tbf rate 60mbit burst 512k latency 80ms
```

**2. Fair-queue per flow so bulk traffic can't starve interactive traffic.**
Apply this on the **inner** device (`snr0`), where the kernel can see each real
flow (DNS, SSH, RDP, an HTTP API call, a backup) — not on the outer UDP socket,
where everything collapses into one flow:

```bash
sudo tc qdisc replace dev snr0 root fq_codel target 5ms interval 100ms limit 2000
```

On a home/branch gateway doing the egress shaping itself, CAKE is a good
single-qdisc alternative (it integrates shaping + AQM + fair queueing):

```bash
sudo tc qdisc replace dev eth0 root cake bandwidth 60mbit
```

This — kernel fair-queueing on the cleartext device — is the correct home for
per-flow prioritisation. It replaces any "in-tunnel QoS scheduler": the OS already
understands the flows, so Subnetra must not duplicate `tc` inside the data plane.

**3. Be conservative with MTU, and clamp MSS.** Stacked PPPoE / cloud VPC / bridge
hops plus Subnetra's own outer IP/UDP + AEAD overhead shrink the usable MTU. Don't
start at 1500. Use the daemon's own plan (Section 3) — it prints the safe tunnel
MTU **and** the MSS-clamp rule for the path:

```bash
sudo subnetrad --print-network-plan --path-mtu 1280   # raise once it proves stable
```

If small packets pass but large transfers stall, this is almost always the cause.

**4. Don't expect the public path to honour your DSCP.** You may mark interactive
traffic inside your own LAN, but carriers frequently zero, ignore, or mis-route
odd DSCP marks. Normalise (clear) DSCP on the public egress and keep prioritisation
local to the host queues above:

```bash
sudo iptables -t mangle -A POSTROUTING -o eth0 -j DSCP --set-dscp 0
```

**5. Multi-path, if you need it, stays static and stateless.** Prefer
**same-ISP** Hub placement and per-region Hubs over one national Hub straining a
saturated backbone — but express that as **static per-link / per-spoke config and
routing**, chosen by the operator (or `subnetra`), **not** as an in-protocol health
probe or auto-failover state machine inside the daemon (iron law #8). If you fan a
link across multiple endpoints, hash by the **inner five-tuple** so a single TCP
connection always rides one path; never stripe one connection's packets across
paths — reordering wrecks TCP congestion control.

**6. Reliability (KCP/FEC) is a v2, static-config option — not a default.** FEC
redundancy can paper over mild loss, but on an already-congested or QoS'd link it
adds traffic and can make things worse. It is selected by static per-link config
only (iron law #8 / Section "v1 vs v2" in `AGENT.md`), never negotiated, never on
by default.

**Diagnosing which knob to turn (read the counters first):**

- RTT steady but throughput capped → rate limiting or a single-flow bottleneck
  (Section item 1/5).
- RTT p95 spikes under load → queueing/congestion (item 2).
- Large packets dropped, small ones fine → MTU (item 3).
- Same-ISP fine, cross-ISP bad → it's the **path**, not the protocol — move the
  Hub closer (item 5), not into the code.
- Bad at night, fine by day → a congestion window, not a regression.

### Host & NIC tuning (socket buffers, CPU & IRQ affinity)

The shaping above is about **egress**; this is about **ingress buffering and CPU**
so a busy node — the **Hub** especially — doesn't drop packets before the
single-threaded reactor can drain them. Like routing and `tc`, all of it is
**host-side and operator-applied**: the daemon prints its plan but never mutates
host state (§3, "print, don't apply"), and it never auto-`sysctl`s.

**Socket receive buffers — the *silent* drop.** Under burst, an undersized UDP
**receive** buffer makes the kernel drop datagrams *before* the reactor reads them.
This loss is **invisible to `subnetra status`** (§6): it is a kernel socket-buffer
overflow, not a daemon drop, so none of the drop counters move. Find it at the
kernel instead:

```bash
ss -u -m                       # per-socket rmem/wmem usage and limits
nstat -az | grep -i 'Udp.*Errors'   # RcvbufErrors / InErrors = kernel UDP drops
netstat -su | grep -i 'receive buffer errors'
```

Raise the ceiling **and** the default. subnetra uses the kernel **default** buffer
(it does not `setsockopt` its own size — same "don't silently override the host"
stance as routing), so `*_default` is what actually sizes its socket and `*_max`
is the ceiling:

```bash
sudo tee /etc/sysctl.d/30-subnetra.conf >/dev/null <<'EOF'
net.core.rmem_max     = 8388608
net.core.wmem_max     = 8388608
net.core.rmem_default = 4194304
net.core.wmem_default = 2097152
EOF
sudo sysctl --system
```

Start at a few MB and confirm the `RcvbufErrors` counter stops advancing under your
real burst; oversizing just adds latency.

**Pin the reactor to a quiet core.** The data plane is single-threaded by law (iron
law #3). Keep it off the cores doing NIC softirq / other load so it is not preempted
mid-drain:

```ini
# /etc/systemd/system/subnetrad.service.d/cpu.conf  ->  [Service]
CPUAffinity=2
```

(or `taskset -cp 2 "$(pidof subnetrad)"` at runtime.)

**Spread NIC interrupts away from that core.** Enable the NIC's multi-queue/RSS and
distribute its IRQs and RPS/XPS softirq work across the *other* cores, so receive
processing doesn't compete with the reactor on its pinned core:

```bash
# RPS: let several cores share softirq for an rx queue (mask excludes the reactor core).
echo fb | sudo tee /sys/class/net/eth0/queues/rx-0/rps_cpus
# IRQ affinity: pin each NIC rx-queue IRQ to a core other than the reactor's
# (see your driver's set_irq_affinity helper; disable irqbalance if it fights you).
```

**The single-core Hub caveat (size for this).** A Hub **relays**: for every relayed
packet it does an ingress decrypt **and** an egress re-encrypt, all on the one
reactor thread (`reactor.zig`). So a Hub saturates a **single CPU core** before a
spoke does and is the first place to hit a packets-per-second ceiling. Size for it:
a fast single-core clock matters more than core count, and when one Hub core
saturates you scale **out** (more Hubs — per-region placement in §9 item 5, or the
redundant-Hub patterns in §8), **not up** with threads (the daemon is single-threaded
by law and will not grow a thread pool). Measure your actual ceiling with the
benchmark harness in §10 (*Reproducible single-host baseline*, issue #97) before sizing.

## 10. Benchmarking a live deployment

Section 9 is about *tuning*; this is about *measuring* — getting real RTT and
throughput/pps numbers from the deployed overlay and attributing any loss. This is
**field measurement** over the actual mesh (real NAT/WAN, the hub relay, cross-OS
spokes); for the single-host, reproducible CI baseline (issue #97) see *Reproducible
single-host baseline* at the end of this section. Use `iperf3` (a **host** tool —
never linked into the daemon, iron law #1) and `ping`, then read the daemon's own
counters.

> **The shipped daemon stays as-is.** `subnetrad` always ships `-O ReleaseSmall`
> (iron law #6). You measure the deployed binary; you do **not** rebuild it
> `ReleaseFast` for an end-to-end test. (The `ReleaseFast` build is only for the
> offline crypto/forward microbenchmarks — `tools/crypto-bench`, and `forward-bench`
> per #101.)

### Quick start

`deploy/bench-overlay.sh` drives the whole matrix and is read-only:

```bash
# On the target (e.g. the hub) — serve, bound to the overlay IP so only
# tunnel traffic reaches it:
deploy/bench-overlay.sh serve 10.66.0.1

# On the peer (a spoke) — ping + the iperf3 client matrix against the target:
deploy/bench-overlay.sh 10.66.0.1 -u -t 30
#   -u  also runs UDP throughput + 64-byte small-packet pps
#   -d <direct-ip>  adds a direct (underlay) run to compute the tunnel-overhead %
```

### Or run the pieces by hand

```bash
# RTT / jitter / loss
ping -c 50 10.66.0.1

# Bulk throughput (start the server first: iperf3 -s -B 10.66.0.1 on the hub)
iperf3 -c 10.66.0.1 -t 30            # single TCP stream
iperf3 -c 10.66.0.1 -t 30 -P 4       # parallel — push toward the single-core hub limit
iperf3 -c 10.66.0.1 -t 30 -R         # reverse (hub -> spoke direction)

# Packet rate + loss
iperf3 -c 10.66.0.1 -u -b 0 -t 30        # UDP unbounded: jitter + loss%
iperf3 -c 10.66.0.1 -u -b 0 -l 64 -t 30  # 64-byte packets: small-packet pps
```

**Tunnel overhead.** Run the same single-stream test once over the overlay IP and
once over the peer's direct (underlay/public) IP; the throughput ratio is the tunnel
tax (outer IP/UDP + AEAD + the single-threaded reactor). `bench-overlay.sh -d
<direct-ip>` computes it for you.

### Attribute loss with the daemon's counters

`iperf3` tells you *that* you lost packets; `subnetra status` (Section 6) tells you
*where*. Snapshot it before and after a run and read the deltas (`bench-overlay.sh`
does this automatically on Linux):

| Counter (in `drops:`) | What a nonzero delta means |
|---|---|
| `udp spoof` | inner source IP outside the peer's `allowed_src` — a misconfigured prefix |
| `udp no_route` / `tun no_route` | no policy entry for the destination — missing/incomplete relay policy (Section 5) |
| `udp unknown_peer` | the datagram's `key_id` matches no configured peer |
| `udp auth_or_invalid` | failed AEAD / replay / malformed — key mismatch or tampering |
| `*_send_err` | the kernel refused the send — local routing/MTU/buffer problem on this node |
| `relay packets` (in `traffic:`) | hub forwarding is happening (expected on the hub) |

A clean run shows the traffic counters climbing and the `drop_*` counters flat. If
`iperf3` reports loss but every `drop_*` is flat **on both ends**, the loss is in the
**underlay** (Section 9), not in subnetra.

> **macOS spokes:** `subnetra status` returns `Unsupported` by design (the control
> client is Linux-only). Use `deploy/mac-spoke-status.sh` for the spoke's own health,
> and query the **hub** (`ssh <hub> 'sudo subnetra status'`) for the per-peer
> relay/drop/last_seen counters.

### Read the result against the MTU

Overlay MTU is **1452** (raw_direct); the inner payload must not exceed it. The
classic signature — small packets fine, large transfers stall — is an MTU/MSS
problem, not a throughput one (Section 9 item 3; see also #98). Print the safe tunnel
MTU and the MSS-clamp rule with `subnetrad --print-network-plan` before you trust a
low bulk number.

### Reproducible single-host baseline (issue #97)

The field measurement above tells you what *your* mesh does today; it cannot tell you
whether a **code change** moved the data plane. For that you need a single-host,
reproducible number. `test/integration/bench.sh` builds the daemon
`-Doptimize=ReleaseFast` (measurement only — the shipped binary stays ReleaseSmall),
stands up the 3-node hub-and-spoke star entirely in local network namespaces,
saturates the overlay with the in-tree `udp-blast` generator, and reads the achieved
packet-rate / throughput from each daemon's **own** counters (`subnetra status`):

```bash
# Linux, root (needs netns + /dev/net/tun). From the repo root:
sudo test/integration/bench.sh
SUBNETRA_BENCH_SECS=10 sudo --preserve-env=SUBNETRA_BENCH_SECS test/integration/bench.sh
```

It measures two patterns and prints pps, inner goodput (Gbps at the snr0 MTU), and the
**hub's single-core CPU%** for each:

| Pattern | What it stresses |
|---|---|
| `spoke -> hub` | the hub terminating traffic — one AEAD `open` per packet |
| `spoke -> hub -> spoke` (relay) | the hub **relaying** — `recvfrom`+`sendto` **and** `open`+`seal` per packet; it saturates a core first, so this is the headline ceiling and the target of the `recvmmsg`/`sendmmsg` batching in issue #100 |

The recorded baseline lives at `test/integration/bench-baseline.env`; each run prints
the delta against it. It is **informational** — shared CI runners vary, so a regression
is surfaced, never enforced (there is no perf gate, the same way #100 calls the baseline
"informational first"). The same benchmark runs in CI via the **Benchmark** workflow
(`.github/workflows/bench.yml`, `workflow_dispatch` or a `bench/**` branch push), which
publishes the table to the job summary so a perf PR can attach reproduced numbers.

> **Why an in-tree generator, not `iperf3` here?** Issue #97 explicitly allows a tiny
> in-tree blaster; a dependency-free, deterministic `udp-blast` (built via
> `zig build tool:udp-blast`, never shipped) makes the baseline reproducible without
> installing a host tool. `iperf3` remains the richer **host** tool for the
> live-overlay field measurement above. Both honor iron law #1 — neither is ever
> linked into the daemon.
