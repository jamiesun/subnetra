<p align="center">
  <img src="images/subnetra.png" alt="Subnetra — a private Layer-3 mesh: spokes tunnel encrypted traffic to a hub that relays between them with policy routing" width="100%">
</p>

# Introduction

**Connect your servers, sites, and devices into one private, encrypted network — shipped as a single tiny binary that runs anywhere, from a cloud VM to a MikroTik router.**

## What is Subnetra?

Subnetra stitches machines in different places — offices, a data center, roaming
laptops, home labs, containers, routers — into a **single flat private subnet**.

It uses a **hub-and-spoke** design: a reachable **hub** relays traffic between
**spokes**, so any node can reach any other by a stable overlay IP **even when most
of them sit behind NAT**. Every packet travels **fully encrypted** over an ordinary
UDP tunnel, and the whole thing is **one self-contained binary** — nothing else to
install, no kernel modules, no daemon zoo.

## What you can do with it

- 🏢 **Link branch offices to a data center** — route whole subnets site-to-site over one private overlay.
- 💻 **Give roaming laptops a stable private IP** that follows them across Wi-Fi, LTE, and home networks.
- 🧪 **Reach home-lab / IoT / container services** as if they were on the same LAN.
- 🛰 **Publish a LAN from behind NAT** — e.g. a MikroTik router exposing `192.168.88.0/24` to the mesh.
- 📦 **Run where heavy VPN stacks won't fit** — constrained containers, BusyBox, small ARM boxes, edge routers.

## Highlights

- **Runs anywhere, installs as one file** — a single static binary (**under 512 KB** on
  Linux) with **zero external dependencies**. Drops onto cloud VMs, containers, BusyBox,
  Raspberry Pi, and **MikroTik RouterOS**. Builds for `amd64` / `arm64` / `armv7` / `armv5`,
  plus a native **macOS** spoke.
- **Encrypted by default, quiet on the wire** — every packet is ChaCha20-Poly1305
  encrypted with **per-link keys** and **replay protection**. There are no magic bytes, and
  unauthenticated packets are **dropped silently** — to a port scanner the tunnel looks like
  nothing is listening. **Header obfuscation is on by default** (`obfuscate`, mesh-wide):
  the 20-byte framing header is XOR-masked per packet so the whole datagram looks random and
  the NAT keepalive cadence is de-periodized — no protocol fingerprint for a *passive*
  observer. Set `"obfuscate": false` for a readable cleartext header (e.g. packet-capture
  debugging). Obfuscation hides the protocol fingerprint, not packet length or timing. See
  [Wire Protocol → Header obfuscation](reference/wire-protocol.md#header-obfuscation-optional).
- **A flat private subnet with policy routing** — give every node an overlay IP, route whole
  subnets site-to-site, and let the hub relay **spoke-to-spoke** so nodes behind NAT still
  reach each other.
- **Just works behind NAT** — spokes keep their own NAT pinhole open with a **built-in
  keepalive**, and the hub **automatically relearns** a spoke that roams to a new address —
  no external pinger, no manual reconnect.
- **Change routes live** — inject or update forwarding rules at runtime with **zero
  downtime**: no restart, no dropped packets.
- **Built to be operated** — human-readable **and** JSON status, per-reason drop counters
  that tell you *why* traffic isn't flowing, per-peer health/`online` flags, and a
  **Prometheus** exporter for alerting.
- **Simple, declarative config** — describe a node as a `hub` or a `spoke` and the
  forwarding table is derived for you. Name your peers so `status` reads `bj-office-gw`,
  not `id=2`.

## Quick start

The fastest path is the container image (the hub is typically a public cloud host):

```bash
# 1. Create a config — one hub, one or more spokes.
cp config.example.json config.json
#    Set a UNIQUE 64-hex key on every peer link:  openssl rand -hex 32

# 2. Run it (the tunnel needs the TUN device + NET_ADMIN).
docker run -d --name subnetra \
    --cap-add=NET_ADMIN --device=/dev/net/tun \
    -v "$PWD/config.json":/etc/subnetra/config.json:ro \
    ghcr.io/jamiesun/subnetra:latest

# 3. Check it.
docker exec subnetra subnetra status
```

Prefer a bare binary? Grab the static build for your architecture from the
[latest release](https://github.com/jamiesun/subnetra/releases/latest), then follow the
**[Installation](getting-started/installation.md)** and **[Quick Start](getting-started/quickstart.md)**
guides. A full hub + two-spoke production walkthrough lives in
**[Production Deployment](operations/deployment.md)**.

## Operate & observe

`subnetra status` turns the silent, by-design packet drops into countable signals so
you can tell *why* traffic is or isn't flowing:

```text
subnetra v0.6.0 [running]
mode=raw_direct local_id=1 udp_port=18020 tun=snr0 peers=2
peers:
  id=2 name=bj-office-gw endpoint=203.0.113.2:18020 allowed_src=10.0.0.2/32
  id=3 name=alice-laptop endpoint=203.0.113.3:18020 allowed_src=10.0.0.3/32
traffic: tun_rx / udp_tx / udp_rx / tun_tx / relay / keepalive …
drops:   unknown_peer / auth_or_invalid / spoof / no_route …
```

`subnetra status --json` emits the same data as a stable, versioned JSON object — with a
per-peer `last_seen_age_seconds` and `online` flag — and a drop-in **Prometheus** exporter
turns it into scrapeable metrics. See
**[Observability & Troubleshooting](operations/observability.md)** for the full status
schema, the drop taxonomy, and alerting examples.

## How to read these docs

- New here? Start with **[Installation](getting-started/installation.md)** and the
  **[Quick Start](getting-started/quickstart.md)**.
- Want to understand the design? Read **[Architecture](concepts/architecture.md)**
  and the **[Security Model](concepts/security-model.md)**.
- Setting up a config? See the **[Configuration Reference](configuration/reference.md)**
  and **[Roles](configuration/roles.md)**.
- Going to production? Follow **[Production Deployment](operations/deployment.md)**,
  **[Containers](operations/containers.md)**, **[RouterOS Spoke](operations/routeros.md)**,
  or the **[macOS Spoke](operations/macos-spoke.md)** runbook.
- Building another implementation? The **[Wire Protocol](reference/wire-protocol.md)**
  is the normative contract.

## Project status

The framework, the pure-algorithm layer, and the syscall data path (TUN, the
readiness reactor, AF_UNIX control plane, daemon main loop) are implemented and
exercised end-to-end in the dev container, with a native macOS `utun`/`poll(2)`
spoke behind the comptime `src/os/` backend. v1 (`raw_direct` + PSK + anti-replay
+ RCU policy) is the deliverable; v2 reliability modes (`kcp_arq`, `fec_xor`) are
reserved interface points only — see the **[Roadmap](reference/roadmap.md)**.

## License

[MIT](https://github.com/jamiesun/subnetra/blob/main/LICENSE) © 2026 jettwang.
