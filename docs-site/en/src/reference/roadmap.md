# Roadmap

Subnetra deliberately ships a small, finished **v1** and reserves a narrow set of
**v2** interface points. This page describes what is delivered, what is reserved,
and — just as importantly — what will **never** be built.

## v1 — delivered

The shipping data plane is `raw_direct`: a stateless, allocation-free,
handshake-free tunnel with:

- ChaCha20-Poly1305 full encryption with per-link keys + per-restart session epoch,
- 64-bit monotonic nonce + sliding-window anti-replay,
- a CIDR longest-prefix policy engine with lock-free RCU hot updates,
- a single-threaded reactor (Linux `epoll` / macOS `poll(2)`),
- a normative [wire protocol](wire-protocol.md) pinned by known-answer vectors.

See the [development status table](https://github.com/jamiesun/subnetra#-development-status)
for module-by-module progress.

## v2 — reserved interface points only

The PRD reserves two **in-house** egress modes for lossy/long-haul leased lines.
They are **design-only** today — the branches return `error.NotImplemented` and no
code is authorized until the maintainer signs off on the design RFC
([`docs/v2-reliability-rfc.md`](https://github.com/jamiesun/subnetra/blob/main/docs/v2-reliability-rfc.md)):

| Mode | Idea | Inner MTU |
|---|---|---|
| `kcp_arq` | Arena-based selective-repeat ARQ to absorb small, sporadic leased-line loss (no `ikcp.c` — in-house) | 1428 |
| `fec_xor` | Forward error correction (naïve 4:1 XOR is known to be inadequate; the real design must do better) | 1428 |

The reservation points that already exist in the tree:

| Reservation | Where it lives |
|---|---|
| `EgressMode { raw_direct, kcp_arq, fec_xor }` | `src/reactor.zig` (v2 ⇒ `error.NotImplemented`) |
| `mtuFor(mode)` → 1452 / 1428 / 1428 | `src/reactor.zig` |
| `flags` header byte (MUST be `0` in v1, except `KEEPALIVE`) | `src/reactor.zig`, `docs/PROTOCOL.md` |
| `negotiation_version` (per-config) | `src/config.zig` |

Crucially, a v2 mode is selected by **static per-link config**, never by an on-wire
handshake. The `negotiation_version` / `flags` fields exist for *static* mode
selection only.

## Explicit non-goals

These are not "not yet" — they are **never**, because they would break the
[design principles](../concepts/design-principles.md):

- **No on-wire handshake / challenge-response / capability exchange.** The
  per-packet epoch *is* session establishment.
- **No in-daemon health-probe or auto-switching path manager.** The data plane is
  single-path; failover is an **external** decision (see
  [Production Deployment → HA](../operations/deployment.md#8-high-availability)).
- **No in-tunnel scheduler / adaptive rate controller.** Traffic shaping is done at
  the OS layer with `tc`.
- **No third-party dependencies.** Not even for v2 reliability — the ARQ must be
  in-house.
- **No in-daemon DNS resolver.** Endpoints are numeric; a dynamic hub is solved
  operationally (DDNS watcher) on the spoke.

Changing any non-goal is an **RFC that amends the iron laws**, not a feature PR —
and is intentionally not on the backlog.

## The keepalive exception (already in v1)

The only addition under `wire_version = 1` is the one-way, never-acknowledged
spoke→hub NAT keepalive (`flags` bit 0). It is backward-compatible and is **not** a
handshake — see the [Security Model](../concepts/security-model.md#nat-keepalive-one-way-never-acknowledged).

## Acceptance matrix (Capability Coverage Matrix)

This section is the **acceptance chapter** of the roadmap. It registers, per
top-level business capability, how far it is verified and where the evidence
lives. The full matrix is maintained **only here**;
[`AGENT.md` §6](https://github.com/jamiesun/subnetra/blob/main/AGENT.md) and the
README carry the rules and a link, never a copy.

> **Coverage floor (hard rules — MUST level, never downgraded to advice):**
>
> 1. Every top-level capability has at least one **Happy-Path E2E** verification.
> 2. Every **high-risk** capability covers at least one **failure path**.
> 3. Every **permission-touching** capability is verified with at least **two
>    roles/principals**.
> 4. Every operation that **mutates system state** verifies at least one
>    **recovery or rollback after failure**.
> 5. Every **new top-level business capability** lands together with its E2E
>    **and** a new row in this matrix — a feature change without them is
>    incomplete.
>
> The matrix constrains *what must be proven and to what depth* — never the
> framework, directory layout, or test style. Evidence cells point at real test
> paths; a missing test is recorded as an explicit `❌ gap`, never invented.

**Role note:** Subnetra has no in-product user accounts. Its only permission
surface is the `0600` UDS control socket, so "two roles" maps to **socket owner
vs. any other principal**.

The primary E2E harness is [`test/integration/run.sh`](https://github.com/jamiesun/subnetra/blob/main/test/integration/run.sh)
(3-node netns hub-and-spoke star), run by the CI `integration` job on every PR
and by the release gate (where a SKIP is a hard failure).

| Capability | Risk | Happy-Path E2E | Failure path | Role coverage | Failure recovery / rollback | Evidence |
|---|---|---|---|---|---|---|
| Encrypted L3 data plane (spoke → hub relay → spoke) | High | ✅ end-to-end ping delivery across the 3-node star | ✅ delivery under 10% underlay loss + 20 ms delay (netem) | n/a (no roles on the data path) | ✅ clean delivery resumes after the impairment is removed | `test/integration/run.sh` |
| Transport security (per-link keys, anti-replay, silent-drop stealth) | High | ✅ on-wire encryption proven by capture (plaintext marker absent on underlay) | ✅ junk + forged datagrams: zero replies on the wire, daemon survives | n/a | n/a — the verdict path is read-only (drop); nothing to roll back | `test/integration/run.sh` (active-probe), `src/crypto.zig`, `src/protocol_vectors.zig` + `tests/protocol-vectors.json` |
| Policy engine & zero-downtime route updates (RCU) | High (mutates live routing state) | ✅ rule injected mid-stream, 20/20 pings delivered | ✅ malformed control datagram is rejected | Partial — `0600` socket binding asserted (`src/uds.zig`, #37); a second-principal **denial** E2E is a `❌ gap` | ✅ a rejected update leaves the active tree unchanged and serving | `test/integration/run.sh` (RCU assertion), `src/uds.zig`, `src/policy.zig` |
| Declarative config & role derivation (hub/spoke, `--check`) | Medium | ✅ role-only 3-node E2E with zero runtime policy commands (#21) | ✅ invalid configs rejected: MTU range, missing/duplicate PSK, subnet overlap, bad role shapes | n/a | n/a — validation is read-only; the daemon refuses to start | `test/integration/run.sh` (role-config), `src/config.zig` |
| NAT traversal (keepalive + endpoint roaming relearn) | High | ✅ hub relearns a roamed spoke (`endpoint_learned` counter rises), no restart | ✅ the roam itself: traffic from a stale endpoint until relearn (#34) | n/a | ✅ end-to-end delivery resumes after the endpoint move (self-healing) | `test/integration/run.sh` (roaming), `src/config.zig` (keepalive) |
| Observability (status text/JSON, drop taxonomy, Prometheus exporter) | Medium | ✅ counters move for real events (`tun:no_route`, `udp:unknown_peer`, `udp:auth_or_invalid`); JSON schema versioned, secrets never serialized | ✅ `status` replies `unavailable` before bind; client reports absent daemon / timeout | Partial — same UDS `0600` note as above | n/a — read-only | `test/integration/run.sh`, `src/uds.zig`, `src/stats.zig`; `❌ gap` — `deploy/subnetra-textfile-exporter.sh` has no automated test |
| Packaging & delivery (static ≤ 512 KB binary, container, OpenWrt / RouterOS / macOS) | Medium | ✅ static + size gates on native and foreign arch; OpenWrt procd smoke under qemu (nightly) | ✅ release gate turns any SKIP into a hard failure | n/a | n/a — build artifacts, no runtime state | `test/integration/run.sh`, `test/openwrt/run.sh`, `.github/workflows/release.yml`; macOS spoke: manual runbook `docs/macos-spoke-acceptance.md`; `❌ gap` — `deploy/routeros/` scripts verified manually only |

**Minimum expectation for each open gap:**

- *Control-socket second-principal denial:* an E2E step proving a non-owner uid
  gets `EACCES` on the live control socket (owner vs. non-owner = the two roles).
- *Textfile exporter:* a shell-level test that feeds a canned `status --json`
  and asserts the emitted metric lines.
- *RouterOS scripts:* a scripted smoke, or a recorded manual acceptance per
  release, for the `deploy/routeros/` bring-up/teardown.

**Maintenance:** adding a top-level capability adds a row (with its E2E, rule 5);
removing a capability removes its row. Cells cite real paths or say `❌ gap` /
"unverified" — this table must never be more optimistic than the tree.
