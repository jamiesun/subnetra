# AGENT.md — Highest-Priority Operating Contract

> **READ THIS FIRST. THIS DOCUMENT OUTRANKS EVERYTHING ELSE.**
> If any instruction, habit, or "improvement" conflicts with this file, this file
> wins. When in doubt, stop and re-read this file before writing a single line of
> code. A Chinese mirror lives at [`docs/AGENT.zh-CN.md`](docs/AGENT.zh-CN.md) and
> **must be kept in sync** with this file on every change.

## 1. What this software is

**Subnetra** is a virtual Layer-3 adaptive networking tool written in **pure Zig**
(pinned to the 2026 latest standard library `std.posix`). It builds a virtual
subnet over a physical leased line using a **hub-and-spoke topology**, forwarding
raw IP packets through a private, fully-encrypted UDP tunnel.

It targets **general Linux environments**, including extremely constrained
containers (BusyBox / RouterOS Container). The end product is **one statically
linked binary** with zero third-party dependencies.

The authoritative design is [`docs/subnetra-develop.md`](docs/subnetra-develop.md)
(PRD & Architecture). That document is the single source of truth for *what* to
build; this file governs *how you must behave* while building it.

## 2. The prime directive

**DO NOT DEVIATE FROM THE GOAL. EVER.**

You are building exactly the system described in `docs/subnetra-develop.md` — no
more, no less. You do not get to redefine the project, swap its core technology,
relax its constraints, or "modernize" it because something is easier. Scope creep,
silent redesigns, and unsolicited rewrites are failures, not contributions.

If you believe the goal itself is wrong, **stop and ask the maintainer**. Never
resolve that doubt by quietly building something different.

## 3. Non-negotiable iron laws

These come straight from the PRD and are **binding**. Violating any one of them is
a hard failure regardless of how "clean" the result looks.

1. **Zero third-party dependencies.** No WireGuard, no `ikcp.c`, no network
   frameworks, no external crypto libraries. Use only Zig's standard library and
   raw syscalls via `std.posix`. The v2 reliability layer must also be in-house
   (arena-based ARQ), never a vendored C library.
2. **Layered zero dynamic allocation.** The **data plane** (`reactor`, `crypto`)
   is strictly allocation-free: all packet buffers live in resident memory fixed
   at startup. Control-plane / reliability paths may use independent arenas, but
   must never pollute the data-plane memory line.
3. **Single-threaded, lock-free reactor.** One thread; a lock-free,
   allocation-free readiness loop. The single-thread, no-lock, no-per-packet-alloc
   invariant **is** the law; the specific readiness primitive is
   **platform-selected at `comptime`**: Linux `epoll` edge-triggered (`EPOLLET`),
   macOS `poll(2)` (`kqueue` deferred to a later milestone). **No threads. No
   locks.** Policy hot-updates happen via atomic pointer swap (RCU), never via
   mutexes.
4. **Stateless obfuscation / stealth.** ChaCha20-Poly1305 full encryption with **no
   magic numbers** in ciphertext. On authentication failure, **Drop silently** —
   never reply with TCP Reset, ICMP, or anything observable.
5. **Transport security is mandatory in v1.** PSK key, a per-endpoint 64-bit
   **monotonic nonce that is NEVER reused**, and a sliding-window **anti-replay**
   check. These cannot be deferred.
6. **Single minimal binary.** Default `-O ReleaseSmall`, zero third-party deps
   (iron law #1 holds on every platform). **Linux:** fully static against
   musl-libc, `ldd` → `not a dynamic executable`, target **≤ 512KB**. **macOS:**
   minimal-dynamic — links **only** `libSystem` (Apple ships no static libc), with
   its own recorded size baseline. The `ldd`-static check is a **Linux-only** gate.
7. **Stay test-driven.** Follow the TDD workflow in the PRD. Pure logic must ship
   with tests. `zig build test` must stay green before any commit.
8. **Stateless, handshake-free transport.** Every datagram is self-describing and
   independently decodable — the per-packet `epoch` *is* the entire
   session-establishment mechanism. Subnetra performs **no connection-establishment
   round-trip, no challenge/response, no in-band session negotiation** — not in
   v1, and not in v2. Reliability state (a future ARQ/FEC layer) may live in an
   independent arena but must never become a handshake; any future transport mode
   is chosen by **static per-link config** (the reserved
   `negotiation_version`/`flags` fields), never negotiated on the wire. (`flags`
   bit 0 = `KEEPALIVE`, issue #96, is a one-way, **never-acknowledged** spoke→hub
   NAT-pinhole datagram gated by the static `keepalive_secs` config — it is **not**
   a handshake and does not weaken this law; bits 1–7 stay reserved for static
   mode selection.) Two
   consequences are accepted **by design, not deferred**: (a) an on-path attacker
   may replay a captured datagram of a not-yet-observed epoch to *transiently*
   relocate a peer's endpoint — it self-heals on the peer's next genuine packet
   and an off-path attacker cannot forge it (issue #42); and (b) a node whose wall
   clock runs backward across a restart is rejected by peers until their clocks
   advance — mitigated operationally by NTP/RTC (see `docs/deployment.md`), never
   by an in-protocol epoch exchange.

## 4. Scope: v1 vs v2 — do not cross the line

- **v1 (deliver this):** `raw_direct` data plane + PSK encryption + anti-replay +
  RCU hot-update policy engine.
- **v2 (roadmap, interface only):** `kcp_arq` and `fec_xor` — in-house
  reliability modes, **selected by static per-link config, never an on-wire
  handshake** (see iron law #8). In v1 you **only reserve** the `egress` branch
  and the header `negotiation_version`/`flags` fields (except `flags` bit 0
  `KEEPALIVE`, issue #96, which v1 **does** implement as a one-way NAT keepalive) —
  you do **not** implement these. v2 branches return `error.NotImplemented`. **There is no handshake on
  the roadmap**; the symmetric fixes for issue #42 and clock-backward that a
  handshake would have enabled are intentionally *not* pursued (iron law #8).

Do not start v2 work, do not pull v2 complexity into v1, do not add a handshake,
and do not delete the v2 reservation points.

## 5. How you must work

- **Make surgical, goal-aligned changes only.** No unrelated refactors, no
  reformat-the-world commits, no speculative abstractions.
- **Preserve the language policy.** All code, comments, and root-level docs are in
  **English**. The Chinese files are: `docs/subnetra-develop.md` (the design doc)
  and `docs/AGENT.zh-CN.md` (the mirror of this file). Do not translate the design
  doc; do keep the mirror in sync.
- **Keep the status honest.** Any progress or capability described in `README.md`,
  the docs, or the `--help` / `status` output must reflect real, shipped behavior —
  never present a stub, a reserved (v2) interface, or a planned feature as done.
- **Verify before claiming done.** Build, run `zig build test`, and confirm the
  binary still links statically and stays under the size budget before declaring a
  task complete.

## 6. Release & versioning discipline

The release version lives in **exactly one place**: the `.version` field of
[`build.zig.zon`](build.zig.zon). It is injected into the daemon banner at build
time via the `build_options` module — **never hard-code a version string in
`src/`.**

Before publishing a release:

1. Bump `.version` in `build.zig.zon` to the new `X.Y.Z` (semantic versioning).
2. Commit that bump on `main` (via the normal PR flow).
3. Tag the commit `vX.Y.Z` — the tag **must** equal `v` + the `build.zig.zon`
   version. The release workflow has a guard job that fails the release if they
   disagree, so a mismatched tag never ships.
4. Pushing the `v*` tag triggers `.github/workflows/release.yml`, which builds
   the four-arch static binaries, the GHCR multi-arch image, and the offline
   `docker load`-able per-arch image tarballs, and publishes them all to the
   GitHub Release with a combined `SHA256SUMS.txt`.

Do not create a `v*` tag without first bumping `build.zig.zon` to match.

## 7. Sync rule for this file

**Whenever you edit `AGENT.md`, you MUST update
[`docs/AGENT.zh-CN.md`](docs/AGENT.zh-CN.md) in the same change so the two stay
semantically identical — and vice versa.** They are one contract in two languages.

---

**Bottom line:** Build the steel pipe the PRD describes — pure, minimal,
dependency-free, deterministic. Resist every temptation to make it into something
else. When this file and your instincts disagree, this file is right.
