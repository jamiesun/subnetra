# Subnetra System Requirements & Architecture Design (PRD & Architecture)

This document provides a fully closed-loop system context for an **advanced AI agent** (e.g. Claude 4.8 Opus). It is **test-driven development (TDD)** oriented, targets the extremely constrained **RouterOS Container (BusyBox environment)** scenario, and guides the agent through independently implementing every module, from raw syscalls to the control-plane policy engine.

## 1. Vision & Constraints

Subnetra is a virtual Layer-3 adaptive networking tool written in **pure Zig (pinned to the 2026 latest standard library `std.posix`)**. The system is optimized for domestic/overseas leased-line environments: it completely abandons high-overhead dynamic obfuscation and pursues nothing but maximum throughput and determinism.

### Iron laws the AI agent must obey absolutely

1. **Layered zero dynamic allocation.** Memory constraints are layered by responsibility — no blanket rule.
   - **Data plane (reactor / crypto): strictly allocation-free.** All packet buffers and forwarding paths must be locked into static resident memory at startup via a `FixedBufferAllocator`; any implicit or frequent `alloc`/`free` at runtime is forbidden. This is the core of the performance story and must be defended at all costs.
   - **Control plane & reliability layer (uds / policy rebuild / future KCP, FEC): independent arenas allowed.** These paths may allocate in arenas physically isolated from the data plane, with independently reclaimed lifetimes, and must never pollute the data plane's resident memory line.
   - The "0-byte RSS variation" acceptance criterion applies only to data-plane (`raw_direct`) load tests; control-plane hot updates may cause brief, reclaimable arena churn.
2. **Single-threaded event-driven reactor.** Threads are strictly forbidden. Must be built on Linux epoll edge-triggered (`EPOLLET`) async multiplexing of `TUN_FD`, `UDP_FD`, and `UDS_FD`. Because the whole process is single-threaded, **there is no data-plane/control-plane concurrency, and introducing any lock is forbidden**; policy hot updates happen via atomic pointer swap (see the RCU model below).
3. **Fully stateless obfuscation.** Transport packets use ChaCha20-Poly1305 full encryption. Ciphertext must contain no fixed magic numbers. Peer authentication failure must result in a silent Drop — never reply with a TCP Reset or ICMP message — achieving physical invisibility to external probes.
4. **Transport-security iron law (keys / nonce / anti-replay).** The tunnel's lifeline; must land in v1, cannot be deferred.
   - **Keys:** v1 uses **private per-peer pre-shared keys (per-peer PSK, issue #13)**: every `peers[]` entry carries its own `psk` field (32 bytes, 64 hex chars); there is no mesh-wide top-level `psk` any more (a legacy config still carrying a top-level `psk` is rejected with `InvalidPsk`). One private key per hub link; link keys are still derived via `deriveLinkKey(peer_psk, from_id, to_id)`, so compromising one spoke's PSK cannot derive or forge any other link. Reusing the same PSK across multiple peers is rejected with `DuplicatePsk`. **Handshake-freedom is a permanent design constraint (see `AGENT.md` iron law #8): this protocol performs no connection-establishment round-trip and no session negotiation.** The negotiation-version fields reserved in the v1 header and config structure exist only for future **static per-link configuration selection** of transport modes — never for an on-wire handshake.
   - **Nonce:** ChaCha20-Poly1305 in a FixedBuffer setting **absolutely forbids fixed or reused nonces**, or the authentication guarantee collapses on the spot. Each endpoint maintains an independent 64-bit monotonically increasing counter as the nonce source, incremented on every send, eliminating cross-session reuse.
     - **Session epoch / boot nonce (issue #14, shipped):** No disk persistence (iron law: no persisted state). At startup the daemon samples `boot_epoch = CLOCK_REALTIME nanoseconds` (u64) once and derives a **per-session key** `session_key = Blake2b256(link_key, "subnetra-v1-session" || epoch_be)`. Every restart yields a fresh session key, so the sequence number can safely restart at 1 without ever repeating a historical `(key, nonce)` pair. `boot_epoch` travels with every packet (8 bytes, no handshake): the receiver derives the matching key statelessly per epoch and applies a **forward-only** ruling — a larger (later) epoch, once authenticated, supersedes the old session and **resets the anti-replay window** (fixing the availability bug where a one-sided restart left the window ahead and rejected new traffic); a smaller epoch is dropped outright (blocking cross-epoch replay of retired sessions). Authentication always completes before any receive state is mutated; a forged high epoch cannot poison the session.
     - **Fail-closed:** An unavailable clock, or a wall clock reporting earlier than 2024-01-01 (no RTC / not NTP-synced), is treated as a fatal error and the daemon refuses to start, avoiding a 0/too-low, collision-prone epoch.
     - **Documented residual limitation:** If a node's wall clock **goes backward** across a restart (no RTC and not yet NTP-synced), its new epoch may be smaller than the old epoch the peer remembers; the peer will reject the new session until the wall clock passes the old value. Operations must keep clocks monotonic across restarts (RTC/NTP), or restart both ends together. **This is an accepted design trade-off, not a defect to fix**: because there is no handshake (iron law #8), no symmetric fix via bidirectional epoch exchange exists; the limitation is mitigated only at the operations layer (NTP/RTC, see `docs/deployment.md`).
   - **Anti-replay:** The receiver maintains a sliding window (e.g. a 64-bit bitmap) to validate sequence numbers; anything outside the window or already seen is dropped. Stateless UDP transport must be paired with anti-replay, or historical ciphertext could be replayed into the private network.
5. **Single-binary artifact.** The build product must be a fully statically linked standalone binary (musl-libc based). The size budget is uniform: with `-O ReleaseSmall` the target is **≤ 512KB**, and the overall Docker image compresses to within **4MB**. (If `ReleaseFast` is chosen for throughput, relax the size cap and document the trade-off in a `build.zig` comment.)

## 2. System Architecture

### 1. Network topology and virtual-layer data flow

The system uses a **hub-and-spoke (star) topology**. An overseas relay node acts as the hub; spoke clients (e.g. RouterOS containers) attach over private UDP tunnels, building a virtual `10.0.0.0/24` subnet on top of the physical leased line, with cross-subnet (e.g. `192.168.1.0/24`) site-to-site routing.

```text
[LAN traffic] -> [RouterOS kernel] -> (route points at tun0) -> [/dev/net/tun]
                                                                     |
    +----------------------------------------------------------------+
    | (non-blocking epoll edge-triggered read of raw IP packets)
    v
[Subnetra core reactor]
    |
    ├── 1. Read the raw IP header (extract Src IP / Dst IP)
    ├── 2. Atomically load the active_tree pointer (lock-free read; FORWARD or DROP)
    ├── 3. Assemble the private header (packed struct: incl. 8B sequence number/nonce)
    ├── 4. Dispatch via egress (v1 ships raw_direct only; KCP/FEC are reserved v2 branches)
    └── 5. ChaCha20-Poly1305 encryption (nonce = sequence number, append 16B tag)
    |
    v
[Physical UDP socket] -> (public leased-line tunnel, latency < 100ms) -> [overseas relay hub]
```

### 2. Key memory model

- **Private header:** A physically aligned Zig packed struct. The header must hold: 1-byte version, 1-byte flags, 2-byte `key_id` (issue #34 — the sender's own mesh id; the receiver uses it to select the peer PSK and session, enabling endpoint relearning under NAT/roaming; the field sits outside the AEAD, so tampering only selects the wrong key and fails authentication), **8-byte session epoch (issue #14 — identifies the sender's current session lifetime so the receiver can statelessly derive the session key and scope anti-replay per session)**, and an **8-byte monotonically increasing sequence number (doubling as the ChaCha20-Poly1305 nonce and the anti-replay basis)**. The header length is recomputed from the fields and currently measures **20 bytes** (per the packed struct's actual alignment; a comptime assertion guards `HEADER_LEN == 20`). Mind the MTU accounting: outer UDP datagram = header(20) + ciphertext + tag(16) + UDP(8) + IP(20); deployments must budget `local_tun_mtu` accordingly to avoid fragmentation.
- **Concurrency control (lock-free RCU model):** Single-threaded throughout, **no locks of any kind**. The policy tree is read atomically by the data plane as a `*const PolicyTree` (`@atomicLoad`). When the control-plane UDS injects rules, it **builds an entirely new tree** in an independent arena, then swaps the `active_tree` pointer wholesale with a single `@atomicStore` (RCU style); the old tree is reclaimed at the next idle point of the event loop. The data plane only ever reads one immutable pointer — hot replacement is zero-copy and jitter-free.

## 3. Feature List & Implementation Spec

### Module 1: Data-plane core reactor

- [ ] **Async TUN attachment:** Open `/dev/net/tun` via raw syscalls, instantiate the virtual NIC with ioctl, set `O_NONBLOCK`.
- [ ] **epoll blind-forwarding engine:** Uniformly schedule `TUN_FD` and the external `UDP_FD`, drain the kernel buffer in a loop with `MSG_DONTWAIT`, and precisely catch and handle `EWOULDBLOCK`.
- [ ] **Adaptive multi-mode flow control (interface reserved, phased delivery):** All egress goes through a single `egress(mode, pkt)` dispatch (tagged union / vtable); adding a mode only adds a branch and never touches the main loop.
  - **v1 (must ship)** `raw_direct`: skip all retransmission, MTU 1452 bytes.
  - **v2 (roadmap; interface reserved, branch returns `error.NotImplemented` for now)** `kcp_arq`: an **in-house** arena-based ARQ in the control/reliability arena (never vendoring ikcp.c or other third-party C — their internal malloc conflicts with the zero-allocation iron law), absorbing minor leased-line loss, MTU 1428 bytes.
  - **v2 (roadmap)** `fec_xor`: in-house forward error correction. Note: 4:1 XOR only recovers "exactly 1 loss per 5 packets" and is useless against burst loss; the v2 design must re-evaluate the coding strategy (higher redundancy or interleaving).

### Module 2: Multi-subnet command-line policy engine (Policy Engine & CLI)

- [ ] **Dynamic CIDR parsing:** Efficiently parse strings like `"192.168.1.0/24"` into a u32 network number and mask.
- [ ] **Unix Domain Socket (UDS) transport:** The daemon listens on `/run/subnetra/subnetra.sock` (`/var/run/subnetra.sock` on macOS).
- [ ] **Standalone control tool `subnetra`:** A 20KB lightweight client that sends plaintext commands to the main process over UDS:
  - `subnetra policy add --src X --dst Y --action forward --target Z`
  - `subnetra policy show`
  - `subnetra save` (makes the main process serialize the in-memory policy tree back over the config file)

### Module 3: Startup & configuration snapshot

- [ ] **Safe `std.json` ingestion:** Parse `config.json` once at startup; if the file is missing, fall back to the comptime hard-coded default baseline config.
- [ ] **Fool-proof sanity check:** Enforce that the MTU lies in a sane range (68–1500), automatically check that the virtual subnet does not overlap the ROS host's physical subnet, and abort startup on any violation.

## 4. Task Backlog

The AI agent must proceed through the following atomic tasks in order, in **TDD mode**:

- [ ] **Task 1 (build config):** Write `build.zig`. Support fully static cross-compilation for `-target x86_64-linux-musl` and `-target aarch64-linux-musl`. Default `-O ReleaseSmall`, strip debug info, minimize size (target ≤ 512KB).
- [ ] **Task 2 (config sanity):** Write `config.zig`. Implement the JSON parser and the comptime fallback config; define the private per-peer `peers[].psk` and the negotiation-version field. Write test cases proving illegal MTU input is rejected.
- [ ] **Task 3 (policy matching):** Write `policy.zig`. Define the `PolicyEntry` struct and implement reverse-order longest-prefix matching with bit operations (`ip & mask`). **No locks**; the policy tree exposes an atomic read-only `*const PolicyTree` interface plus one `swap(new_tree)` atomic pointer-swap interface (RCU), verified by a unit test proving "the old pointer remains safely readable after a hot swap".
- [ ] **Task 4 (system driver):** Write `tun.zig`. Use the latest `std.posix` for the ioctl syscalls and complete dependency-free virtual-NIC initialization.
- [ ] **Task 5 (crypto pipeline):** Write `crypto.zig`. Wrap `std.crypto.stream.chacha20.ChaCha20Poly1305`, implementing fixed-size-slice encryption and authentication with zero runtime allocation. **The nonce derives from each endpoint's 64-bit monotonic counter and is never reused**; the receiver implements sliding-window anti-replay validation.
- [ ] **Task 6 (core reactor):** Write `reactor.zig`. Build the single-threaded `epoll_wait` closed-loop state machine. Handle TUN-readable, UDP-readable, and UDS-readable events, implementing non-blocking blind forwarding of raw data; egress goes through the dispatch (v1 ships `raw_direct` only).
- [ ] **Task 7 (control-plane UDS):** Write `uds.zig`. Create the local Unix-domain-socket listener and a string tokenizer; rebuild the policy tree in an arena, then call `policy.zig`'s atomic swap interface (lock-free injection).
- [ ] **Task 8 (control tool):** Write `subnetra.zig`. Implement the minimal branch logic that packs terminal command-line arguments into a text stream and throws it at the main process over UDS.

> **Phasing note:** v1 delivers only the `raw_direct` data plane + PSK encryption + anti-replay + RCU hot-updated policy. `kcp_arq` / `fec_xor` are the v2 roadmap — only the `egress` branch and the header negotiation field are reserved; they are not implemented in v1. **There is no handshake on the roadmap — any transport mode is selected by static per-link configuration (iron law #8), never negotiated on the wire.**

## 5. TDD Test Cases & Acceptance Criteria

The agent may declare delivery only after passing the following test cases and real-world scenario checks:

### 1. Unit-test coverage requirements

During development, the agent must keep the following assertions green via `zig test src/main.zig`:

- **`test "JSON Parser & Sanity Check"`**: input `local_tun_mtu: 9000` triggers an assertion error; invalid JSON aborts parsing.
- **`test "CIDR Overlap & Matching"`**: with both `0.0.0.0/0` (DROP) and `192.168.2.0/24` (FORWARD) in the rule tree, traffic to `192.168.2.100` must hit FORWARD and traffic to `8.8.8.8` must hit DROP.
- **`test "RCU Hot-Swap"`**: while the data plane holds the old `active_tree` pointer, perform one `swap(new_tree)`; the old pointer must still read the original rules safely, new reads must hit the new rules, and the whole sequence must be lock-free with zero data-plane allocation.
- **`test "Crypto Invariance"`**: 1000 randomly generated raw IP packets must each grow by exactly 16 bytes (the tag) after encrypt, and decrypt must reproduce the plaintext exactly.
- **`test "Nonce Monotonic & Anti-Replay"`**: consecutive encryptions must produce strictly increasing, never-repeating nonces; the receiver must Drop out-of-window or already-seen sequence numbers and accept out-of-order ones inside the window.

### 2. Runtime final acceptance checklist

- [ ] **Zero-dependency check:** Running `ldd ./subnetrad` on a Linux terminal must print `not a dynamic executable` (purely static linking).
- [ ] **Size check:** `ls -lh ./subnetrad` must show the binary under **512KB**.
- [ ] **No-memory-leak check:** Deploy in a BusyBox container and watch resident memory (RSS) with `top` or `pmap`. After 10 minutes of gigabit large-packet load on the leased line, the memory line must be perfectly flat — **0 bytes** of variation.
- [ ] **Active-probe resistance check:** Use a third-party tool (e.g. `nc -u`) to send invalid binary junk (including replayed old ciphertext) at the running Subnetra relay's UDP port. The relay's CPU must show no abnormal spike, and packet capture must show the peer **replies with nothing at all (a perfect Drop)**; replayed packets must be blocked by the sliding window.
- [ ] **Dynamic policy hot-update check:** While the network is live, run `./subnetra policy add --src 192.168.1.0/24 --dst 192.168.2.0/24 --action forward --target 3`; the latency jitter of an in-flight upper-layer TCP throughput test must not exceed **2ms**, proving the atomic pointer swap (RCU) and the non-blocking event reactor's zero-copy hot replacement work flawlessly.

---

**Punchline (the agent's final reminder):** Keep the code pure. Reject every third-party network framework (including ikcp.c); the v2 reliability layer must also be an in-house arena ARQ; hold tight to the latest `std.posix`. Remember: v1 ships only the `raw_direct` data plane + PSK encryption + anti-replay + RCU hot updates; KCP/FEC are interface reservations only (**no handshake — iron law #8**). When you are ready to build this steel pipe purpose-fitted to the RouterOS container, start by generating Task 1's `build.zig` and Task 2's config-sanity unit tests.
