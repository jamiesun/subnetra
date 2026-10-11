//! Task 6 (issue #5): Core reactor (data-plane reactor).
//!
//! Single-threaded epoll edge-triggered loop: non-blocking forwarding between
//! TUN_FD and UDP_FD across a multi-peer hub-and-spoke mesh. Routing is driven
//! by the policy tree's `target` (Model A): a matched entry names either the
//! local TUN (`target == LOCAL_TARGET`) or a peer id to forward/relay to. Egress
//! is dispatched uniformly via `egress(mode, pkt)`; adding a mode only adds a
//! branch, never touches the main loop. v1 ships raw_direct only; kcp_arq /
//! fec_xor are v2 roadmap and return NotImplemented for now.
//!
//! Iron laws honoured here:
//! - Zero data-plane allocation: every packet buffer is resident in `Reactor`
//!   (rx, tx, and the `UdpBatch` recv/send buffer set used for batched hub
//!   forwarding — issue #100).
//! - Single-threaded, lock-free, epoll edge-triggered (EPOLLET); fds are forced
//!   non-blocking and each readable fd is drained until EAGAIN. UDP ingress is
//!   drained a batch at a time (one `recvmmsg`) and egress is coalesced (one
//!   `sendmmsg`); macOS keeps single recvfrom/sendto behind the same surface.
//! - Crypto auth failure / replay / malformed input are dropped silently.
//!
//! Security model (issue #5):
//! - Each peer has its own directional keys (`crypto.deriveLinkKey`), so per-peer
//!   nonce counters can never collide under the shared PSK.
//! - Inbound datagrams are filtered by source endpoint; the decoded inner IPv4
//!   source must fall inside the source peer's `allowed_src` prefix, defeating
//!   inner-source spoofing by an authenticated spoke.
//! - The hub never reflects a packet back to its source peer (no-reflect guard).
//!   Topology is single-hub hub-and-spoke; spokes do not relay.
//!
//! Control plane (issue #6): an optional `*uds.Control` listener is registered
//! level-triggered so `subnetra` can hot-swap the policy tree at runtime; the data
//! plane only ever reads the tree atomically and never blocks on control I/O.

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys.zig");
const os = @import("os/mod.zig");
const policy = @import("policy.zig");
const crypto = @import("crypto.zig");
const peer = @import("peer.zig");
const uds = @import("uds.zig");
const stats = @import("stats.zig");
const config = @import("config.zig");

/// Private wire header (packed struct, physically aligned): 1B version + 1B
/// flags + 2B key_id (issue #34, the sender's own mesh id, used by the receiver
/// to SELECT the candidate peer/key before authentication so a NATed/roaming
/// spoke is identified by its key rather than its source endpoint) + 8B boot
/// epoch (issue #14, identifies the sender's current session so the receiver can
/// derive the matching session key statelessly and scope anti-replay per
/// session) + 8B monotonic sequence number (doubles as the nonce and anti-replay
/// basis). 20 bytes total. The header is serialized field-by-field (see
/// `encodeEgress`/`decodeIngress`) rather than by memory layout, so the wire
/// format is endian-stable.
pub const WireHeader = packed struct {
    version: u8 = 1,
    flags: u8 = 0,
    /// Sender mesh id (issue #34). An UNAUTHENTICATED selector: the receiver
    /// uses it only to pick which peer's key to try; a tampered value selects a
    /// wrong key and fails authentication (fail-closed). Little-endian on wire.
    key_id: u16 = 0,
    /// Sender boot epoch (wall-clock ns at startup); never zero.
    epoch: u64,
    seq: u64,
};

pub const HEADER_LEN = @divExact(@bitSizeOf(WireHeader), 8);

/// On-wire protocol version for v1.
pub const WIRE_VERSION: u8 = 1;

/// `WireHeader.flags` bit 0 (issue #96): this datagram is a one-way spoke→hub
/// keepalive, not a tunnelled packet. Its sealed body carries NO inner IP packet
/// (zero-length plaintext). The hub authenticates it like any datagram, uses it
/// only to keep the NAT pinhole open and refresh the learned endpoint, then drops
/// it before any inner-IPv4 parsing or routing. Every other flag bit stays
/// reserved (must be zero); a datagram setting one is dropped by `decodeIngress`.
pub const FLAG_KEEPALIVE: u8 = 0b0000_0001;

/// Full-registry trial-scan budget per UDP drain when header obfuscation is on
/// (issue #174). The source-endpoint fast path resolves every steady-state
/// datagram with ONE keyed hash; only a datagram from an UNKNOWN source endpoint
/// (a genuinely roamed/restarted peer — or off-path junk with a spoofed source)
/// falls back to trialing every configured peer's rx link key. This budget caps
/// those fallback scans per `pumpUdpIngress` drain, bounding the worst-case
/// unauthenticated CPU amplification at `OBFS_SCAN_BUDGET * MAX_PEERS` keyed
/// hashes per drain instead of `packets * MAX_PEERS`. It refills every drain, so
/// a roaming peer locked out by a concurrent flood is only deferred one tick: its
/// next datagram (or keepalive) retries, wins a scan slot, authenticates, and its
/// new endpoint is learned back onto the O(1) fast path. Eight slots per drain
/// lets even a full 128-peer mesh re-home after a hub restart within a handful of
/// keepalive-driven drains while keeping the flood ceiling small.
pub const OBFS_SCAN_BUDGET: u32 = 8;

/// Egress flow-control mode. New modes add a branch here and in `egress`.
pub const EgressMode = enum {
    raw_direct, // v1: skip retransmission, MTU 1452
    kcp_arq, // v2: in-house arena-based ARQ, MTU 1428
    fec_xor, // v2: in-house forward error correction
};

pub fn mtuFor(mode: EgressMode) u16 {
    return switch (mode) {
        .raw_direct => 1452,
        .kcp_arq => 1428,
        .fec_xor => 1428,
    };
}

/// Largest tunnelled IP packet (v1 raw_direct MTU).
pub const MAX_PLAINTEXT: usize = mtuFor(.raw_direct);
/// Largest datagram that ever crosses the UDP socket: header + ciphertext + tag.
pub const MAX_WIRE: usize = HEADER_LEN + MAX_PLAINTEXT + crypto.TAG_LEN;
/// Resident packet buffer size. Sized with headroom for jumbo-ish reads while
/// staying comfortably above MAX_WIRE.
pub const BUF_LEN: usize = 2048;

comptime {
    std.debug.assert(BUF_LEN >= MAX_WIRE);
    std.debug.assert(HEADER_LEN == 20);
    // The batch's per-datagram buffer must match the reactor's wire buffer size
    // so a decoded packet always fits when re-sealed into an egress slot.
    std.debug.assert(os.UdpBatch.BUF == BUF_LEN);
}

pub const EgressError = error{NotImplemented};

/// Egress mode guard. v1 ships raw_direct only; the rest are v2-reserved
/// branches. The actual `sendto` happens in the reactor pump after this guard
/// admits the packet.
pub fn egress(mode: EgressMode, pkt: []const u8) EgressError!void {
    switch (mode) {
        .raw_direct => {
            _ = pkt;
        },
        .kcp_arq, .fec_xor => return EgressError.NotImplemented,
    }
}

/// Serialize the wire header for the session's next sequence number, seal
/// `ip_pkt` after it, and return the total wire length. Allocation-free: writes
/// straight into `out`. The header carries the session `epoch` so the receiver
/// can derive the matching session key (issue #14); the body is sealed with the
/// epoch-bound session key, and `seq` is drawn from the per-session monotonic
/// counter (never reused with the same key).
pub fn encodeEgress(tx: *crypto.TxSession, key_id: u16, ip_pkt: []const u8, out: []u8) usize {
    return encodeFramed(tx, key_id, 0, ip_pkt, out);
}

/// Seal a one-way keepalive (issue #96): the same header + seal path as a data
/// packet, but with the `KEEPALIVE` flag set and an EMPTY inner payload. Returns
/// the total wire length (`HEADER_LEN + crypto.TAG_LEN`). The sealed empty body
/// still authenticates and rides the monotonic nonce + replay window exactly like
/// a data packet, so it is not a handshake and needs no reply (iron law #8).
pub fn encodeKeepalive(tx: *crypto.TxSession, key_id: u16, out: []u8) usize {
    return encodeFramed(tx, key_id, FLAG_KEEPALIVE, &.{}, out);
}

/// Shared header serialization + seal for `encodeEgress` (flags 0) and
/// `encodeKeepalive` (flags `KEEPALIVE`, empty body). Allocation-free: writes
/// straight into `out`.
fn encodeFramed(tx: *crypto.TxSession, key_id: u16, flags: u8, ip_pkt: []const u8, out: []u8) usize {
    std.debug.assert(out.len >= HEADER_LEN + ip_pkt.len + crypto.TAG_LEN);
    const seq = tx.counter.next();
    out[0] = WIRE_VERSION;
    out[1] = flags;
    std.mem.writeInt(u16, out[2..][0..2], key_id, .little); // key_id (sender mesh id)
    std.mem.writeInt(u64, out[4..][0..8], tx.epoch, .little);
    std.mem.writeInt(u64, out[12..][0..8], seq, .little);
    const sealed = crypto.seal(tx.skey, seq, ip_pkt, out[HEADER_LEN..]);
    return HEADER_LEN + sealed;
}

/// Read the `key_id` selector (the sender's mesh id) from a datagram's header
/// without authenticating it. Returns `null` only if the datagram is too short
/// to hold a header. The value is untrusted until `decodeIngress` authenticates
/// the datagram under the selected peer's key.
pub fn parseKeyId(datagram: []const u8) ?u16 {
    if (datagram.len < HEADER_LEN) return null;
    return std.mem.readInt(u16, datagram[2..][0..2], .little);
}

/// XOR-mask the 20-byte cleartext header of a freshly-encoded datagram in place,
/// hiding the protocol's only fixed / low-entropy bytes (constant `version`,
/// `flags`, the small `key_id`, the repeated `epoch`, and the low monotonic
/// `seq`) behind a per-packet pseudorandom pad (`crypto.headerMask`). The pad is
/// keyed by the directional `link_key` (so the receiver, who shares it, can
/// reverse this) and salted by the datagram's own 16-byte AEAD tag, which rides
/// the wire in the clear after the header. The body (ciphertext + tag) is left
/// untouched — it is already indistinguishable from random — so after masking the
/// WHOLE datagram looks like uniform random bytes to an observer without the PSK.
/// `wire` must be a complete datagram (header ‖ ciphertext ‖ tag), i.e. at least
/// `HEADER_LEN + crypto.TAG_LEN` bytes.
pub fn obfuscateHeader(link_key: crypto.Key, wire: []u8) void {
    std.debug.assert(wire.len >= HEADER_LEN + crypto.TAG_LEN);
    const tag = wire[wire.len - crypto.TAG_LEN ..];
    var mask: [HEADER_LEN]u8 = undefined;
    crypto.headerMask(link_key, tag, &mask);
    for (wire[0..HEADER_LEN], 0..) |*b, i| b.* ^= mask[i];
}

/// Reverse `obfuscateHeader` for a candidate sender holding `link_key`. Computes
/// the de-mask pad from the (cleartext) tag, recovers the would-be header, and
/// only commits — de-masking `wire`'s header IN PLACE — when the recovered header
/// is self-consistent for this peer: `version == WIRE_VERSION` AND the embedded
/// `key_id == expect_id`. A wrong key yields effectively random header bytes that
/// clear both checks with probability < 2^-24, so trialing each configured peer's
/// receive link key reliably resolves the real sender. The subsequent AEAD
/// authentication in `decodeIngress` is the actual security gate: a (vanishingly
/// rare) false pre-filter match simply fails there and the datagram is dropped,
/// exactly like any other unauthenticated packet. Returns true and mutates `wire`
/// on a match; returns false and leaves `wire` untouched otherwise. The caller
/// guarantees `wire.len >= HEADER_LEN + crypto.TAG_LEN`.
pub fn tryDeobfuscate(link_key: crypto.Key, expect_id: u32, wire: []u8) bool {
    std.debug.assert(wire.len >= HEADER_LEN + crypto.TAG_LEN);
    const tag = wire[wire.len - crypto.TAG_LEN ..];
    var mask: [HEADER_LEN]u8 = undefined;
    crypto.headerMask(link_key, tag, &mask);
    if ((wire[0] ^ mask[0]) != WIRE_VERSION) return false;
    const kid = std.mem.readInt(u16, wire[2..][0..2], .little) ^ std.mem.readInt(u16, mask[2..][0..2], .little);
    if (@as(u32, kid) != expect_id) return false;
    for (wire[0..HEADER_LEN], 0..) |*b, i| b.* ^= mask[i];
    return true;
}

/// Parse, authenticate, then anti-replay check an inbound datagram against the
/// receive session. Writes the recovered IP packet into `out` and returns its
/// length, or `null` if the datagram must be dropped (malformed header,
/// stale/zero epoch, auth failure, or replay).
///
/// The header `key_id` (bytes [2..4]) is NOT validated here: it is the caller's
/// peer selector (see `parseKeyId`/`pumpUdpIngress`) and carries no meaning to
/// the receive session, which has already been chosen by it. A wrong `key_id`
/// selects a wrong key upstream and surfaces here as an authentication failure.
///
/// Session-epoch handling (issue #14) is forward-only: the highest
/// authenticated epoch wins. A packet from an older epoch than the one in force
/// is dropped before any crypto (cheap, and it rejects cross-session replay of a
/// retired lifetime). A packet from a newer epoch, once authenticated, adopts
/// that epoch and RESETS the replay window — this is what lets a one-sided
/// sender restart re-establish a fresh accepted session instead of being stuck
/// behind a window that ran ahead. Authentication always runs BEFORE any state
/// is mutated, so a forged higher epoch (or sequence number) can never poison
/// the session.
pub fn decodeIngress(rx: *crypto.RxSession, datagram: []const u8, out: []u8) ?usize {
    if (datagram.len < HEADER_LEN) return null;
    if (datagram[0] != WIRE_VERSION) return null;
    if (datagram[1] & ~FLAG_KEEPALIVE != 0) return null; // only the KEEPALIVE flag (bit 0) is defined; other bits reserved
    const pkt_epoch = std.mem.readInt(u64, datagram[4..][0..8], .little);
    if (pkt_epoch == 0) return null; // zero is the "no session" sentinel, never valid on the wire
    const seq = std.mem.readInt(u64, datagram[12..][0..8], .little);

    // Forward-only: a strictly older epoch than the one in force is a retired
    // session (or a cross-epoch replay). Drop before spending any crypto.
    if (rx.epoch != 0 and pkt_epoch < rx.epoch) return null;

    // Steady state reuses the cached session key; a newer (or first) epoch
    // derives a candidate key that is only committed after authentication.
    const key = if (pkt_epoch == rx.epoch) rx.skey else crypto.deriveSessionKey(rx.link_key, pkt_epoch);

    const ct = datagram[HEADER_LEN..];
    const plen = crypto.open(key, seq, ct, out) catch return null; // silent drop on auth/truncation

    // Authenticated: a newer epoch now supersedes the old session — adopt it and
    // start a fresh replay window so the restarted sender's low sequence numbers
    // are accepted again.
    if (pkt_epoch > rx.epoch) {
        rx.epoch = pkt_epoch;
        rx.skey = key;
        rx.window = .{};
    }
    if (!rx.window.accept(seq)) return null; // replay or too old -> drop
    return plen;
}

/// Extract the IPv4 destination address (host byte order) after validating the
/// header. Returns `null` for anything that is not a well-formed IPv4 packet.
/// `pub` so out-of-tree benchmarks (tools/forward-bench.zig, issue #101) can
/// time the live parser; read-only, no data-plane behavior change.
pub fn ipv4Dst(pkt: []const u8) ?u32 {
    if (pkt.len < 20) return null;
    if ((pkt[0] >> 4) != 4) return null; // version
    const ihl = pkt[0] & 0x0f;
    if (ihl < 5) return null;
    if (pkt.len < @as(usize, ihl) * 4) return null;
    return std.mem.readInt(u32, pkt[16..][0..4], .big);
}

/// Extract the IPv4 source address (host byte order) after validating the
/// header. Applies the **same** version/IHL/length checks as `ipv4Dst` so that
/// the inner-source binding check and endpoint learning (issue #34) only ever
/// run on a well-formed IPv4 packet, regardless of evaluation order.
/// `pub` for the same out-of-tree benchmark use as `ipv4Dst` (issue #101).
pub fn ipv4Src(pkt: []const u8) ?u32 {
    if (pkt.len < 20) return null;
    if ((pkt[0] >> 4) != 4) return null; // version
    const ihl = pkt[0] & 0x0f;
    if (ihl < 5) return null;
    if (pkt.len < @as(usize, ihl) * 4) return null;
    return std.mem.readInt(u32, pkt[12..][0..4], .big);
}

pub const Reactor = struct {
    tun_fd: sys.fd_t,
    /// Local UDP sockets, one per configured listen port (multi-port listening).
    /// The node accepts datagrams on ALL of them; a reply/relay to a peer leaves
    /// by the socket that peer was last heard on (`Peer.rx_fd_index`) so the
    /// source port matches its NAT pinhole. `init` seeds a single socket
    /// (`udp_fds[0]`); `main` registers the rest with `addListenFd`. Only the
    /// first `udp_fd_count` entries are valid.
    udp_fds: [config.MAX_LISTEN_PORTS]sys.fd_t = undefined,
    udp_fd_count: usize = 0,
    /// Optional AF_UNIX control listener (issue #6). When present its datagram
    /// socket is registered level-triggered in `run()` and drained via
    /// `Control.handle()`; the control plane owns the policy-tree storage and the
    /// data plane only reads `active` atomically.
    control: ?*uds.Control = null,
    active: *policy.ActiveTree,
    mode: EgressMode = .raw_direct,
    /// Multi-peer endpoint + crypto registry (per-peer keys, counters, windows).
    registry: *peer.PeerRegistry,
    /// Optional runtime counters (issue #24). Null in unit tests that don't care
    /// about observability; set by `main` so `subnetra status` can read them. Plain
    /// increments are safe under the single-threaded reactor (no atomics).
    counters: ?*stats.Counters = null,
    /// Spoke→hub keepalive (issue #96). `keepalive_ns == 0` disables it (the
    /// default, and the only setting for hub/manual roles); a NATed spoke sets a
    /// non-zero interval so it emits a tiny authenticated keepalive to its single
    /// hub peer, holding the NAT pinhole open and the hub's learned endpoint fresh
    /// with NO external sidecar. Wired by `main` for `role=spoke` only.
    keepalive_ns: u64 = 0,
    /// The hub peer id keepalives are sent to (the spoke's single hub). Only read
    /// when `keepalive_ns > 0`.
    keepalive_peer_id: u32 = 0,
    /// Monotonic-clock deadline (ns) of the next keepalive, armed in `run()`.
    keepalive_due_ns: u64 = 0,
    /// PRNG for keepalive interval jitter when `obfuscate` is on (issue #96 /
    /// stealth). Seeded in `run()` from the system clocks plus an ASLR sample (this
    /// std build has no OS CSPRNG); the comptime default keeps it valid for unit
    /// tests that bypass `run()`. Not security-sensitive — it only de-periodizes
    /// the NAT keepalive cadence.
    keepalive_prng: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0),
    /// Header obfuscation (traffic-analysis countermeasure). When true, every
    /// datagram's 20-byte cleartext header is XOR-masked on egress with a
    /// per-packet pad derived from the link key and the datagram's AEAD tag
    /// (`obfuscateHeader`), and de-masked on ingress by trialing each peer's link
    /// key (`tryDeobfuscate`), so the wire carries no fixed protocol fingerprint;
    /// the spoke keepalive is also de-periodized (`nextKeepaliveDueNs`) so its
    /// cadence is not a fingerprint either. MUST be set identically on every mesh
    /// node (it is not negotiated — Subnetra performs no handshake): a mismatch
    /// makes all traffic fail to de-mask and then fail authentication, i.e. it
    /// fails closed and loudly. Wired by `main` from `config.obfuscate`, which
    /// defaults ON (stealth by default). This mechanism field is inert until
    /// wired, so a node with it off emits/accepts byte-identical v1 datagrams.
    obfuscate: bool = false,
    /// Remaining full-registry trial scans this UDP drain (issue #174). With
    /// obfuscation on, an inbound datagram whose SOURCE endpoint matches no
    /// peer's current endpoint must trial every configured peer's rx link key
    /// (one keyed-Blake2b each) before it can be dropped — an off-path attacker
    /// spoofing arbitrary sources can amplify one cheap junk datagram into
    /// O(MAX_PEERS) keyed hashes on this single-threaded reactor. This budget
    /// caps how many such full scans one `pumpUdpIngress` drain will perform;
    /// it refills at the top of every drain (see `OBFS_SCAN_BUDGET`), so the
    /// steady state is unaffected and only a flood hits the ceiling.
    obfs_scan_budget: u32 = OBFS_SCAN_BUDGET,
    rx: [BUF_LEN]u8 = undefined,
    tx: [BUF_LEN]u8 = undefined,
    /// Batched UDP datagram I/O (issue #100). Inbound datagrams are drained in
    /// groups with one `recvmmsg`, and relays/forwards are coalesced with one
    /// `sendmmsg` (macOS loops single recvfrom/sendto behind the same surface).
    /// Resident and fixed at startup, so the data plane stays allocation-free. An
    /// inbound datagram is decoded into `tx`, then re-sealed into one of the
    /// batch's own output buffers before forwarding, so the two never alias.
    udp: os.UdpBatch = .{},

    /// Construct a reactor with its FIRST (primary) UDP socket. Additional listen
    /// sockets are appended by `addListenFd` before `run`. Keeping the single-fd
    /// signature lets every existing unit test (and a single-port node) build a
    /// reactor unchanged; `udp_fds[0]` is the primary used for keepalive/relay
    /// cold-start before a peer's arrival socket is learned.
    pub fn init(
        tun_fd: sys.fd_t,
        udp_fd: sys.fd_t,
        control: ?*uds.Control,
        active: *policy.ActiveTree,
        registry: *peer.PeerRegistry,
    ) Reactor {
        var r = Reactor{
            .tun_fd = tun_fd,
            .control = control,
            .active = active,
            .registry = registry,
        };
        r.udp_fds[0] = udp_fd;
        r.udp_fd_count = 1;
        return r;
    }

    /// Register an additional UDP listen socket (multi-port listening). Called by
    /// `main` once per extra `config.listen_ports` entry after `init`. Silently
    /// ignores a fd past `MAX_LISTEN_PORTS` — config validation already caps the
    /// set, so this is only a defensive bound.
    pub fn addListenFd(self: *Reactor, fd: sys.fd_t) void {
        if (self.udp_fd_count >= config.MAX_LISTEN_PORTS) return;
        self.udp_fds[self.udp_fd_count] = fd;
        self.udp_fd_count += 1;
    }

    /// Index of `fd` within the active listen-socket set, or null if it is not a
    /// UDP listen socket (so `run` can dispatch a ready fd to the right pump and
    /// tag ingress with its arrival socket index).
    fn udpIndexOf(self: *const Reactor, fd: sys.fd_t) ?usize {
        var i: usize = 0;
        while (i < self.udp_fd_count) : (i += 1) {
            if (self.udp_fds[i] == fd) return i;
        }
        return null;
    }

    /// Single-threaded readiness loop. Forces TUN/UDP non-blocking, registers
    /// them edge-triggered and the optional control socket level-triggered on the
    /// comptime-selected `os.Poller`, and dispatches each ready fd to its drain
    /// pump. Runs until an unrecoverable poller error. The OS readiness mechanism
    /// (epoll on Linux, poll(2) on macOS) lives behind `os.Poller`; this loop has
    /// no runtime OS branch.
    pub fn run(self: *Reactor) !void {
        try sys.setNonblock(self.tun_fd);
        {
            var fi: usize = 0;
            while (fi < self.udp_fd_count) : (fi += 1) try sys.setNonblock(self.udp_fds[fi]);
        }

        var poller = try os.Poller.init();
        defer poller.deinit();

        try poller.add(self.tun_fd, .edge);
        {
            var fi: usize = 0;
            while (fi < self.udp_fd_count) : (fi += 1) try poller.add(self.udp_fds[fi], .edge);
        }
        // Control socket is level-triggered: handle() processes a bounded number
        // of commands per tick, and the poller re-notifies while datagrams remain.
        if (self.control) |c| try poller.add(c.fd, .level);

        // Seed the keepalive jitter PRNG. This std build exposes no OS CSPRNG, and
        // the value is not security-sensitive (it only de-periodizes the keepalive),
        // so mix the monotonic + wall clocks with a stack-address (ASLR) sample: the
        // result varies per process, avoiding lockstep across nodes.
        var seed_anchor: u8 = 0;
        // Widen the pointer to u64 BEFORE the multiply: on 32-bit targets `usize`
        // (the @intFromPtr result) is u32, which cannot represent the 64-bit
        // golden-ratio constant — the mix must happen in u64 on every target.
        const seed: u64 = monoNs() ^ wallNs() ^ (@as(u64, @intFromPtr(&seed_anchor)) *% 0x9E3779B97F4A7C15);
        self.keepalive_prng = std.Random.DefaultPrng.init(seed);

        // Arm the first keepalive (issue #96). When disabled (keepalive_ns == 0)
        // the poll blocks forever as before — zero timer overhead on the hub.
        if (self.keepalive_ns != 0) self.keepalive_due_ns = self.nextKeepaliveDueNs(monoNs());

        var ready: [16]sys.fd_t = undefined;
        while (true) {
            // Emit a due keepalive, then derive the poll timeout from the next
            // deadline. Driven purely by the poll timeout in this single loop —
            // no threads, no timerfd, no second OS branch (issue #96).
            const now = monoNs();
            if (self.keepalive_ns != 0 and now >= self.keepalive_due_ns) {
                self.sendKeepalive();
                self.keepalive_due_ns = self.nextKeepaliveDueNs(now);
            }
            const n = try poller.wait(&ready, self.keepaliveTimeoutMs(now));
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const fd = ready[i];
                if (fd == self.tun_fd) {
                    self.pumpTunToUdp();
                } else if (self.udpIndexOf(fd)) |idx| {
                    self.pumpUdpIngress(fd, idx);
                } else if (self.control != null and fd == self.control.?.fd) {
                    self.control.?.handle();
                }
            }
        }
    }

    /// Milliseconds the poll should block before the next keepalive is due, given
    /// the current monotonic `now_ns`; `-1` (block forever) when keepalive is
    /// disabled. Pure (takes the clock as an argument) so the schedule is
    /// unit-testable without sleeping. Rounds UP so the loop never busy-spins on a
    /// sub-millisecond remainder.
    fn keepaliveTimeoutMs(self: *const Reactor, now_ns: u64) i32 {
        if (self.keepalive_ns == 0) return -1;
        if (now_ns >= self.keepalive_due_ns) return 0;
        const ms = (self.keepalive_due_ns - now_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms;
        return if (ms > std.math.maxInt(i32)) std.math.maxInt(i32) else @intCast(ms);
    }

    /// Monotonic-clock deadline for the NEXT keepalive given the current `now_ns`.
    /// With obfuscation OFF this is the exact configured interval — deterministic
    /// and easy to reason about on the wire / in a capture. With obfuscation ON the
    /// interval is uniformly randomized within `[keepalive_ns/2, keepalive_ns]` so
    /// an idle spoke's NAT-keepalive carries NO fixed period for a passive observer
    /// to fingerprint, while NEVER exceeding the configured (NAT-safe) interval — it
    /// only ever fires the same or sooner, so the pinhole guarantee is preserved.
    /// The caller guarantees `keepalive_ns != 0` (keepalive enabled).
    fn nextKeepaliveDueNs(self: *Reactor, now_ns: u64) u64 {
        if (!self.obfuscate) return now_ns + self.keepalive_ns;
        const half = self.keepalive_ns / 2;
        return now_ns + half + self.keepalive_prng.random().uintLessThan(u64, half + 1);
    }

    /// Seal and send one keepalive to the configured hub peer (issue #96).
    /// Best-effort: a vanished hub or a transient send error is counted-or-ignored,
    /// never fatal — the next interval simply tries again. Reuses the resident `tx`
    /// buffer (idle between pump dispatches in the single-threaded loop).
    fn sendKeepalive(self: *Reactor) void {
        const hub = self.registry.findById(self.keepalive_peer_id) orelse return;
        const wire_len = encodeKeepalive(&hub.tx, self.localKeyId(), &self.tx);
        if (self.obfuscate) obfuscateHeader(hub.tx.link_key, self.tx[0..wire_len]);
        // Leave by the socket the hub was last heard on so the keepalive refreshes
        // the SAME NAT pinhole the data path uses (cold-start uses the primary).
        if (self.sendTo(self.udp_fds[hub.rx_fd_index], hub.endpoint, self.tx[0..wire_len])) self.cInc("keepalive_tx");
    }

    inline fn cInc(self: *Reactor, comptime field: []const u8) void {
        if (self.counters) |c| c.inc(field);
    }

    inline fn cAdd(self: *Reactor, comptime field: []const u8, n: u64) void {
        if (self.counters) |c| c.add(field, n);
    }

    /// Drain the TUN fd (locally-originated traffic): read each IP packet, look
    /// up its destination in the policy tree to find the target peer, seal it
    /// with that peer's key, and forward. Packets with no route, a DROP rule, a
    /// LOCAL target (would loop to self), or an unknown target are dropped.
    /// Loops until EAGAIN.
    pub fn pumpTunToUdp(self: *Reactor) void {
        while (true) {
            const pkt = os.tunRead(self.tun_fd, &self.rx) orelse break;
            self.cInc("tun_rx_packets");
            self.cAdd("tun_rx_bytes", @intCast(pkt.len));

            const dst = ipv4Dst(pkt) orelse {
                self.cInc("drop_tun_not_ipv4");
                continue; // non-IPv4/malformed -> drop
            };
            const entry = self.active.load().match(dst) orelse {
                self.cInc("drop_tun_no_route");
                continue; // no route -> drop
            };
            if (entry.action == .drop) {
                self.cInc("drop_tun_drop_rule");
                continue;
            }
            if (entry.target == peer.LOCAL_TARGET) {
                self.cInc("drop_tun_local_loop");
                continue; // local-origin to local -> drop
            }
            const dst_peer = self.registry.findById(entry.target) orelse {
                self.cInc("drop_tun_unknown_target");
                continue; // unknown target
            };
            if (pkt.len > MAX_PLAINTEXT) {
                self.cInc("drop_tun_oversized");
                continue; // oversized -> drop
            }
            egress(self.mode, pkt) catch {
                self.cInc("drop_tun_egress_err");
                continue; // v2 modes not yet shipped -> drop
            };

            // Seal into the next coalesced egress slot; the flush below pushes the
            // whole drain with one sendmmsg (issue #100). Counters are attributed
            // per slot at flush time (so a short send is still counted honestly).
            self.stageEgress(dst_peer, pkt, TAG_TUN_FWD);
        }
        self.flushEgress();
    }

    /// Drain the UDP fd: filter by source endpoint, authenticate + anti-replay
    /// with the source peer's key, enforce inner-source binding, then route by
    /// the policy `target` — deliver to the local TUN, or relay to another peer
    /// (hub behaviour). Loops until EAGAIN.
    /// Drain the UDP fd in batches: one `recvmmsg` pulls up to `UdpBatch.N`
    /// datagrams (issue #100), then each is authenticated + anti-replayed +
    /// routed individually by `processIngress` exactly as before — batching is
    /// purely I/O amortization, never a semantics change (iron law #8). Relays /
    /// forwards produced during the drain are coalesced and flushed with one
    /// `sendmmsg`. Loops until the socket is drained (recvmmsg would block).
    pub fn pumpUdpIngress(self: *Reactor, fd: sys.fd_t, fd_index: usize) void {
        // Refill the obfuscation full-scan budget (issue #174): each drain may
        // spend at most OBFS_SCAN_BUDGET full-registry key trials on datagrams
        // whose source endpoint matches no peer, capping the unauthenticated CPU
        // an off-path spoofed-source flood can extract from this single thread.
        self.obfs_scan_budget = OBFS_SCAN_BUDGET;
        while (true) {
            const got = self.udp.recv(fd);
            if (got == 0) break; // EAGAIN / drained -> done this tick
            var i: usize = 0;
            while (i < got) : (i += 1) {
                const dgram = self.udp.datagram(i);
                self.cInc("udp_rx_packets");
                self.cAdd("udp_rx_bytes", @intCast(dgram.len));
                self.processIngress(dgram, self.udp.source(i), fd_index);
            }
        }
        self.flushEgress();
    }

    /// Resolve the sender peer for an inbound datagram. With obfuscation off this
    /// is the cheap O(1) header read: the cleartext `key_id` selects the peer.
    /// With obfuscation on the selector is masked, so selection is a trial
    /// de-mask (`tryDeobfuscate`, one keyed hash per candidate): the real
    /// sender's key reproduces the pad, recovering a self-consistent header,
    /// which is then de-masked IN PLACE so the shared decode path downstream sees
    /// a cleartext header. To keep that trial from being an O(peers) scan per
    /// datagram (issue #174 — off-path junk would amplify into MAX_PEERS keyed
    /// hashes each), the peer whose CURRENT endpoint matches the datagram's
    /// source (`src`) is tried first: steady-state traffic — including a
    /// previously-roamed peer, whose learned endpoint is what `findByAddr`
    /// matches — resolves with ONE keyed hash. Only a datagram from an unknown
    /// source endpoint falls back to the full scan, and those scans are metered
    /// by `obfs_scan_budget` per drain; a datagram that needs a scan after the
    /// budget is spent is dropped for this drain (`drop_udp_scan_budget`) — a
    /// real roaming peer simply retries next drain, junk stays cheap forever.
    /// Returns null and bumps the matching drop counter when the datagram is too
    /// short or no configured peer claims it.
    fn selectIngressPeer(self: *Reactor, dgram: []u8, src: sys.sockaddr.in) ?*peer.Peer {
        if (self.obfuscate) {
            if (dgram.len < HEADER_LEN + crypto.TAG_LEN) {
                self.cInc("drop_udp_auth_or_invalid"); // too short to hold an obfuscated header + tag
                return null;
            }
            // Fast path: the peer we last heard from this endpoint (address
            // comparisons only — no crypto). Its key either claims the datagram
            // (one keyed hash, the steady state) or the datagram is not from the
            // peer it appears to be from and must survive the metered full scan
            // below like any other unknown-source datagram.
            const hint = self.registry.findByAddr(src.addr, src.port);
            if (hint) |p| {
                if (tryDeobfuscate(p.rx.link_key, p.id, dgram)) return p;
            }
            if (self.obfs_scan_budget == 0) {
                self.cInc("drop_udp_scan_budget"); // scan budget spent this drain
                return null;
            }
            self.obfs_scan_budget -= 1;
            var i: usize = 0;
            while (i < self.registry.len) : (i += 1) {
                const p = &self.registry.peers[i];
                if (hint == p) continue; // already tried on the fast path
                if (tryDeobfuscate(p.rx.link_key, p.id, dgram)) return p;
            }
            self.cInc("drop_udp_unknown_peer"); // no peer's link key recovers a valid header
            return null;
        }
        const key_id = parseKeyId(dgram) orelse {
            self.cInc("drop_udp_auth_or_invalid"); // too short to hold a header
            return null;
        };
        return self.registry.findById(key_id) orelse {
            self.cInc("drop_udp_unknown_peer"); // key_id matches no configured peer
            return null;
        };
    }

    /// Authenticate, anti-replay, inner-source-bind, and route ONE inbound
    /// datagram (`dgram`, received from `src`): deliver to the local TUN, refresh
    /// a keepalive, or stage a relay to another peer. Factored out of the batch
    /// drain in `pumpUdpIngress` so the per-packet security path is identical
    /// whether a batch holds one datagram or `UdpBatch.N` of them.
    fn processIngress(self: *Reactor, dgram: []u8, src: sys.sockaddr.in, fd_index: usize) void {
        // Identity selector (issue #34): the candidate peer is chosen by the
        // header `key_id` (the sender's mesh id), NOT by source endpoint — a
        // NATed/roaming spoke may legitimately arrive from an unexpected
        // endpoint. This selection is only a HINT until the datagram
        // authenticates below; a wrong/forged key_id fails authentication. When
        // header obfuscation is on, the selector is masked, so `selectIngressPeer`
        // trial-de-masks the header in place first — source-endpoint fast path,
        // then a budget-metered full scan (issue #174; see below).
        const src_peer = self.selectIngressPeer(dgram, src) orelse return; // drop counter bumped inside

        const plen = decodeIngress(&src_peer.rx, dgram, &self.tx) orelse {
            self.cInc("drop_udp_auth_or_invalid");
            return;
        };

        // Multi-port return path: the datagram has authenticated (and passed the
        // anti-replay window) inside `decodeIngress`, so it is genuinely
        // `src_peer`. Remember WHICH local socket it arrived on so every reply /
        // relay to this peer egresses by the same socket — the source port then
        // matches the NAT pinhole the peer punched, which restricted-cone and
        // symmetric NATs require. Gated on authentication so a forged datagram
        // cannot redirect a peer's return socket.
        src_peer.rx_fd_index = fd_index;

        // Keepalive (issue #96): the datagram has authenticated AND passed the
        // anti-replay window inside `decodeIngress`, so it is genuinely
        // `src_peer` and not a replay. A keepalive carries NO inner packet, so it
        // refreshes the learned endpoint + `last_seen` and is then dropped before
        // any inner-IPv4 parsing or routing.
        if (dgram[1] & FLAG_KEEPALIVE != 0) {
            self.maybeLearnEndpoint(src_peer, src);
            self.cInc("keepalive_rx");
            return;
        }
        const pkt = self.tx[0..plen];

        // Inner-source binding: the decoded source IP must belong to the source
        // peer's allowed prefix (anti-spoofing).
        const isrc = ipv4Src(pkt) orelse {
            self.cInc("drop_udp_not_ipv4");
            return;
        };
        if (!src_peer.allowed_src.contains(isrc)) {
            self.cInc("drop_udp_spoof");
            return;
        }

        // Endpoint roaming (issue #34): authenticated AND inner-source-checked, so
        // it is genuinely `src_peer`. Learn its current endpoint so replies / hub
        // relays follow a roamed/NATed spoke. Gated on full decode + the spoof
        // check, so a replayed/forged/spoofed packet can never move the endpoint.
        self.maybeLearnEndpoint(src_peer, src);

        const dst = ipv4Dst(pkt) orelse {
            self.cInc("drop_udp_not_ipv4");
            return;
        };
        const entry = self.active.load().match(dst) orelse {
            self.cInc("drop_udp_no_route");
            return; // no route -> drop
        };
        if (entry.action == .drop) {
            self.cInc("drop_udp_drop_rule");
            return;
        }

        if (entry.target == peer.LOCAL_TARGET) {
            if (self.writeTun(pkt)) {
                self.cInc("tun_tx_packets");
                self.cAdd("tun_tx_bytes", @intCast(plen));
            } else {
                self.cInc("drop_udp_send_err");
            }
            return;
        }

        // Relay to another peer (hub forwarding) — the double-syscall path #100
        // targets. Sealed into a coalesced egress slot; flushed with one sendmmsg.
        const dst_peer = self.registry.findById(entry.target) orelse {
            self.cInc("drop_udp_unknown_target");
            return; // unknown target
        };
        if (dst_peer.id == src_peer.id) {
            self.cInc("drop_udp_no_reflect");
            return; // no-reflect guard
        }
        if (pkt.len > MAX_PLAINTEXT) {
            self.cInc("drop_udp_oversized");
            return;
        }
        self.stageEgress(dst_peer, pkt, TAG_RELAY);
    }

    /// Egress slot category for honest counter attribution at flush time:
    /// a locally-originated forward (`TAG_TUN_FWD`) bumps `udp_tx_*`, a relayed
    /// hub forward (`TAG_RELAY`) bumps `relay_*`; a short send bumps the matching
    /// `drop_*_send_err`.
    const TAG_TUN_FWD: u8 = 0;
    const TAG_RELAY: u8 = 1;

    /// Seal `pkt` for `dst_peer` straight into the next coalesced egress slot
    /// (issue #100). Flushes first if the batch is full, so a long drain still
    /// bounds the staged set at `UdpBatch.N`. The actual transmission and counter
    /// attribution happen in `flushEgress`.
    fn stageEgress(self: *Reactor, dst_peer: *peer.Peer, pkt: []const u8, tag: u8) void {
        if (self.udp.isFull()) self.flushEgress();
        const buf = self.udp.nextOutBuf();
        const wire_len = encodeEgress(&dst_peer.tx, self.localKeyId(), pkt, buf);
        // Mask the cleartext header before it leaves the box so the wire shows no
        // fixed protocol fingerprint; the de-mask key is this link's tx key, which
        // the receiver mirrors as its rx key for us.
        if (self.obfuscate) obfuscateHeader(dst_peer.tx.link_key, buf[0..wire_len]);
        // Egress out the socket this peer was last heard on (NAT-correct return
        // path); cold-start before any rx defaults to the primary socket (index 0).
        self.udp.commitOut(wire_len, dst_peer.endpoint, self.udp_fds[dst_peer.rx_fd_index], tag);
    }

    /// Transmit all staged datagrams with one `sendmmsg` (macOS: a `sendto` loop)
    /// and attribute per-slot counters. `flush` returns how many leading
    /// datagrams the kernel accepted; the rest (if any) are counted as send
    /// errors, matching the old per-packet `sendTo` accounting.
    fn flushEgress(self: *Reactor) void {
        const n = self.udp.pending();
        if (n == 0) return;
        const sent = self.udp.flush();
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const ok = i < sent;
            if (self.udp.tagAt(i) == TAG_RELAY) {
                if (ok) {
                    self.cInc("relay_packets");
                    self.cAdd("relay_bytes", self.udp.lenAt(i));
                } else self.cInc("drop_udp_send_err");
            } else {
                if (ok) {
                    self.cInc("udp_tx_packets");
                    self.cAdd("udp_tx_bytes", self.udp.lenAt(i));
                } else self.cInc("drop_tun_send_err");
            }
        }
    }

    /// Send `buf` to `endpoint` out the given local socket `fd`. Returns true if
    /// the datagram was handed to the kernel without error, false otherwise (so
    /// the caller can count send errors honestly rather than assuming success).
    /// Used for the single-shot keepalive (issue #96); bulk data egress is
    /// coalesced via `flushEgress`.
    fn sendTo(self: *Reactor, fd: sys.fd_t, endpoint: sys.sockaddr.in, buf: []const u8) bool {
        _ = self;
        var ep = endpoint;
        while (true) {
            const rc = sys.sendto(
                fd,
                buf.ptr,
                buf.len,
                0,
                @ptrCast(&ep),
                @sizeOf(sys.sockaddr.in),
            );
            if (sys.errno(rc) == .INTR) continue;
            return sys.errno(rc) == .SUCCESS;
        }
    }

    /// Write `buf` (a bare IP packet) to the local TUN. Returns true on success,
    /// false on a write error (counted by the caller). The backend handles any
    /// platform framing (e.g. macOS utun's 4-byte address-family prefix).
    fn writeTun(self: *Reactor, buf: []const u8) bool {
        return os.tunWrite(self.tun_fd, buf);
    }

    /// This node's own mesh id as the egress `key_id` selector (issue #34). The
    /// id is validated to fit `u16` at config/registry load (`PeerRegistry.add`),
    /// so the narrowing cast never loses information.
    inline fn localKeyId(self: *Reactor) u16 {
        return @intCast(self.registry.local_id);
    }

    /// Update a peer's learned UDP endpoint from an authenticated datagram's
    /// source (issue #34). MUST be called only after the datagram has fully
    /// authenticated (decode + anti-replay), so an unauthenticated or replayed
    /// packet can never move the endpoint. For a routed data packet the caller
    /// also applies the inner-source binding check first; a keepalive (issue #96)
    /// carries no inner packet, so its authenticity rests entirely on auth+replay
    /// and it skips that check. The endpoint is runtime state only — it is never
    /// written back to config.
    fn maybeLearnEndpoint(self: *Reactor, p: *peer.Peer, src: sys.sockaddr.in) void {
        p.last_seen_wall_ns = wallNs();
        if (p.endpoint.addr != src.addr or p.endpoint.port != src.port) {
            p.endpoint.addr = src.addr;
            p.endpoint.port = src.port;
            self.cInc("udp_endpoint_learned");
        }
    }
};

/// Wall-clock nanoseconds for the observability-only `last_seen_wall_ns` field.
/// REALTIME (not MONOTONIC) so `subnetra status` shows a human-meaningful instant;
/// it is subject to NTP/clock jumps and MUST NOT drive any protocol logic. On a
/// non-Linux host (unit tests only) it returns 0.
fn wallNs() u64 {
    if (builtin.os.tag != .linux) return 0;
    var ts: sys.timespec = undefined;
    if (sys.errno(sys.clock_gettime(sys.CLOCK.REALTIME, &ts)) != .SUCCESS) return 0;
    if (ts.sec < 0) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Monotonic nanoseconds for keepalive scheduling (issue #96). Unlike `wallNs`
/// (REALTIME, Linux-only, observability) this MUST work on every platform the
/// reactor runs on, including macOS spokes, because it drives a real timer; it is
/// also immune to wall-clock steps. Returns 0 only on an impossible clock failure,
/// which at worst makes one keepalive fire early.
fn monoNs() u64 {
    var ts: sys.timespec = undefined;
    if (sys.errno(sys.clock_gettime(sys.CLOCK.MONOTONIC, &ts)) != .SUCCESS) return 0;
    if (ts.sec < 0) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

test "WireHeader is 20 bytes" {
    try std.testing.expectEqual(@as(usize, 20), HEADER_LEN);
}

test "egress: v1 raw_direct works, v2 modes return NotImplemented" {
    try egress(.raw_direct, &.{});
    try std.testing.expectError(EgressError.NotImplemented, egress(.kcp_arq, &.{}));
    try std.testing.expectError(EgressError.NotImplemented, egress(.fec_xor, &.{}));
    try std.testing.expectEqual(@as(u16, 1452), mtuFor(.raw_direct));
}

test "codec: encodeEgress -> decodeIngress roundtrips the IP packet" {
    const key: crypto.Key = [_]u8{0x11} ** crypto.KEY_LEN;
    var tx = crypto.TxSession.init(key, 0x1700_0000_0000_0001);
    var rx = crypto.RxSession.init(key);

    const ip_pkt = [_]u8{ 0x45, 0, 0, 28 } ++ [_]u8{0} ** 12 ++ [_]u8{ 10, 0, 0, 2 } ++ [_]u8{0} ** 8;
    var wire: [MAX_WIRE]u8 = undefined;
    const wlen = encodeEgress(&tx, 2, &ip_pkt, &wire);
    try std.testing.expectEqual(HEADER_LEN + ip_pkt.len + crypto.TAG_LEN, wlen);
    try std.testing.expectEqual(WIRE_VERSION, wire[0]);

    var out: [MAX_PLAINTEXT]u8 = undefined;
    const plen = decodeIngress(&rx, wire[0..wlen], &out) orelse return error.UnexpectedDrop;
    try std.testing.expectEqualSlices(u8, &ip_pkt, out[0..plen]);
    // The receiver adopted the sender's epoch.
    try std.testing.expectEqual(@as(u64, 0x1700_0000_0000_0001), rx.epoch);
}

test "obfuscation: masks the header on the wire and de-masks back to a decodable datagram" {
    const psk: crypto.Key = [_]u8{0x33} ** crypto.KEY_LEN;
    const from_id: u16 = 2;
    // Sender tx key for direction (2 -> 1) equals the receiver's rx key for the
    // same ordered pair (see crypto.deriveLinkKey / peer.add), so both ends derive
    // the same obfuscation pad.
    const link = crypto.deriveLinkKey(psk, from_id, 1);
    var tx = crypto.TxSession.init(link, 0x1700_0000_0000_0001);

    const ip_pkt = [_]u8{ 0x45, 0, 0, 28 } ++ [_]u8{0} ** 12 ++ [_]u8{ 10, 0, 0, 2 } ++ [_]u8{0} ** 8;
    var wire: [MAX_WIRE]u8 = undefined;
    const wlen = encodeEgress(&tx, from_id, &ip_pkt, &wire);

    // Snapshot the cleartext header and body, then obfuscate the header in place.
    var clear_header: [HEADER_LEN]u8 = undefined;
    @memcpy(&clear_header, wire[0..HEADER_LEN]);
    var clear_body: [MAX_WIRE]u8 = undefined;
    @memcpy(clear_body[0 .. wlen - HEADER_LEN], wire[HEADER_LEN..wlen]);
    obfuscateHeader(link, wire[0..wlen]);

    // The header no longer carries its fixed fingerprint (the constant version
    // byte, repeated epoch, low seq) — it differs from the cleartext header.
    try std.testing.expect(!std.mem.eql(u8, &clear_header, wire[0..HEADER_LEN]));
    // The body (ciphertext + tag) is untouched: only the 20-byte header is masked,
    // so the trailing tag stays clear for the receiver to derive the de-mask pad.
    try std.testing.expectEqualSlices(u8, clear_body[0 .. wlen - HEADER_LEN], wire[HEADER_LEN..wlen]);

    // The matching peer key recovers the header in place...
    try std.testing.expect(tryDeobfuscate(link, from_id, wire[0..wlen]));
    try std.testing.expectEqualSlices(u8, &clear_header, wire[0..HEADER_LEN]);

    // ...and the recovered datagram decodes to the original inner packet.
    var rx = crypto.RxSession.init(link);
    var out: [MAX_PLAINTEXT]u8 = undefined;
    const plen = decodeIngress(&rx, wire[0..wlen], &out) orelse return error.UnexpectedDrop;
    try std.testing.expectEqualSlices(u8, &ip_pkt, out[0..plen]);
}

test "obfuscation: tryDeobfuscate rejects a wrong key or a mismatched id without mutating" {
    const psk: crypto.Key = [_]u8{0x44} ** crypto.KEY_LEN;
    const from_id: u16 = 7;
    const link = crypto.deriveLinkKey(psk, from_id, 3);
    var tx = crypto.TxSession.init(link, 0x1700_0000_0000_0009);

    const ip_pkt = [_]u8{ 0x45, 0, 0, 20 } ++ [_]u8{0} ** 16;
    var wire: [MAX_WIRE]u8 = undefined;
    const wlen = encodeEgress(&tx, from_id, &ip_pkt, &wire);
    obfuscateHeader(link, wire[0..wlen]);

    var snapshot: [MAX_WIRE]u8 = undefined;
    @memcpy(snapshot[0..wlen], wire[0..wlen]);

    // Wrong link key: the recovered header is garbage, so no commit and no mutation.
    const wrong_link = crypto.deriveLinkKey(psk, 8, 3);
    try std.testing.expect(!tryDeobfuscate(wrong_link, from_id, wire[0..wlen]));
    try std.testing.expectEqualSlices(u8, snapshot[0..wlen], wire[0..wlen]);

    // Right key but the wrong expected id (header key_id won't match): reject, no mutation.
    try std.testing.expect(!tryDeobfuscate(link, 999, wire[0..wlen]));
    try std.testing.expectEqualSlices(u8, snapshot[0..wlen], wire[0..wlen]);

    // Right key and id: accept and de-mask in place.
    try std.testing.expect(tryDeobfuscate(link, from_id, wire[0..wlen]));
}

test "codec: decodeIngress drops tampered, replayed, and malformed datagrams" {
    const key: crypto.Key = [_]u8{0x22} ** crypto.KEY_LEN;
    var tx = crypto.TxSession.init(key, 0x1700_0000_0000_0001);

    const ip_pkt = [_]u8{ 0x45, 0, 0, 20 } ++ [_]u8{0} ** 16;
    var wire: [MAX_WIRE]u8 = undefined;
    const wlen = encodeEgress(&tx, 2, &ip_pkt, &wire);
    var out: [MAX_PLAINTEXT]u8 = undefined;

    // Tampered ciphertext -> auth fails -> drop, and the replay window must not
    // have advanced (a fresh valid copy still decodes afterwards).
    var rx = crypto.RxSession.init(key);
    var tampered = wire;
    tampered[wlen - 1] ^= 0xFF;
    try std.testing.expect(decodeIngress(&rx, tampered[0..wlen], &out) == null);
    try std.testing.expect(decodeIngress(&rx, wire[0..wlen], &out) != null);

    // Replay of the same seq is dropped the second time.
    try std.testing.expect(decodeIngress(&rx, wire[0..wlen], &out) == null);

    // Wrong version byte -> drop.
    var badver = wire;
    badver[0] = 2;
    try std.testing.expect(decodeIngress(&rx, badver[0..wlen], &out) == null);

    // Set a still-reserved flag bit (bit 1) -> drop. Bit 0 is now KEEPALIVE and
    // is accepted; every other bit remains reserved and must be rejected.
    var badflags = wire;
    badflags[1] = 0b0000_0010;
    try std.testing.expect(decodeIngress(&rx, badflags[0..wlen], &out) == null);

    // Zero epoch (the "no session" sentinel) -> drop.
    var badepoch = wire;
    std.mem.writeInt(u64, badepoch[4..][0..8], 0, .little);
    try std.testing.expect(decodeIngress(&rx, badepoch[0..wlen], &out) == null);

    // Too short for a header -> drop.
    try std.testing.expect(decodeIngress(&rx, wire[0 .. HEADER_LEN - 1], &out) == null);
}

test "codec: session epoch is forward-only (stale dropped, newer resets window)" {
    const key: crypto.Key = [_]u8{0x33} ** crypto.KEY_LEN;
    const ip_pkt = [_]u8{ 0x45, 0, 0, 20 } ++ [_]u8{0} ** 16;
    var out: [MAX_PLAINTEXT]u8 = undefined;
    var rx = crypto.RxSession.init(key);

    // Session 1 (epoch E1) sends a few packets; the receiver advances its window.
    var tx1 = crypto.TxSession.init(key, 1_700_000_000_000_000_000);
    var w1a: [MAX_WIRE]u8 = undefined;
    var w1b: [MAX_WIRE]u8 = undefined;
    const l1a = encodeEgress(&tx1, 2, &ip_pkt, &w1a); // seq 1
    const l1b = encodeEgress(&tx1, 2, &ip_pkt, &w1b); // seq 2
    try std.testing.expect(decodeIngress(&rx, w1a[0..l1a], &out) != null);
    try std.testing.expect(decodeIngress(&rx, w1b[0..l1b], &out) != null);
    try std.testing.expectEqual(@as(u64, 1_700_000_000_000_000_000), rx.epoch);

    // The sender restarts: session 2 (a later epoch) restarts seq at 1. Without
    // the epoch reset this seq-1 packet would be rejected as a replay; with it,
    // the newer epoch is adopted and the window resets, so it is accepted.
    var tx2 = crypto.TxSession.init(key, 1_700_000_000_000_000_500);
    var w2: [MAX_WIRE]u8 = undefined;
    const l2 = encodeEgress(&tx2, 2, &ip_pkt, &w2); // seq 1 again, new epoch
    try std.testing.expect(decodeIngress(&rx, w2[0..l2], &out) != null);
    try std.testing.expectEqual(@as(u64, 1_700_000_000_000_000_500), rx.epoch);

    // A leftover packet from the retired session 1 (older epoch) is now dropped,
    // defeating cross-epoch replay of the previous lifetime.
    var w1c: [MAX_WIRE]u8 = undefined;
    const l1c = encodeEgress(&tx1, 2, &ip_pkt, &w1c); // session 1, seq 3
    try std.testing.expect(decodeIngress(&rx, w1c[0..l1c], &out) == null);

    // Replay within the live session 2 is still rejected.
    try std.testing.expect(decodeIngress(&rx, w2[0..l2], &out) == null);
}

test "keepalive: encodeKeepalive seals an empty KEEPALIVE-flagged datagram (issue #96)" {
    const psk: crypto.Key = [_]u8{0x55} ** crypto.KEY_LEN;
    const link = crypto.deriveLinkKey(psk, 2, 1);
    var tx = crypto.TxSession.init(link, TEST_EPOCH);
    var rx = crypto.RxSession.init(link);

    var wire: [MAX_WIRE]u8 = undefined;
    const wlen = encodeKeepalive(&tx, 2, &wire);
    // A keepalive is exactly a header + a tag over an empty body — no inner packet.
    try std.testing.expectEqual(@as(usize, HEADER_LEN + crypto.TAG_LEN), wlen);
    try std.testing.expectEqual(WIRE_VERSION, wire[0]);
    try std.testing.expect(wire[1] & FLAG_KEEPALIVE != 0);

    // It authenticates and decodes to a zero-length plaintext (carries no packet).
    var out: [MAX_PLAINTEXT]u8 = undefined;
    const plen = decodeIngress(&rx, wire[0..wlen], &out);
    try std.testing.expectEqual(@as(?usize, 0), plen);

    // Tampering the sealed body still fails authentication like any datagram.
    var tampered = wire;
    tampered[HEADER_LEN] ^= 0xFF;
    var rx2 = crypto.RxSession.init(link);
    try std.testing.expect(decodeIngress(&rx2, tampered[0..wlen], &out) == null);
}

test "keepalive: keepaliveTimeoutMs reflects the schedule (issue #96)" {
    var reg = peer.PeerRegistry.init(1);
    var tree = policy.PolicyTree{ .entries = &.{} };
    var active = policy.ActiveTree.init(&tree);
    var r = Reactor.init(-1, -1, null, &active, &reg);

    // Disabled -> block forever.
    r.keepalive_ns = 0;
    try std.testing.expectEqual(@as(i32, -1), r.keepaliveTimeoutMs(0));
    try std.testing.expectEqual(@as(i32, -1), r.keepaliveTimeoutMs(999));

    // Enabled, due in the future -> milliseconds remaining.
    r.keepalive_ns = 20 * std.time.ns_per_s;
    r.keepalive_due_ns = 1000 * std.time.ns_per_ms; // due at t=1000ms
    try std.testing.expectEqual(@as(i32, 1000), r.keepaliveTimeoutMs(0));
    try std.testing.expectEqual(@as(i32, 500), r.keepaliveTimeoutMs(500 * std.time.ns_per_ms));

    // Due now / overdue -> 0 (fire immediately, never negative).
    try std.testing.expectEqual(@as(i32, 0), r.keepaliveTimeoutMs(1000 * std.time.ns_per_ms));
    try std.testing.expectEqual(@as(i32, 0), r.keepaliveTimeoutMs(5000 * std.time.ns_per_ms));

    // A sub-millisecond remainder rounds UP so the loop never busy-spins on it.
    r.keepalive_due_ns = 1; // 1 ns from t=0
    try std.testing.expectEqual(@as(i32, 1), r.keepaliveTimeoutMs(0));
}

test "keepalive: obfuscation randomizes the interval within [half, full] (NAT-safe)" {
    var reg = peer.PeerRegistry.init(1);
    var tree = policy.PolicyTree{ .entries = &.{} };
    var active = policy.ActiveTree.init(&tree);
    var r = Reactor.init(-1, -1, null, &active, &reg);
    r.keepalive_ns = 20 * std.time.ns_per_s;

    // Obfuscation off: the schedule is exactly the configured interval.
    r.obfuscate = false;
    try std.testing.expectEqual(@as(u64, 1000 + 20 * std.time.ns_per_s), r.nextKeepaliveDueNs(1000));

    // Obfuscation on: every draw lands in [now+half, now+full] and never overshoots
    // the configured (NAT-safe) ceiling. Over many draws we must also see it fire
    // before the full interval (i.e. jitter is actually applied).
    r.obfuscate = true;
    const half = r.keepalive_ns / 2;
    var saw_below_full = false;
    var k: usize = 0;
    while (k < 2000) : (k += 1) {
        const due = r.nextKeepaliveDueNs(1000);
        try std.testing.expect(due >= 1000 + half);
        try std.testing.expect(due <= 1000 + r.keepalive_ns);
        if (due < 1000 + r.keepalive_ns) saw_below_full = true;
    }
    try std.testing.expect(saw_below_full);
}

// ---- Live-socket pump tests (Linux only; skip elsewhere / on permission gaps) ----

// Live-socket pump tests are Linux-gated: they assume synchronous loopback
// delivery (a Linux behaviour) so a datagram is readable immediately after
// sendto. macOS defers loopback delivery, so these would need explicit poll
// readiness; the production reactor never races (epoll/poll drive readiness).
// macOS data-plane behaviour is certified by the manual acceptance runbook
// (docs/macos-spoke-acceptance.md, issue #79) per the RFC.
fn makeUdpLoopback() !sys.fd_t {
    const fd = sys.socket(sys.AF.INET, sys.SOCK.DGRAM, 0, true, false) catch return error.SkipZigTest;
    var addr = sys.sockaddr.in{ .family = sys.AF.INET, .port = 0, .addr = 0x0100007f }; // 127.0.0.1:0
    if (sys.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))) != .SUCCESS) {
        _ = sys.close(fd);
        return error.SkipZigTest;
    }
    return fd;
}

fn addrOf(fd: sys.fd_t) !sys.sockaddr.in {
    var a: sys.sockaddr.in = undefined;
    var l: sys.socklen_t = @sizeOf(sys.sockaddr.in);
    if (sys.errno(sys.getsockname(fd, @ptrCast(&a), &l)) != .SUCCESS) return error.SkipZigTest;
    return a;
}

fn ipPkt(src: [4]u8, dst: [4]u8) [28]u8 {
    var p = [_]u8{0} ** 28;
    p[0] = 0x45; // IPv4, IHL=5
    p[3] = 28; // total length
    p[8] = 64; // TTL
    @memcpy(p[12..16], &src);
    @memcpy(p[16..20], &dst);
    return p;
}

const ANY_SRC = policy.Cidr{ .network = 0, .prefix = 0 };
const TEST_EPOCH: u64 = 1_700_000_000_000_000_000;

/// A synthetic UDP endpoint (127.0.0.1:`port`) used as a peer's *stale* configured
/// endpoint, so endpoint relearning (issue #34) is observable as a change away
/// from it. `port` is chosen below the ephemeral range so it never aliases a
/// loopback test socket.
fn fakeAddr(port: u16) sys.sockaddr.in {
    return .{ .family = sys.AF.INET, .port = std.mem.nativeToBig(u16, port), .addr = 0x0100007f };
}

fn sameEndpoint(a: sys.sockaddr.in, b: sys.sockaddr.in) bool {
    return a.addr == b.addr and a.port == b.port;
}

test "pump: TUN->UDP seals to the policy-selected peer" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x33} ** crypto.KEY_LEN;

    // tun side: a pipe whose read end the reactor drains.
    const pipe_fds = sys.pipeNonblock() catch return error.SkipZigTest;
    defer _ = sys.close(pipe_fds[0]);
    defer _ = sys.close(pipe_fds[1]);

    const udp_hub = try makeUdpLoopback(); // reactor's udp_fd (local id 1)
    defer _ = sys.close(udp_hub);
    const udp_a = try makeUdpLoopback(); // peer A (id 2)
    defer _ = sys.close(udp_a);

    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, try addrOf(udp_a), ANY_SRC, TEST_EPOCH);

    // Route 10.0.0.2 -> peer 2.
    const entries = [_]policy.PolicyEntry{.{
        .src = try policy.parseCidr("0.0.0.0/0"),
        .dst = try policy.parseCidr("10.0.0.2/32"),
        .action = .forward,
        .target = 2,
    }};
    var tree = policy.PolicyTree{ .entries = &entries };
    var active = policy.ActiveTree.init(&tree);

    var r = Reactor.init(pipe_fds[0], udp_hub, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;

    const ip_pkt = ipPkt(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 });
    _ = sys.write(pipe_fds[1], &ip_pkt, ip_pkt.len);

    r.pumpTunToUdp();

    // Issue #24: a forwarded packet bumps the rx-from-tun and tx-to-udp counters.
    try std.testing.expectEqual(@as(u64, 1), ctr.tun_rx_packets);
    try std.testing.expectEqual(@as(u64, 1), ctr.udp_tx_packets);
    try std.testing.expect(ctr.udp_tx_bytes > 0);

    var buf: [MAX_WIRE]u8 = undefined;
    const rc = sys.recvfrom(udp_a, &buf, buf.len, 0, null, null);
    try std.testing.expect(sys.errno(rc) == .SUCCESS);

    // Peer A decodes with its rx key for traffic from the hub: derive(psk, 1, 2).
    const a_rx_key = crypto.deriveLinkKey(psk, 1, 2);
    var a_rx = crypto.RxSession.init(a_rx_key);
    var out: [MAX_PLAINTEXT]u8 = undefined;
    const plen = decodeIngress(&a_rx, buf[0..@intCast(rc)], &out) orelse return error.UnexpectedDrop;
    try std.testing.expectEqualSlices(u8, &ip_pkt, out[0..plen]);

    // A packet whose destination has no route is dropped (no default peer).
    const no_route = ipPkt(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 9 });
    _ = sys.write(pipe_fds[1], &no_route, no_route.len);
    r.pumpTunToUdp();
    const rc2 = sys.recvfrom(udp_a, &buf, buf.len, 0, null, null);
    try std.testing.expect(sys.errno(rc2) == .AGAIN);
    // The no-route packet was read but dropped: the drop counter records it.
    try std.testing.expectEqual(@as(u64, 2), ctr.tun_rx_packets);
    try std.testing.expectEqual(@as(u64, 1), ctr.drop_tun_no_route);
}

test "pump: obfuscated ingress trial-selects the sender, de-masks, and delivers (header obfuscation)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x33} ** crypto.KEY_LEN;

    // The reactor delivers LOCAL packets to its TUN; here the TUN is a pipe whose
    // read end the test inspects.
    const pipe_fds = sys.pipeNonblock() catch return error.SkipZigTest;
    defer _ = sys.close(pipe_fds[0]);
    defer _ = sys.close(pipe_fds[1]);

    const udp_hub = try makeUdpLoopback(); // reactor's udp_fd (local id 1)
    defer _ = sys.close(udp_hub);
    const udp_a = try makeUdpLoopback(); // spoke A (id 2)
    defer _ = sys.close(udp_a);

    const hub_addr = try addrOf(udp_hub);

    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, try addrOf(udp_a), try policy.parseCidr("10.0.0.2/32"), TEST_EPOCH);
    // A second peer (id 3) so the trial has more than one candidate key to reject.
    _ = try reg.add(psk, 3, fakeAddr(40003), try policy.parseCidr("10.0.0.3/32"), TEST_EPOCH);

    // Inner dst 10.0.0.1 is the hub's own TUN address (LOCAL delivery).
    const entries = [_]policy.PolicyEntry{.{
        .src = try policy.parseCidr("0.0.0.0/0"),
        .dst = try policy.parseCidr("10.0.0.1/32"),
        .action = .forward,
        .target = peer.LOCAL_TARGET,
    }};
    var tree = policy.PolicyTree{ .entries = &entries };
    var active = policy.ActiveTree.init(&tree);

    var r = Reactor.init(pipe_fds[1], udp_hub, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;
    r.obfuscate = true; // the node under test runs with header obfuscation enabled

    const a_tx_key = crypto.deriveLinkKey(psk, 2, 1); // spoke A -> hub direction
    var a_tx = crypto.TxSession.init(a_tx_key, TEST_EPOCH);
    const legit = ipPkt(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 });
    var wire: [MAX_WIRE]u8 = undefined;
    var buf: [MAX_PLAINTEXT]u8 = undefined;

    // A obfuscates its datagram exactly as an obfuscation-enabled spoke would.
    const wl = encodeEgress(&a_tx, 2, &legit, &wire);
    obfuscateHeader(a_tx_key, wire[0..wl]);
    _ = sys.sendto(udp_a, &wire, wl, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);

    // The hub trial-de-masked the header (against peers 2 and 3), selected peer 2,
    // authenticated, and delivered the inner packet to its TUN.
    const rc = sys.read(pipe_fds[0], &buf, buf.len);
    try std.testing.expect(sys.errno(rc) == .SUCCESS);
    try std.testing.expectEqualSlices(u8, &legit, buf[0..@intCast(rc)]);

    // A NON-obfuscated datagram is unintelligible to an obfuscation-enabled hub:
    // its cleartext header, treated as masked, de-masks to garbage that matches no
    // peer, so it is dropped and never reaches the TUN.
    var a_tx2 = crypto.TxSession.init(a_tx_key, TEST_EPOCH);
    a_tx2.counter.value = 9; // a fresh, unseen seq
    const wl_plain = encodeEgress(&a_tx2, 2, &legit, &wire);
    _ = sys.sendto(udp_a, &wire, wl_plain, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .AGAIN);
    try std.testing.expectEqual(@as(u64, 1), ctr.drop_udp_unknown_peer);

    // A runt (too short to hold an obfuscated header + tag) is the ONLY drop an
    // outsider can push into auth_or_invalid once the selector is masked — every
    // full-length unmatched datagram lands in unknown_peer (above). This mirrors
    // the active-probe integration scenario so both layers assert the same taxonomy.
    const runt = [_]u8{ 1, 0, 2 };
    _ = sys.sendto(udp_a, &runt, runt.len, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .AGAIN);
    try std.testing.expectEqual(@as(u64, 1), ctr.drop_udp_auth_or_invalid);
}

test "pump: obfuscated ingress fast path is O(1), roaming pays one scan, junk is budget-capped (issue #174)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x35} ** crypto.KEY_LEN;

    const pipe_fds = sys.pipeNonblock() catch return error.SkipZigTest;
    defer _ = sys.close(pipe_fds[0]);
    defer _ = sys.close(pipe_fds[1]);

    const udp_hub = try makeUdpLoopback(); // reactor's udp_fd (local id 1)
    defer _ = sys.close(udp_hub);
    const udp_a = try makeUdpLoopback(); // spoke A (id 2), at its REGISTERED endpoint
    defer _ = sys.close(udp_a);
    const udp_roam = try makeUdpLoopback(); // spoke A again, from an UNKNOWN endpoint (roamed)
    defer _ = sys.close(udp_roam);
    const udp_junk = try makeUdpLoopback(); // off-path junk source (never registered)
    defer _ = sys.close(udp_junk);

    const hub_addr = try addrOf(udp_hub);

    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, try addrOf(udp_a), try policy.parseCidr("10.0.0.2/32"), TEST_EPOCH);
    _ = try reg.add(psk, 3, fakeAddr(40003), try policy.parseCidr("10.0.0.3/32"), TEST_EPOCH);

    const entries = [_]policy.PolicyEntry{.{
        .src = try policy.parseCidr("0.0.0.0/0"),
        .dst = try policy.parseCidr("10.0.0.1/32"),
        .action = .forward,
        .target = peer.LOCAL_TARGET,
    }};
    var tree = policy.PolicyTree{ .entries = &entries };
    var active = policy.ActiveTree.init(&tree);

    var r = Reactor.init(pipe_fds[1], udp_hub, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;
    r.obfuscate = true;

    const a_tx_key = crypto.deriveLinkKey(psk, 2, 1); // spoke A -> hub direction
    var a_tx = crypto.TxSession.init(a_tx_key, TEST_EPOCH);
    const legit = ipPkt(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 });
    var wire: [MAX_WIRE]u8 = undefined;
    var buf: [MAX_PLAINTEXT]u8 = undefined;

    // 1. Steady state: A sends from its registered endpoint. The source-endpoint
    //    fast path resolves it with ONE keyed trial — the full-scan budget is
    //    untouched and the packet is delivered.
    var wl = encodeEgress(&a_tx, 2, &legit, &wire);
    obfuscateHeader(a_tx_key, wire[0..wl]);
    _ = sys.sendto(udp_a, &wire, wl, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .SUCCESS);
    try std.testing.expectEqual(OBFS_SCAN_BUDGET, r.obfs_scan_budget); // no scan slot spent

    // 2. Roaming: A sends from an endpoint no peer currently owns. The fast path
    //    misses, ONE budgeted full scan resolves it, the packet is delivered, and
    //    the new endpoint is learned back onto the fast path.
    wl = encodeEgress(&a_tx, 2, &legit, &wire);
    obfuscateHeader(a_tx_key, wire[0..wl]);
    _ = sys.sendto(udp_roam, &wire, wl, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .SUCCESS);
    try std.testing.expectEqual(OBFS_SCAN_BUDGET - 1, r.obfs_scan_budget); // exactly one scan slot spent
    try std.testing.expect(sameEndpoint(reg.findById(2).?.endpoint, try addrOf(udp_roam)));

    // 3. Post-roam steady state: the next datagram from the roamed endpoint rides
    //    the fast path again (the drain-refilled budget stays full).
    wl = encodeEgress(&a_tx, 2, &legit, &wire);
    obfuscateHeader(a_tx_key, wire[0..wl]);
    _ = sys.sendto(udp_roam, &wire, wl, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .SUCCESS);
    try std.testing.expectEqual(OBFS_SCAN_BUDGET, r.obfs_scan_budget);

    // 4. Off-path flood: unknown-source junk that no peer's key claims. One drain
    //    performs at most OBFS_SCAN_BUDGET full scans (each dropped unknown_peer);
    //    everything past the budget is dropped WITHOUT any keyed trials
    //    (drop_udp_scan_budget) — the amplification is capped per drain.
    var junk: [HEADER_LEN + crypto.TAG_LEN]u8 = undefined;
    for (&junk, 0..) |*b, i| b.* = @intCast((i *% 131 +% 7) & 0xff);
    const extra = 3;
    var n: usize = 0;
    while (n < OBFS_SCAN_BUDGET + extra) : (n += 1) {
        _ = sys.sendto(udp_junk, &junk, junk.len, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    }
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .AGAIN);
    try std.testing.expectEqual(@as(u64, OBFS_SCAN_BUDGET), ctr.drop_udp_unknown_peer);
    try std.testing.expectEqual(@as(u64, extra), ctr.drop_udp_scan_budget);
    try std.testing.expectEqual(@as(u32, 0), r.obfs_scan_budget);

    // 5. The budget refills next drain: A (still at the roamed endpoint) is not
    //    locked out by the earlier flood — it delivers via the fast path anyway.
    wl = encodeEgress(&a_tx, 2, &legit, &wire);
    obfuscateHeader(a_tx_key, wire[0..wl]);
    _ = sys.sendto(udp_roam, &wire, wl, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .SUCCESS);
    try std.testing.expectEqual(OBFS_SCAN_BUDGET, r.obfs_scan_budget);
}

test "pump: relay A -> hub -> B routes by policy target, no-reflect holds" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x44} ** crypto.KEY_LEN;

    const udp_hub = try makeUdpLoopback(); // reactor (local id 1)
    defer _ = sys.close(udp_hub);
    const udp_a = try makeUdpLoopback(); // spoke A (id 2)
    defer _ = sys.close(udp_a);
    const udp_b = try makeUdpLoopback(); // spoke B (id 3)
    defer _ = sys.close(udp_b);

    const hub_addr = try addrOf(udp_hub);

    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, try addrOf(udp_a), try policy.parseCidr("10.0.0.2/32"), TEST_EPOCH);
    _ = try reg.add(psk, 3, try addrOf(udp_b), try policy.parseCidr("10.0.0.3/32"), TEST_EPOCH);

    // 10.0.0.3 relays to peer 3; 10.0.0.2 would reflect back to the source.
    const entries = [_]policy.PolicyEntry{
        .{ .src = try policy.parseCidr("0.0.0.0/0"), .dst = try policy.parseCidr("10.0.0.3/32"), .action = .forward, .target = 3 },
        .{ .src = try policy.parseCidr("0.0.0.0/0"), .dst = try policy.parseCidr("10.0.0.2/32"), .action = .forward, .target = 2 },
    };
    var tree = policy.PolicyTree{ .entries = &entries };
    var active = policy.ActiveTree.init(&tree);

    // tun fd unused on the relay path; a throwaway pipe write end keeps it valid.
    const pipe_fds = sys.pipeNonblock() catch return error.SkipZigTest;
    defer _ = sys.close(pipe_fds[0]);
    defer _ = sys.close(pipe_fds[1]);

    var r = Reactor.init(pipe_fds[1], udp_hub, null, &active, &reg);

    // A seals with its tx key to the hub: derive(psk, 2, 1).
    const a_tx_key = crypto.deriveLinkKey(psk, 2, 1);
    var a_tx = crypto.TxSession.init(a_tx_key, TEST_EPOCH);
    const to_b = ipPkt(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 3 });
    var wire: [MAX_WIRE]u8 = undefined;
    const wlen = encodeEgress(&a_tx, 2, &to_b, &wire);
    _ = sys.sendto(udp_a, &wire, wlen, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));

    r.pumpUdpIngress(r.udp_fds[0], 0);

    // B receives the relayed packet, decodes with derive(psk, 1, 3).
    var buf: [MAX_WIRE]u8 = undefined;
    const rcb = sys.recvfrom(udp_b, &buf, buf.len, 0, null, null);
    try std.testing.expect(sys.errno(rcb) == .SUCCESS);
    const b_rx_key = crypto.deriveLinkKey(psk, 1, 3);
    var b_rx = crypto.RxSession.init(b_rx_key);
    var out: [MAX_PLAINTEXT]u8 = undefined;
    const plen = decodeIngress(&b_rx, buf[0..@intCast(rcb)], &out) orelse return error.UnexpectedDrop;
    try std.testing.expectEqualSlices(u8, &to_b, out[0..plen]);

    // No-reflect: A sends a packet destined to itself (target 2). The hub must
    // not bounce it back to A.
    const to_self = ipPkt(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 2 });
    const wlen2 = encodeEgress(&a_tx, 2, &to_self, &wire);
    _ = sys.sendto(udp_a, &wire, wlen2, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    const rca = sys.recvfrom(udp_a, &buf, buf.len, 0, null, null);
    try std.testing.expect(sys.errno(rca) == .AGAIN);
}

test "pump: ingress delivers LOCAL target, drops strangers and inner-source spoofs" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x55} ** crypto.KEY_LEN;

    const pipe_fds = sys.pipeNonblock() catch return error.SkipZigTest;
    defer _ = sys.close(pipe_fds[0]);
    defer _ = sys.close(pipe_fds[1]);

    const udp_hub = try makeUdpLoopback(); // reactor (local id 1)
    defer _ = sys.close(udp_hub);
    const udp_a = try makeUdpLoopback(); // spoke A (id 2), bound to 10.0.0.2/32
    defer _ = sys.close(udp_a);
    const udp_c = try makeUdpLoopback(); // an unregistered stranger
    defer _ = sys.close(udp_c);

    const hub_addr = try addrOf(udp_hub);

    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, try addrOf(udp_a), try policy.parseCidr("10.0.0.2/32"), TEST_EPOCH);

    // 10.0.0.1 is the hub's own TUN address (LOCAL delivery).
    const entries = [_]policy.PolicyEntry{.{
        .src = try policy.parseCidr("0.0.0.0/0"),
        .dst = try policy.parseCidr("10.0.0.1/32"),
        .action = .forward,
        .target = peer.LOCAL_TARGET,
    }};
    var tree = policy.PolicyTree{ .entries = &entries };
    var active = policy.ActiveTree.init(&tree);

    var r = Reactor.init(pipe_fds[1], udp_hub, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;

    const a_addr = try addrOf(udp_a);
    const a_tx_key = crypto.deriveLinkKey(psk, 2, 1);
    // A single per-peer session for everything peer A legitimately sends (mirrors
    // reality: one counter per peer, so sequence numbers never repeat against the
    // hub's per-peer replay window).
    var a_tx = crypto.TxSession.init(a_tx_key, TEST_EPOCH);

    const legit = ipPkt(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 });
    var wire: [MAX_WIRE]u8 = undefined;
    var buf: [MAX_PLAINTEXT]u8 = undefined;

    // Unknown `key_id` selector (issue #34): no peer has id 99, so the datagram is
    // dropped before any crypto runs. Sealed with A's real key but mislabelled.
    const wl_unk = encodeEgress(&a_tx, 99, &legit, &wire);
    _ = sys.sendto(udp_a, &wire, wl_unk, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .AGAIN);
    try std.testing.expectEqual(@as(u64, 1), ctr.drop_udp_unknown_peer);

    // True stranger: a correct `key_id=2` but sealed with the WRONG key, arriving
    // from a brand-new endpoint (udp_c). It selects peer A, fails authentication,
    // and is dropped — and it MUST NOT move A's learned endpoint.
    const wrong_key: crypto.Key = [_]u8{0x77} ** crypto.KEY_LEN;
    var bad_tx = crypto.TxSession.init(wrong_key, TEST_EPOCH);
    const wl_bad = encodeEgress(&bad_tx, 2, &legit, &wire);
    _ = sys.sendto(udp_c, &wire, wl_bad, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .AGAIN);
    try std.testing.expectEqual(@as(u64, 1), ctr.drop_udp_auth_or_invalid);
    try std.testing.expectEqual(@as(u64, 0), ctr.udp_endpoint_learned);
    try std.testing.expect(sameEndpoint(reg.findById(2).?.endpoint, a_addr));

    // Inner-source spoof: A is bound to 10.0.0.2/32 but claims source 10.0.0.99.
    // It authenticates (so the replay window records it) but fails the inner-source
    // check — and an authenticated-but-spoofed packet MUST NOT move the endpoint.
    const spoof = ipPkt(.{ 10, 0, 0, 99 }, .{ 10, 0, 0, 1 });
    const wl1 = encodeEgress(&a_tx, 2, &spoof, &wire);
    _ = sys.sendto(udp_c, &wire, wl1, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .AGAIN);
    try std.testing.expectEqual(@as(u64, 1), ctr.drop_udp_spoof);
    try std.testing.expectEqual(@as(u64, 0), ctr.udp_endpoint_learned);
    try std.testing.expect(sameEndpoint(reg.findById(2).?.endpoint, a_addr));

    // Legitimate packet from A's configured endpoint -> written to the TUN. The
    // endpoint is unchanged, so no relearn is recorded.
    const wl2 = encodeEgress(&a_tx, 2, &legit, &wire);
    _ = sys.sendto(udp_a, &wire, wl2, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    const rc = sys.read(pipe_fds[0], &buf, buf.len);
    try std.testing.expect(sys.errno(rc) == .SUCCESS);
    try std.testing.expectEqualSlices(u8, &legit, buf[0..@intCast(rc)]);
    try std.testing.expectEqual(@as(u64, 0), ctr.udp_endpoint_learned);
}

test "pump: an authenticated packet from a new endpoint relearns the peer (issue #34)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x55} ** crypto.KEY_LEN;

    const pipe_fds = sys.pipeNonblock() catch return error.SkipZigTest;
    defer _ = sys.close(pipe_fds[0]);
    defer _ = sys.close(pipe_fds[1]);

    const udp_hub = try makeUdpLoopback();
    defer _ = sys.close(udp_hub);
    const udp_a = try makeUdpLoopback(); // A's ACTUAL (roamed) endpoint
    defer _ = sys.close(udp_a);

    const hub_addr = try addrOf(udp_hub);
    const a_addr = try addrOf(udp_a);

    // A is CONFIGURED at a stale endpoint; it actually transmits from udp_a.
    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, fakeAddr(9), try policy.parseCidr("10.0.0.2/32"), TEST_EPOCH);
    try std.testing.expect(!sameEndpoint(reg.findById(2).?.endpoint, a_addr));

    const entries = [_]policy.PolicyEntry{.{
        .src = try policy.parseCidr("0.0.0.0/0"),
        .dst = try policy.parseCidr("10.0.0.1/32"),
        .action = .forward,
        .target = peer.LOCAL_TARGET,
    }};
    var tree = policy.PolicyTree{ .entries = &entries };
    var active = policy.ActiveTree.init(&tree);

    var r = Reactor.init(pipe_fds[1], udp_hub, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;

    const a_tx_key = crypto.deriveLinkKey(psk, 2, 1);
    var a_tx = crypto.TxSession.init(a_tx_key, TEST_EPOCH);
    const legit = ipPkt(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 });
    var wire: [MAX_WIRE]u8 = undefined;
    var buf: [MAX_PLAINTEXT]u8 = undefined;

    // First authenticated datagram from the new endpoint: delivered AND learned.
    const wl0 = encodeEgress(&a_tx, 2, &legit, &wire);
    _ = sys.sendto(udp_a, &wire, wl0, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    const rc0 = sys.read(pipe_fds[0], &buf, buf.len);
    try std.testing.expect(sys.errno(rc0) == .SUCCESS);
    try std.testing.expectEqualSlices(u8, &legit, buf[0..@intCast(rc0)]);
    try std.testing.expectEqual(@as(u64, 1), ctr.udp_endpoint_learned);
    try std.testing.expectEqual(@as(u64, 0), ctr.drop_udp_unknown_peer);
    try std.testing.expect(sameEndpoint(reg.findById(2).?.endpoint, a_addr));

    // A second datagram from the SAME (now learned) endpoint does not relearn.
    const wl1 = encodeEgress(&a_tx, 2, &legit, &wire);
    _ = sys.sendto(udp_a, &wire, wl1, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    const rc1 = sys.read(pipe_fds[0], &buf, buf.len);
    try std.testing.expect(sys.errno(rc1) == .SUCCESS);
    try std.testing.expectEqual(@as(u64, 1), ctr.udp_endpoint_learned);
}

test "pump: a replayed datagram from a new endpoint cannot move the endpoint (issue #34)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x55} ** crypto.KEY_LEN;

    const pipe_fds = sys.pipeNonblock() catch return error.SkipZigTest;
    defer _ = sys.close(pipe_fds[0]);
    defer _ = sys.close(pipe_fds[1]);

    const udp_hub = try makeUdpLoopback();
    defer _ = sys.close(udp_hub);
    const udp_a = try makeUdpLoopback();
    defer _ = sys.close(udp_a);
    const udp_c = try makeUdpLoopback(); // attacker replaying from elsewhere
    defer _ = sys.close(udp_c);

    const hub_addr = try addrOf(udp_hub);
    const a_addr = try addrOf(udp_a);

    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, a_addr, try policy.parseCidr("10.0.0.2/32"), TEST_EPOCH);

    const entries = [_]policy.PolicyEntry{.{
        .src = try policy.parseCidr("0.0.0.0/0"),
        .dst = try policy.parseCidr("10.0.0.1/32"),
        .action = .forward,
        .target = peer.LOCAL_TARGET,
    }};
    var tree = policy.PolicyTree{ .entries = &entries };
    var active = policy.ActiveTree.init(&tree);

    var r = Reactor.init(pipe_fds[1], udp_hub, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;

    const a_tx_key = crypto.deriveLinkKey(psk, 2, 1);
    var a_tx = crypto.TxSession.init(a_tx_key, TEST_EPOCH);
    const legit = ipPkt(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 });
    var wire: [MAX_WIRE]u8 = undefined;
    var buf: [MAX_PLAINTEXT]u8 = undefined;

    // A genuine datagram from A's real endpoint -> accepted, no endpoint change.
    const wl = encodeEgress(&a_tx, 2, &legit, &wire);
    _ = sys.sendto(udp_a, &wire, wl, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .SUCCESS);
    try std.testing.expectEqual(@as(u64, 0), ctr.udp_endpoint_learned);

    // The attacker replays the identical bytes from udp_c. The replay window
    // rejects it (decode null) BEFORE any endpoint learning, so A stays put.
    _ = sys.sendto(udp_c, &wire, wl, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .AGAIN);
    try std.testing.expectEqual(@as(u64, 1), ctr.drop_udp_auth_or_invalid);
    try std.testing.expectEqual(@as(u64, 0), ctr.udp_endpoint_learned);
    try std.testing.expect(sameEndpoint(reg.findById(2).?.endpoint, a_addr));
}

test "pump: a short datagram is counted and never crashes parseKeyId (issue #34)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x55} ** crypto.KEY_LEN;

    const udp_hub = try makeUdpLoopback();
    defer _ = sys.close(udp_hub);
    const udp_a = try makeUdpLoopback();
    defer _ = sys.close(udp_a);
    const hub_addr = try addrOf(udp_hub);

    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, try addrOf(udp_a), try policy.parseCidr("10.0.0.2/32"), TEST_EPOCH);

    const entries = [_]policy.PolicyEntry{.{
        .src = try policy.parseCidr("0.0.0.0/0"),
        .dst = try policy.parseCidr("10.0.0.1/32"),
        .action = .forward,
        .target = peer.LOCAL_TARGET,
    }};
    var tree = policy.PolicyTree{ .entries = &entries };
    var active = policy.ActiveTree.init(&tree);

    var r = Reactor.init(0, udp_hub, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;

    // 3 bytes: too short to even hold the key_id selector at [2..4].
    const runt = [_]u8{ 1, 0, 0 };
    _ = sys.sendto(udp_a, &runt, runt.len, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expectEqual(@as(u64, 1), ctr.drop_udp_auth_or_invalid);
    try std.testing.expectEqual(@as(u64, 0), ctr.udp_endpoint_learned);
}
test "pump: relay learns the source's endpoint, leaves the destination's untouched (issue #34)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x44} ** crypto.KEY_LEN;

    const udp_hub = try makeUdpLoopback();
    defer _ = sys.close(udp_hub);
    const udp_a = try makeUdpLoopback(); // A's ACTUAL (roamed) endpoint
    defer _ = sys.close(udp_a);
    const udp_b = try makeUdpLoopback(); // B, at its configured endpoint
    defer _ = sys.close(udp_b);

    const hub_addr = try addrOf(udp_hub);
    const a_addr = try addrOf(udp_a);
    const b_addr = try addrOf(udp_b);

    // A (id 2) is CONFIGURED at a stale endpoint; B (id 3) at its real one.
    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, fakeAddr(9), try policy.parseCidr("10.0.0.2/32"), TEST_EPOCH);
    _ = try reg.add(psk, 3, b_addr, try policy.parseCidr("10.0.0.3/32"), TEST_EPOCH);

    const entries = [_]policy.PolicyEntry{
        .{ .src = try policy.parseCidr("0.0.0.0/0"), .dst = try policy.parseCidr("10.0.0.3/32"), .action = .forward, .target = 3 },
    };
    var tree = policy.PolicyTree{ .entries = &entries };
    var active = policy.ActiveTree.init(&tree);

    const pipe_fds = sys.pipeNonblock() catch return error.SkipZigTest;
    defer _ = sys.close(pipe_fds[0]);
    defer _ = sys.close(pipe_fds[1]);

    var r = Reactor.init(pipe_fds[1], udp_hub, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;

    const a_tx_key = crypto.deriveLinkKey(psk, 2, 1);
    var a_tx = crypto.TxSession.init(a_tx_key, TEST_EPOCH);
    const to_b = ipPkt(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 3 });
    var wire: [MAX_WIRE]u8 = undefined;
    const wlen = encodeEgress(&a_tx, 2, &to_b, &wire);
    _ = sys.sendto(udp_a, &wire, wlen, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);

    // B still receives the relayed packet at its (unchanged) endpoint.
    var buf: [MAX_WIRE]u8 = undefined;
    const rcb = sys.recvfrom(udp_b, &buf, buf.len, 0, null, null);
    try std.testing.expect(sys.errno(rcb) == .SUCCESS);

    // The hub learned A's real endpoint; B's endpoint was not disturbed.
    try std.testing.expectEqual(@as(u64, 1), ctr.udp_endpoint_learned);
    try std.testing.expect(sameEndpoint(reg.findById(2).?.endpoint, a_addr));
    try std.testing.expect(sameEndpoint(reg.findById(3).?.endpoint, b_addr));
}
test "pump: an authenticated non-IPv4 inner packet is dropped before endpoint learning (#41)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x55} ** crypto.KEY_LEN;

    const pipe_fds = sys.pipeNonblock() catch return error.SkipZigTest;
    defer _ = sys.close(pipe_fds[0]);
    defer _ = sys.close(pipe_fds[1]);

    const udp_hub = try makeUdpLoopback();
    defer _ = sys.close(udp_hub);
    const udp_a = try makeUdpLoopback();
    defer _ = sys.close(udp_a);
    const hub_addr = try addrOf(udp_hub);

    // A is configured at a stale endpoint; if learning ran it would move to udp_a.
    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, fakeAddr(9), try policy.parseCidr("10.0.0.2/32"), TEST_EPOCH);

    const entries = [_]policy.PolicyEntry{.{
        .src = try policy.parseCidr("0.0.0.0/0"),
        .dst = try policy.parseCidr("10.0.0.1/32"),
        .action = .forward,
        .target = peer.LOCAL_TARGET,
    }};
    var tree = policy.PolicyTree{ .entries = &entries };
    var active = policy.ActiveTree.init(&tree);

    var r = Reactor.init(pipe_fds[1], udp_hub, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;

    const a_tx_key = crypto.deriveLinkKey(psk, 2, 1);
    var a_tx = crypto.TxSession.init(a_tx_key, TEST_EPOCH);

    // Authenticated but malformed inner: version nibble is 0 (not 4). Bytes
    // [12..16] hold 10.0.0.2, which WOULD satisfy allowed_src if the source
    // parser skipped IPv4 validation — so this packet must be dropped at the
    // not_ipv4 gate, before any endpoint learning.
    var bad = [_]u8{0} ** 28;
    bad[12] = 10;
    bad[13] = 0;
    bad[14] = 0;
    bad[15] = 2;
    var wire: [MAX_WIRE]u8 = undefined;
    const wl = encodeEgress(&a_tx, 2, &bad, &wire);
    _ = sys.sendto(udp_a, &wire, wl, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);

    var buf: [MAX_PLAINTEXT]u8 = undefined;
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .AGAIN);
    try std.testing.expectEqual(@as(u64, 1), ctr.drop_udp_not_ipv4);
    try std.testing.expectEqual(@as(u64, 0), ctr.udp_endpoint_learned);
    try std.testing.expect(sameEndpoint(reg.findById(2).?.endpoint, fakeAddr(9)));
}

test "keepalive: a spoke emits a sealed KEEPALIVE datagram to its hub with no host traffic (issue #96)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x55} ** crypto.KEY_LEN;

    const udp_hub = try makeUdpLoopback(); // the hub: receives the keepalive
    defer _ = sys.close(udp_hub);
    const udp_spoke = try makeUdpLoopback(); // the spoke's own UDP socket (egress)
    defer _ = sys.close(udp_spoke);

    const hub_addr = try addrOf(udp_hub);

    // A spoke (local_id=2) whose single hub peer is id=1 at hub_addr.
    var reg = peer.PeerRegistry.init(2);
    _ = try reg.add(psk, 1, hub_addr, ANY_SRC, TEST_EPOCH);

    var tree = policy.PolicyTree{ .entries = &.{} };
    var active = policy.ActiveTree.init(&tree);
    var r = Reactor.init(-1, udp_spoke, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;
    r.keepalive_ns = 20 * std.time.ns_per_s;
    r.keepalive_peer_id = 1;

    // Emit one keepalive directly (no TUN/host traffic involved).
    r.sendKeepalive();
    try std.testing.expectEqual(@as(u64, 1), ctr.keepalive_tx);

    // The hub receives exactly a header + tag, KEEPALIVE-flagged, and it
    // authenticates + decodes to a zero-length plaintext (no inner packet).
    var recv: [MAX_WIRE]u8 = undefined;
    const rc = sys.read(udp_hub, &recv, recv.len);
    try std.testing.expect(sys.errno(rc) == .SUCCESS);
    const got: usize = @intCast(rc);
    try std.testing.expectEqual(@as(usize, HEADER_LEN + crypto.TAG_LEN), got);
    try std.testing.expect(recv[1] & FLAG_KEEPALIVE != 0);

    var hub_rx = crypto.RxSession.init(crypto.deriveLinkKey(psk, 2, 1));
    var out: [MAX_PLAINTEXT]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, 0), decodeIngress(&hub_rx, recv[0..got], &out));
}

test "keepalive: hub authenticated keepalive refreshes the endpoint and is not injected into the TUN (issue #96)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const psk: crypto.Key = [_]u8{0x55} ** crypto.KEY_LEN;

    const pipe_fds = sys.pipeNonblock() catch return error.SkipZigTest;
    defer _ = sys.close(pipe_fds[0]);
    defer _ = sys.close(pipe_fds[1]);

    const udp_hub = try makeUdpLoopback(); // hub's UDP socket (reactor udp_fd)
    defer _ = sys.close(udp_hub);
    const udp_spoke = try makeUdpLoopback(); // the spoke's ACTUAL (roamed) endpoint
    defer _ = sys.close(udp_spoke);

    const hub_addr = try addrOf(udp_hub);
    const spoke_addr = try addrOf(udp_spoke);

    // The hub (local_id=1) has the spoke (id=2) CONFIGURED at a stale endpoint;
    // the spoke really transmits from udp_spoke.
    var reg = peer.PeerRegistry.init(1);
    _ = try reg.add(psk, 2, fakeAddr(9), try policy.parseCidr("10.0.0.2/32"), TEST_EPOCH);
    try std.testing.expect(!sameEndpoint(reg.findById(2).?.endpoint, spoke_addr));

    var tree = policy.PolicyTree{ .entries = &.{} };
    var active = policy.ActiveTree.init(&tree);
    var r = Reactor.init(pipe_fds[1], udp_hub, null, &active, &reg);
    var ctr = stats.Counters{};
    r.counters = &ctr;

    var spoke_tx = crypto.TxSession.init(crypto.deriveLinkKey(psk, 2, 1), TEST_EPOCH);
    var wire: [MAX_WIRE]u8 = undefined;
    var buf: [MAX_PLAINTEXT]u8 = undefined;

    // The idle spoke sends one keepalive from its roamed endpoint.
    const wl = encodeKeepalive(&spoke_tx, 2, &wire);
    _ = sys.sendto(udp_spoke, &wire, wl, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);

    // It is counted as a keepalive, relearns the endpoint + refreshes last_seen,
    // and writes NOTHING to the TUN (it carries no inner packet).
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .AGAIN);
    try std.testing.expectEqual(@as(u64, 1), ctr.keepalive_rx);
    try std.testing.expectEqual(@as(u64, 0), ctr.tun_tx_packets);
    try std.testing.expectEqual(@as(u64, 1), ctr.udp_endpoint_learned);
    try std.testing.expect(sameEndpoint(reg.findById(2).?.endpoint, spoke_addr));
    try std.testing.expect(reg.findById(2).?.last_seen_wall_ns > 0);

    // A keepalive sealed with the WRONG key fails authentication: it is dropped
    // before the keepalive branch, so it moves nothing.
    const bad_psk: crypto.Key = [_]u8{0x66} ** crypto.KEY_LEN;
    var bad_tx = crypto.TxSession.init(crypto.deriveLinkKey(bad_psk, 2, 1), TEST_EPOCH);
    const wlb = encodeKeepalive(&bad_tx, 2, &wire);
    _ = sys.sendto(udp_spoke, &wire, wlb, 0, @ptrCast(@constCast(&hub_addr)), @sizeOf(sys.sockaddr.in));
    r.pumpUdpIngress(r.udp_fds[0], 0);
    try std.testing.expect(sys.errno(sys.read(pipe_fds[0], &buf, buf.len)) == .AGAIN);
    try std.testing.expectEqual(@as(u64, 1), ctr.drop_udp_auth_or_invalid);
    try std.testing.expectEqual(@as(u64, 1), ctr.keepalive_rx);
    try std.testing.expectEqual(@as(u64, 1), ctr.udp_endpoint_learned);
    try std.testing.expect(sameEndpoint(reg.findById(2).?.endpoint, spoke_addr));
}

fn fuzzIngressDecode(_: void, smith: *std.testing.Smith) anyerror!void {
    // A fixed receive session: the fuzzer drives the datagram bytes, not the key.
    // The decode path must never crash, read out of bounds, or report a length
    // larger than the output buffer for ANY input — well-formed or hostile.
    const psk: crypto.Key = [_]u8{0xAB} ** crypto.KEY_LEN;
    var rx = crypto.RxSession.init(crypto.deriveLinkKey(psk, 1, 2));

    var dgram: [MAX_WIRE]u8 = undefined;
    const n = smith.slice(&dgram);
    const input = dgram[0..n];

    // parseKeyId is a pure header read: null iff too short, never otherwise.
    const kid = parseKeyId(input);
    try std.testing.expectEqual(input.len < HEADER_LEN, kid == null);

    var out: [MAX_PLAINTEXT]u8 = undefined;
    if (decodeIngress(&rx, input, &out)) |plen| {
        // A returned length must be a valid slice of the output buffer.
        try std.testing.expect(plen <= out.len);
    }
}

test "fuzz: UDP ingress decode path tolerates arbitrary datagrams (#40)" {
    try std.testing.fuzz({}, fuzzIngressDecode, .{});
}
