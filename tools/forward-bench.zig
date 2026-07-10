//! forward-bench — offline forwarding hot-path microbenchmark (issue #101).
//!
//! Measures the per-packet cost of subnetra's data-plane forwarding decision
//! *around* the AEAD, using the LIVE reactor/policy/peer primitives with NO
//! network I/O (no tun fd, no udp fd, no syscalls). Three measurements are made:
//!
//!   tx-forward (egress, `pumpTunToUdp` hot path):
//!     ipv4Dst -> PolicyTree.match -> PeerRegistry.findById -> encodeEgress(seal)
//!
//!   rx-forward (ingress relay, `pumpUdpIngress` hot path):
//!     parseKeyId -> findById -> decodeIngress(open+replay) -> ipv4Src ->
//!     allowed_src.contains -> ipv4Dst -> PolicyTree.match
//!
//!   ingress-select (obfuscation de-mux, `selectIngressPeer`):
//!     with header obfuscation ON (the default) the wire key_id is masked, so the
//!     reactor cannot index a peer directly — it trials peers' rx link keys via a
//!     keyed-Blake2b `tryDeobfuscate` until one recovers a self-consistent
//!     header. Since issue #174 the live reactor tries the source-endpoint peer
//!     first (steady-state O(1)) and meters the fallback full sweep with a
//!     per-drain budget; what this tool measures is that fallback's worst case —
//!     a junk datagram NO peer claims paying the FULL peer-count sweep (i.e. one
//!     budget slot) before it is silently dropped — against the cleartext key_id
//!     selector (obfuscation off) to expose the per-peer de-mux cost that scales
//!     with the configured peer count.
//!
//! The tx/rx pipeline numbers are also printed against the raw AEAD floor measured
//! in the same run (seal for tx, open for rx) so the "forwarding tax" — the parse +
//! route + registry-lookup overhead the daemon pays on top of crypto — is
//! visible directly, and the ingress-select number against the cleartext selector
//! for the obfuscation de-mux tax. crypto-bench (issue #66) measures the AEAD floor
//! in isolation; this tool measures what the daemon actually executes per packet.
//!
//! NOT part of the shipped daemon (built via `zig build tool:forward-bench`).

const std = @import("std");
const builtin = @import("builtin");
const bt = @import("subnetra");
const build_options = @import("build_options");

const crypto = bt.crypto;
const config = bt.config;
const policy = bt.policy;
const peer = bt.peer;
const reactor = bt.reactor;

const MAX_PLAINTEXT = reactor.MAX_PLAINTEXT;
const MAX_WIRE = reactor.MAX_WIRE;
const HEADER_LEN = reactor.HEADER_LEN;
const TAG_LEN = crypto.TAG_LEN;

/// Minimum IPv4 packet the reactor's parsers accept (header only).
const MIN_IP = 20;

/// Fixed in-range session epoch (wall-clock-ns shaped, nonzero). The value is
/// irrelevant to forwarding cost; it only has to be consistent on both ends.
const EPOCH: u64 = 1_750_000_000_000_000_000;

const IP_SPOKE: u32 = 0x0A42_0002; // 10.66.0.2  (inner src of the relayed packet)
const IP_DEST: u32 = 0x0A42_0003; //  10.66.0.3  (inner dst -> routes to peer 3)

const USAGE =
    \\Usage: forward-bench [--size BYTES] [--iters N] [--peers N]
    \\
    \\Microbenchmark subnetra's in-process forwarding hot path (parse + route +
    \\registry lookup + codec) with no network I/O. Reports tx/rx packet rate, the
    \\forwarding tax over the raw AEAD floor, and the ingress peer-selection cost of
    \\header obfuscation (the per-peer de-mux sweep), all measured in the same run.
    \\
    \\  --size BYTES   inner IPv4 packet size per op (default 1400, 20..1452)
    \\  --iters N      iterations per measurement (default 200000)
    \\  --peers N      peers for the ingress-select sweep (default/max the build's
    \\                 MAX_PEERS; rebuild with -Dmax-peers=128 to sweep higher)
    \\  -h, --help     show this help
    \\  -V, --version  show version
    \\
;

fn writeOut(io: std.Io, bytes: []const u8) void {
    std.Io.File.stdout().writeStreamingAll(io, bytes) catch {};
}

fn writeErr(io: std.Io, bytes: []const u8) void {
    std.Io.File.stderr().writeStreamingAll(io, bytes) catch {};
}

fn nowNs(io: std.Io) i128 {
    const t = std.Io.Timestamp.now(io, .awake);
    return @intCast(t.nanoseconds);
}

/// Write a minimal well-formed IPv4 packet (version 4, IHL 5) of `buf.len`
/// bytes carrying `src`/`dst` (host byte order) so the live `ipv4Src`/`ipv4Dst`
/// parsers accept it. `buf.len` must be >= MIN_IP.
fn craftIpv4(buf: []u8, src: u32, dst: u32) void {
    @memset(buf, 0);
    buf[0] = 0x45; // version 4, IHL 5 (20-byte header)
    std.mem.writeInt(u16, buf[2..4], @intCast(buf.len), .big); // total length
    buf[8] = 64; // TTL
    buf[9] = 17; // protocol UDP
    std.mem.writeInt(u32, buf[12..16], src, .big);
    std.mem.writeInt(u32, buf[16..20], dst, .big);
    var i: usize = MIN_IP;
    while (i < buf.len) : (i += 1) buf[i] = @intCast(i & 0xff);
}

/// Build a hub-side fixture: a registry (local id 1) with spoke peers 2 and 3,
/// and a small longest-prefix policy tree routing the overlay. Returns the
/// registry by pointer-stable storage the caller owns.
const Fixture = struct {
    hub: peer.PeerRegistry,
    entries: [4]policy.PolicyEntry,

    fn tree(self: *const Fixture) policy.PolicyTree {
        return .{ .entries = &self.entries };
    }
};

fn buildFixture(fx: *Fixture, psk: crypto.Key) !void {
    fx.hub = peer.PeerRegistry.init(1);
    const ep2 = try config.parseEndpoint("10.66.0.2:51820");
    const ep3 = try config.parseEndpoint("10.66.0.3:51821");
    const src2 = try config.parseCidr("10.66.0.2/32");
    const src3 = try config.parseCidr("10.66.0.3/32");
    _ = try fx.hub.add(psk, 2, ep2, src2, EPOCH);
    _ = try fx.hub.add(psk, 3, ep3, src3, EPOCH);

    const any = config.Cidr{ .network = 0, .prefix = 0 };
    fx.entries = .{
        .{ .src = any, .dst = try config.parseCidr("10.66.0.2/32"), .action = .forward, .target = 2 },
        .{ .src = any, .dst = try config.parseCidr("10.66.0.3/32"), .action = .forward, .target = 3 },
        .{ .src = any, .dst = try config.parseCidr("10.66.0.0/24"), .action = .forward, .target = 0 },
        .{ .src = any, .dst = try config.parseCidr("10.189.189.0/24"), .action = .forward, .target = 3 },
    };
}

/// Populate `reg` (local id 1) with `npeers` spoke peers — ids 2..npeers+1, each
/// with a distinct /32 `allowed_src` and UDP endpoint derived from its id — so the
/// ingress-select benchmark can measure how peer selection scales with the peer
/// count. Runs once at fixture-build time, so per-peer string formatting is fine.
fn buildWideRegistry(reg: *peer.PeerRegistry, psk: crypto.Key, npeers: usize) !void {
    reg.* = peer.PeerRegistry.init(1);
    var id: u32 = 2;
    while (id < 2 + npeers) : (id += 1) {
        var ebuf: [32]u8 = undefined;
        var cbuf: [32]u8 = undefined;
        const hi = (id >> 8) & 0xff;
        const lo = id & 0xff;
        const ep_str = try std.fmt.bufPrint(&ebuf, "10.66.{d}.{d}:51820", .{ hi, lo });
        const src_str = try std.fmt.bufPrint(&cbuf, "10.66.{d}.{d}/32", .{ hi, lo });
        _ = try reg.add(psk, id, try config.parseEndpoint(ep_str), try config.parseCidr(src_str), EPOCH);
    }
}

/// Mirror of the reactor's obfuscation-ON ingress FALLBACK selection (the
/// budget-metered full sweep inside `selectIngressPeer`, issue #174):
/// trial-de-obfuscate `wire` against every peer's rx link key, returning the first
/// whose keyed-Blake2b pad recovers a self-consistent header (de-masking `wire` IN
/// PLACE on the hit) or null if none claim it. This is the O(peers) keyed-hash
/// sweep the daemon runs per unknown-source datagram (up to `OBFS_SCAN_BUDGET`
/// times per drain) when header obfuscation is on.
fn selectTrial(reg: *peer.PeerRegistry, wire: []u8) ?*peer.Peer {
    var i: usize = 0;
    while (i < reg.len) : (i += 1) {
        const p = &reg.peers[i];
        if (reactor.tryDeobfuscate(p.rx.link_key, p.id, wire)) return p;
    }
    return null;
}

/// Fill `buf[0..len]` with a deterministic junk datagram that NO peer in `reg`
/// claims — the worst case for `selectTrial`, which must sweep every peer before
/// the datagram is silently dropped. A miss leaves `buf` untouched (tryDeobfuscate
/// only de-masks on a hit), so the bytes stay stable across bench iterations. No
/// PRNG: a counter is folded into the fill and retried until the sweep misses,
/// which it does on the first try for any header not forgeable without a link key.
fn craftJunkMiss(buf: []u8, len: usize, reg: *peer.PeerRegistry) void {
    var seed: usize = 0;
    while (true) : (seed += 1) {
        var i: usize = 0;
        while (i < len) : (i += 1) buf[i] = @intCast((i *% 131 +% seed) & 0xff);
        if (selectTrial(reg, buf[0..len]) == null) return;
    }
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = init.minimal.args;

    if (hasFlag(args, "--help") or hasFlag(args, "-h")) {
        writeOut(io, USAGE);
        return;
    }
    if (hasFlag(args, "--version") or hasFlag(args, "-V")) {
        var vbuf: [80]u8 = undefined;
        const v = std.fmt.bufPrint(&vbuf, "forward-bench (subnetra v{s})\n", .{build_options.version}) catch return;
        writeOut(io, v);
        return;
    }

    var size: usize = 1400;
    if (flagValue(args, "--size")) |raw| {
        size = std.fmt.parseInt(usize, raw, 10) catch {
            writeErr(io, "forward-bench: invalid --size value\n");
            return error.InvalidArgument;
        };
    }
    if (size < MIN_IP) size = MIN_IP;
    if (size > MAX_PLAINTEXT) size = MAX_PLAINTEXT;

    var iters: usize = 200_000;
    if (flagValue(args, "--iters")) |raw| {
        iters = std.fmt.parseInt(usize, raw, 10) catch {
            writeErr(io, "forward-bench: invalid --iters value\n");
            return error.InvalidArgument;
        };
        if (iters == 0) {
            writeErr(io, "forward-bench: --iters must be >= 1\n");
            return error.InvalidArgument;
        }
    }

    // Peers configured for the ingress-select sweep. Defaults to (and is capped
    // at) this build's MAX_PEERS; to sweep past it, rebuild with -Dmax-peers=N.
    var npeers: usize = config.MAX_PEERS;
    if (flagValue(args, "--peers")) |raw| {
        npeers = std.fmt.parseInt(usize, raw, 10) catch {
            writeErr(io, "forward-bench: invalid --peers value\n");
            return error.InvalidArgument;
        };
        if (npeers < 1) npeers = 1;
        if (npeers > config.MAX_PEERS) npeers = config.MAX_PEERS;
    }

    const psk: crypto.Key = [_]u8{0x42} ** crypto.KEY_LEN;
    var fx: Fixture = undefined;
    buildFixture(&fx, psk) catch {
        writeErr(io, "forward-bench: fixture construction FAILED — aborting\n");
        return error.FixtureFailed;
    };
    const hub = &fx.hub;
    const tree = fx.tree();
    var active = policy.ActiveTree.init(&tree);
    const p2 = hub.findById(2).?; // rx session: traffic from spoke 2 (link 2->1)
    const p3 = hub.findById(3).?; // tx session: egress to spoke 3 (link 1->3)

    // Inner IPv4 packet 10.66.0.2 -> 10.66.0.3 (routes to peer 3 via the /32).
    var inner: [MAX_PLAINTEXT]u8 = undefined;
    craftIpv4(inner[0..size], IP_SPOKE, IP_DEST);
    const pkt = inner[0..size];

    // Inbound datagram as crafted by spoke 2 (sender link 2->1, key_id 2). Its
    // rx link key/epoch match the hub's peer-2 rx session, so decodeIngress
    // authenticates it. Used for the rx pipeline and the open() floor.
    var s2_to_hub = crypto.TxSession.init(crypto.deriveLinkKey(psk, 2, 1), EPOCH);
    var dgram: [MAX_WIRE]u8 = undefined;
    const dlen = reactor.encodeEgress(&s2_to_hub, 2, pkt, &dgram);

    var out: [MAX_PLAINTEXT]u8 = undefined;
    var wire: [MAX_WIRE]u8 = undefined;
    var ct: [MAX_PLAINTEXT + TAG_LEN]u8 = undefined;

    // Self-check (adopts the rx epoch as a side effect): a wrong build can never
    // report a bogus rate. decodeIngress must recover the exact inner packet.
    {
        const kid = reactor.parseKeyId(dgram[0..dlen]) orelse {
            writeErr(io, "forward-bench: self-check parseKeyId FAILED\n");
            return error.SelfCheckFailed;
        };
        const sp = hub.findById(kid) orelse {
            writeErr(io, "forward-bench: self-check findById FAILED\n");
            return error.SelfCheckFailed;
        };
        const plen = reactor.decodeIngress(&sp.rx, dgram[0..dlen], &out) orelse {
            writeErr(io, "forward-bench: self-check decodeIngress FAILED\n");
            return error.SelfCheckFailed;
        };
        if (!std.mem.eql(u8, pkt, out[0..plen])) {
            writeErr(io, "forward-bench: self-check round-trip MISMATCH — aborting\n");
            return error.SelfCheckFailed;
        }
        const dst = reactor.ipv4Dst(out[0..plen]) orelse return error.SelfCheckFailed;
        const entry = active.load().match(dst) orelse return error.SelfCheckFailed;
        if (entry.target != 3) {
            writeErr(io, "forward-bench: self-check routing MISMATCH — aborting\n");
            return error.SelfCheckFailed;
        }
    }

    var hdr: [256]u8 = undefined;
    writeOut(io, std.fmt.bufPrint(&hdr, "forward-bench: arch={s} optimize={s} size={d}B iters={d} (ops/sec == packets/sec)\n", .{
        @tagName(builtin.cpu.arch), @tagName(builtin.mode), size, iters,
    }) catch "");

    // --- tx side: raw AEAD seal floor, then the full egress forwarding path ---
    const seal_ns = blk: {
        const t0 = nowNs(io);
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            const n = crypto.seal(p3.tx.skey, @intCast(i + 1), pkt, &ct);
            std.mem.doNotOptimizeAway(ct[n - 1]);
        }
        break :blk report(io, "seal floor (tx)", iters, size, nowNs(io) - t0);
    };
    const tx_ns = blk: {
        const t0 = nowNs(io);
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            const dst = reactor.ipv4Dst(pkt).?;
            const entry = active.load().match(dst).?;
            const dst_peer = hub.findById(entry.target).?;
            const n = reactor.encodeEgress(&dst_peer.tx, @intCast(hub.local_id), pkt, &wire);
            std.mem.doNotOptimizeAway(wire[n - 1]);
        }
        break :blk report(io, "tx-forward     ", iters, size, nowNs(io) - t0);
    };

    // --- rx side: raw AEAD open floor, then the full ingress relay path ---
    const ct_in = dgram[HEADER_LEN..dlen]; // sealed body; opens under p2.rx.skey @ seq 1
    const open_ns = blk: {
        const t0 = nowNs(io);
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            const m = crypto.open(p2.rx.skey, 1, ct_in, &out) catch unreachable;
            std.mem.doNotOptimizeAway(out[m - 1]);
        }
        break :blk report(io, "open floor (rx)", iters, size, nowNs(io) - t0);
    };
    const rx_ns = blk: {
        const t0 = nowNs(io);
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            // Re-arm only the anti-replay window so the same datagram re-decodes
            // each iteration; epoch/skey stay cached (steady state, no KDF).
            p2.rx.window = .{};
            const kid = reactor.parseKeyId(dgram[0..dlen]).?;
            const sp = hub.findById(kid).?;
            const plen = reactor.decodeIngress(&sp.rx, dgram[0..dlen], &out).?;
            const isrc = reactor.ipv4Src(out[0..plen]).?;
            std.mem.doNotOptimizeAway(sp.allowed_src.contains(isrc));
            const dst = reactor.ipv4Dst(out[0..plen]).?;
            const entry = active.load().match(dst).?;
            std.mem.doNotOptimizeAway(entry.target);
        }
        break :blk report(io, "rx-forward     ", iters, size, nowNs(io) - t0);
    };

    var sbuf: [256]u8 = undefined;
    writeOut(io, std.fmt.bufPrint(&sbuf, "  tx forwarding tax: {d:.1} ns/op over AEAD seal ({d:.1} -> {d:.1} ns/op)\n", .{
        tx_ns - seal_ns, seal_ns, tx_ns,
    }) catch "");
    writeOut(io, std.fmt.bufPrint(&sbuf, "  rx forwarding tax: {d:.1} ns/op over AEAD open ({d:.1} -> {d:.1} ns/op)\n", .{
        rx_ns - open_ns, open_ns, rx_ns,
    }) catch "");

    // --- ingress peer-selection: the header-obfuscation de-mux sweep ---
    // With obfuscation ON (default) the wire key_id is masked, so the reactor
    // cannot index a peer directly. Since issue #174 `selectIngressPeer` resolves
    // steady-state traffic with ONE keyed trial via the source-endpoint fast
    // path; only an unknown-source datagram falls back to trialing every
    // configured peer's rx link key, and at most `OBFS_SCAN_BUDGET` such sweeps
    // run per drain. This bench measures that fallback sweep's worst case: a
    // junk datagram NO peer claims pays the FULL N-peer keyed-Blake2b sweep (one
    // budget slot) before it is silently dropped. Measured against the cleartext
    // key_id selector (obfuscation off: a trivial integer scan of the same
    // registry) to isolate the per-peer de-mux tax.
    var wide: peer.PeerRegistry = undefined;
    buildWideRegistry(&wide, psk, npeers) catch {
        writeErr(io, "forward-bench: wide-registry construction FAILED — aborting\n");
        return error.FixtureFailed;
    };
    const last_id: u32 = @intCast(1 + npeers); // ids run 2..npeers+1; the last is trialed last
    const last = wide.findById(last_id).?;

    // A genuine inbound datagram from the LAST peer (link last->1), sealed then
    // header-masked exactly as that spoke's egress would (see reactor.stageEgress):
    // `clr` is the cleartext-header form the O(1) selector reads, `obf` the mask.
    var last_to_hub = crypto.TxSession.init(last.rx.link_key, EPOCH);
    var clr: [MAX_WIRE]u8 = undefined;
    const olen = reactor.encodeEgress(&last_to_hub, @intCast(last_id), pkt, &clr);
    var obf: [MAX_WIRE]u8 = undefined;
    @memcpy(obf[0..olen], clr[0..olen]);
    reactor.obfuscateHeader(last.rx.link_key, obf[0..olen]);

    // A deterministic junk datagram no peer's key recovers (worst-case full sweep).
    var junk: [MAX_WIRE]u8 = undefined;
    craftJunkMiss(&junk, olen, &wide);

    // Self-checks (fail closed): a wrong build can never report a bogus rate.
    {
        const kid = reactor.parseKeyId(clr[0..olen]) orelse {
            writeErr(io, "forward-bench: select self-check parseKeyId FAILED\n");
            return error.SelfCheckFailed;
        };
        if (@as(u32, kid) != last_id) {
            writeErr(io, "forward-bench: select self-check key_id MISMATCH — aborting\n");
            return error.SelfCheckFailed;
        }
        // The genuine masked datagram must select its sender via the trial sweep;
        // the hit de-masks `obf` in place (obf is consumed by this self-check).
        const hit = selectTrial(&wide, obf[0..olen]) orelse {
            writeErr(io, "forward-bench: select self-check genuine sweep MISSED — aborting\n");
            return error.SelfCheckFailed;
        };
        if (hit.id != last_id) {
            writeErr(io, "forward-bench: select self-check selected the wrong peer — aborting\n");
            return error.SelfCheckFailed;
        }
        // And the junk datagram must miss the entire sweep.
        if (selectTrial(&wide, junk[0..olen]) != null) {
            writeErr(io, "forward-bench: select self-check junk unexpectedly matched — aborting\n");
            return error.SelfCheckFailed;
        }
    }

    writeOut(io, std.fmt.bufPrint(&hdr, "ingress peer-selection (obfuscation de-mux): peers={d}\n", .{npeers}) catch "");
    const off_ns = blk: {
        const t0 = nowNs(io);
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            const kid = reactor.parseKeyId(clr[0..olen]).?;
            const sp = wide.findById(kid).?;
            std.mem.doNotOptimizeAway(sp.id);
        }
        break :blk report(io, "cleartext select  ", iters, olen, nowNs(io) - t0);
    };
    const junk_ns = blk: {
        const t0 = nowNs(io);
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            std.mem.doNotOptimizeAway(selectTrial(&wide, junk[0..olen]));
        }
        break :blk report(io, "obfusc. junk sweep", iters, olen, nowNs(io) - t0);
    };
    const per_peer = junk_ns / @as(f64, @floatFromInt(npeers));
    var xbuf: [384]u8 = undefined;
    writeOut(io, std.fmt.bufPrint(&xbuf, "  obfuscation de-mux tax: {d:.1} ns/op over cleartext select ({d:.1} -> {d:.1} ns/op across {d} peers, ~{d:.1} ns/peer of keyed Blake2b a junk datagram pays before silent drop)\n", .{
        junk_ns - off_ns, off_ns, junk_ns, npeers, per_peer,
    }) catch "");
}

/// Print "ops/sec, MB/sec, ns/op" for a measurement and return ns/op so the
/// caller can compute the forwarding tax over the AEAD floor.
fn report(io: std.Io, label: []const u8, iters: usize, size: usize, ns: i128) f64 {
    const ns_f: f64 = @floatFromInt(@max(ns, 1));
    const iters_f: f64 = @floatFromInt(iters);
    const ns_per_op = ns_f / iters_f;
    const ops_per_sec = iters_f * 1e9 / ns_f;
    const mb_per_sec = iters_f * @as(f64, @floatFromInt(size)) / (ns_f / 1e9) / 1e6;
    var buf: [192]u8 = undefined;
    writeOut(io, std.fmt.bufPrint(&buf, "  {s}: {d:.0} ops/sec, {d:.1} MB/sec, {d:.1} ns/op\n", .{
        label, ops_per_sec, mb_per_sec, ns_per_op,
    }) catch "");
    return ns_per_op;
}

fn hasFlag(args: std.process.Args, flag: []const u8) bool {
    var it = args.iterate();
    _ = it.skip(); // argv[0]
    while (it.next()) |a| {
        if (std.mem.eql(u8, a, flag)) return true;
    }
    return false;
}

fn flagValue(args: std.process.Args, flag: []const u8) ?[]const u8 {
    var it = args.iterate();
    _ = it.skip(); // argv[0]
    while (it.next()) |a| {
        if (std.mem.eql(u8, a, flag)) return it.next();
    }
    return null;
}

test "forward-bench fixture: tx encode -> rx decode round-trip recovers inner packet and routes" {
    const psk: crypto.Key = [_]u8{0x42} ** crypto.KEY_LEN;
    var fx: Fixture = undefined;
    try buildFixture(&fx, psk);
    const hub = &fx.hub;
    const tree = fx.tree();
    var active = policy.ActiveTree.init(&tree);

    var inner: [64]u8 = undefined;
    craftIpv4(&inner, IP_SPOKE, IP_DEST);

    // Spoke 2 crafts an inbound datagram (key_id 2, link 2->1).
    var s2 = crypto.TxSession.init(crypto.deriveLinkKey(psk, 2, 1), EPOCH);
    var dg: [reactor.MAX_WIRE]u8 = undefined;
    const dl = reactor.encodeEgress(&s2, 2, &inner, &dg);

    const kid = reactor.parseKeyId(dg[0..dl]).?;
    try std.testing.expectEqual(@as(u16, 2), kid);
    const sp = hub.findById(kid).?;
    var out: [reactor.MAX_PLAINTEXT]u8 = undefined;
    const pl = reactor.decodeIngress(&sp.rx, dg[0..dl], &out).?;
    try std.testing.expect(std.mem.eql(u8, &inner, out[0..pl]));

    // Inner source must be inside the peer's allowed prefix; dst routes to peer 3.
    const isrc = reactor.ipv4Src(out[0..pl]).?;
    try std.testing.expect(sp.allowed_src.contains(isrc));
    const dst = reactor.ipv4Dst(out[0..pl]).?;
    const entry = active.load().match(dst).?;
    try std.testing.expectEqual(@as(u32, 3), entry.target);
}

test "forward-bench craftIpv4 produces a parser-valid packet" {
    var buf: [40]u8 = undefined;
    craftIpv4(&buf, IP_SPOKE, IP_DEST);
    try std.testing.expectEqual(IP_SPOKE, reactor.ipv4Src(&buf).?);
    try std.testing.expectEqual(IP_DEST, reactor.ipv4Dst(&buf).?);
}

test "forward-bench wide registry: obfuscated datagram trial-selects its sender, junk misses the sweep" {
    const psk: crypto.Key = [_]u8{0x42} ** crypto.KEY_LEN;
    var reg: peer.PeerRegistry = undefined;
    try buildWideRegistry(&reg, psk, 8);
    const last_id: u32 = 9; // ids 2..9; the sender is trialed last (worst case)
    const last = reg.findById(last_id).?;

    var inner: [64]u8 = undefined;
    craftIpv4(&inner, IP_SPOKE, IP_DEST);

    // Genuine inbound datagram from the last peer (link last->1), then header-masked
    // exactly as that spoke's egress would (obfuscate with its tx == hub rx key).
    var tx = crypto.TxSession.init(last.rx.link_key, EPOCH);
    var wire: [reactor.MAX_WIRE]u8 = undefined;
    const wlen = reactor.encodeEgress(&tx, @intCast(last_id), &inner, &wire);
    reactor.obfuscateHeader(last.rx.link_key, wire[0..wlen]);

    // The trial sweep recovers the sender and de-masks the header in place.
    const hit = selectTrial(&reg, wire[0..wlen]).?;
    try std.testing.expectEqual(last_id, hit.id);

    // A junk datagram no key recovers must miss the entire sweep.
    var junk: [reactor.MAX_WIRE]u8 = undefined;
    craftJunkMiss(&junk, wlen, &reg);
    try std.testing.expect(selectTrial(&reg, junk[0..wlen]) == null);
}
