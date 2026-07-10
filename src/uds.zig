//! Task 7: Control-plane Unix domain socket.
//!
//! The daemon binds the control socket (AF_UNIX, SOCK_DGRAM; default
//! `/run/subnetra/subnetra.sock` on Linux, `/var/run/subnetra.sock` on macOS —
//! see `SOCKET_PATH`), receives
//! plaintext command datagrams from subnetra, tokenizes them, rebuilds the policy
//! tree, and injects it into the data plane via policy's atomic swap interface
//! (lock-free RCU).
//!
//! A datagram socket is used deliberately: each datagram is exactly one command
//! (one `recvfrom` == one message), so there is no stream framing, no partial
//! reads, and no per-connection fd to accept/track/leak. The control plane may
//! allocate; the data plane must not — so the policy tree is double-buffered in
//! fixed storage owned by `Control` and swapped wholesale, with no allocator.

const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const sys = @import("sys.zig");
const policy = @import("policy.zig");
const peer = @import("peer.zig");
const stats = @import("stats.zig");

/// Default control-socket path. Platform-aware so the compiled default matches
/// the shipped deployment on each OS without an env override:
///   - Linux: `/run/subnetra/subnetra.sock` — a per-service runtime subdir, the
///     systemd `RuntimeDirectory=subnetra` convention (see `deploy/subnetrad.service`).
///   - macOS: `/var/run/subnetra.sock` — `/run` does not exist on macOS, but
///     `/var/run` always does.
/// Both the daemon and the `subnetra` CLI read this same constant, so a manual
/// `subnetra ...` invocation (no `SUBNETRA_SOCK` set) targets the socket the
/// daemon actually bound. The daemon best-effort-creates the parent dir on bind.
pub const SOCKET_PATH = if (builtin.os.tag == .macos)
    "/var/run/subnetra.sock"
else
    "/run/subnetra/subnetra.sock";

/// Default snapshot file `save` serializes the live policy tree to (as replayable
/// `policy add` command lines). Deliberately NOT config.json: the config schema
/// carries no policy section in v1, so the operator-driven policy state is
/// persisted as a separate, replayable command snapshot instead of being merged
/// back into the daemon's startup config. Lives alongside the socket.
pub const SAVE_PATH = if (builtin.os.tag == .macos)
    "/var/run/subnetra.policy"
else
    "/run/subnetra/subnetra.policy";

/// Headroom for operator-added policy rules layered on top of the role-derived
/// table (one forward rule per spoke + route rules). 224 leaves ample room for
/// manual `policy add` rules; with the default `config.MAX_PEERS = 32` the table
/// is 32 + MAX_ROUTES*2 + 224 = 272 entries.
const POLICY_HEADROOM: usize = 224;

/// Upper bound on installed policy rules. Derived from `config.MAX_PEERS` so a
/// larger peer table can never overflow the hub's role-derived forwarding rules
/// (one per spoke) plus route rules, with `POLICY_HEADROOM` left for manual
/// rules. The control plane keeps two fixed buffers of this size (double-buffered
/// RCU), so memory is allocation-free and bounded.
pub const MAX_POLICY_ENTRIES = config.MAX_PEERS + config.MAX_ROUTES * 2 + POLICY_HEADROOM;

comptime {
    // A role=hub derives one forward rule per peer plus up to MAX_ROUTES*2 route
    // rules; the table must always hold at least that many or daemon startup
    // (policy bind) would fail.
    std.debug.assert(MAX_POLICY_ENTRIES >= config.MAX_PEERS + config.MAX_ROUTES * 2);
}

/// Per-tick datagram budget: `handle()` processes at most this many commands per
/// reactor wake-up so a local control flood cannot starve the data plane. The
/// control fd is level-triggered, so epoll re-notifies while datagrams remain.
const MAX_CMDS_PER_TICK = 64;

const RX_BUF = 4096;

/// Worst-case length of one serialized `policy add` line, e.g.
/// `policy add --src 255.255.255.255/32 --dst 255.255.255.255/32 --action forward --target 4294967295\n`.
const MAX_RULE_LINE = 112;

/// Size of the reply/snapshot buffer. Large enough to serialize a full policy
/// table (`MAX_POLICY_ENTRIES` rules) without ever truncating, so `policy show`
/// and `save` are always complete and the `save` ack count is always accurate.
pub const MAX_REPLY = MAX_POLICY_ENTRIES * MAX_RULE_LINE;

/// Stable schema version for `subnetra status --json` (issue #105). Bump on any
/// breaking change to the JSON shape (a removed/renamed key or a changed type) so
/// a monitor can pin the contract it parses.
pub const STATUS_SCHEMA_VERSION: u32 = 1;

/// Default freshness window for the per-peer `online` flag in the JSON status
/// (issue #105): a peer is `online` iff its last authenticated datagram is no
/// older than this. Sized to tolerate a few missed spoke->hub keepalives (default
/// 20s, issue #96) without flapping. Passed into `formatStatusJson` so a caller
/// may override it.
pub const STATUS_ONLINE_FRESHNESS_SECS: u64 = 90;

/// Header bytes of `sockaddr_un` preceding `path` (i.e. `@sizeOf(sa_family_t)`).
/// Used both as the bind addrlen for Linux abstract autobind and as the
/// threshold that distinguishes an addressable (bound) client from an anonymous
/// one in `recvfrom`'s returned source length.
const ADDR_HDR = @offsetOf(sys.sockaddr.un, "path");

pub const ControlError = error{
    Unsupported,
    SocketFailed,
    BindFailed,
    ChmodFailed,
    PathTooLong,
    TooManyEntries,
};

/// Errors surfaced to the subnetra client.
pub const ClientError = error{
    Unsupported,
    SocketFailed,
    BindFailed,
    PathTooLong,
    /// The daemon socket is absent or not listening (operator-facing: daemon down).
    DaemonUnavailable,
    SendFailed,
    /// The daemon accepted the request but sent no reply within the timeout.
    NoResponse,
};

pub const ParseError = error{
    UnknownCommand,
    MissingArgument,
    InvalidValue,
};

/// Control command.
pub const Command = union(enum) {
    policy_add: policy.PolicyEntry,
    policy_show,
    save,
    status,
    /// `subnetra status --json` — machine-readable status (issue #105).
    status_json,
};

fn nextValue(it: *std.mem.TokenIterator(u8, .scalar)) ParseError![]const u8 {
    return it.next() orelse ParseError.MissingArgument;
}

/// Tokenize a line of plaintext command into a Command.
/// e.g. `policy add --src 192.168.1.0/24 --dst 192.168.2.0/24 --action forward --target 3`
pub fn parseCommand(line: []const u8) ParseError!Command {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    const verb = it.next() orelse return ParseError.UnknownCommand;

    if (std.mem.eql(u8, verb, "save")) return .save;
    if (std.mem.eql(u8, verb, "status")) {
        // `status` is human text; `status --json` is the machine-readable form
        // (issue #105). Reject any other trailing token rather than silently
        // ignoring a typo'd flag.
        if (it.next()) |opt| {
            if (std.mem.eql(u8, opt, "--json")) return .status_json;
            return ParseError.UnknownCommand;
        }
        return .status;
    }

    if (!std.mem.eql(u8, verb, "policy")) return ParseError.UnknownCommand;

    const sub = it.next() orelse return ParseError.MissingArgument;
    if (std.mem.eql(u8, sub, "show")) return .policy_show;
    if (!std.mem.eql(u8, sub, "add")) return ParseError.UnknownCommand;

    var entry = policy.PolicyEntry{
        .src = undefined,
        .dst = undefined,
        .action = .drop,
    };
    var have_src = false;
    var have_dst = false;
    var have_target = false;

    while (it.next()) |flag| {
        if (std.mem.eql(u8, flag, "--src")) {
            entry.src = policy.parseCidr(try nextValue(&it)) catch return ParseError.InvalidValue;
            have_src = true;
        } else if (std.mem.eql(u8, flag, "--dst")) {
            entry.dst = policy.parseCidr(try nextValue(&it)) catch return ParseError.InvalidValue;
            have_dst = true;
        } else if (std.mem.eql(u8, flag, "--action")) {
            const v = try nextValue(&it);
            entry.action = if (std.mem.eql(u8, v, "forward"))
                .forward
            else if (std.mem.eql(u8, v, "drop"))
                .drop
            else
                return ParseError.InvalidValue;
        } else if (std.mem.eql(u8, flag, "--target")) {
            entry.target = std.fmt.parseInt(u32, try nextValue(&it), 10) catch return ParseError.InvalidValue;
            have_target = true;
        } else {
            return ParseError.UnknownCommand;
        }
    }

    if (!have_src or !have_dst) return ParseError.MissingArgument;
    // `--target` is required for `forward` (docs/CONTROL-PROTOCOL.md §3.1).
    // Without this check a missing target would default to 0 == LOCAL_TARGET
    // and silently install a local-delivery rule instead of a forward rule.
    if (entry.action == .forward and !have_target) return ParseError.MissingArgument;
    return .{ .policy_add = entry };
}

/// Fill a filesystem `sockaddr_un` from `path`, returning the address and the
/// exact addrlen (`offsetof(path) + len + NUL`). Errors if the path cannot fit.
fn fillUnixAddr(path: []const u8) ControlError!struct { addr: sys.sockaddr.un, alen: sys.socklen_t } {
    if (path.len + 1 > 108) return error.PathTooLong; // sockaddr_un.path is 108 bytes incl. NUL
    var addr = sys.sockaddr.un{ .path = undefined };
    @memset(&addr.path, 0);
    @memcpy(addr.path[0..path.len], path);
    addr.path[path.len] = 0;
    const alen: sys.socklen_t = @intCast(ADDR_HDR + path.len + 1);
    return .{ .addr = addr, .alen = alen };
}

/// Open a non-blocking AF_UNIX datagram socket bound to `path`. A stale socket
/// file at `path` is unlinked first (filesystem sockets only). On any failure
/// after the socket is created, the fd is closed (no leak).
fn openDgramSocket(path: []const u8) ControlError!sys.fd_t {
    const a = try fillUnixAddr(path);

    const fd = sys.socket(sys.AF.UNIX, sys.SOCK.DGRAM, 0, true, true) catch return error.SocketFailed;
    errdefer _ = sys.close(fd);

    // Best-effort: create the parent runtime dir (e.g. /run/subnetra) so the
    // compiled default path works even when no init system pre-created it (a
    // manual `sudo subnetrad` run, or OpenWrt). One level only — /run already
    // exists on Linux. Under systemd the dir is already present via
    // `RuntimeDirectory=subnetra` (EEXIST is fine). macOS uses a flat
    // /var/run/subnetra.sock, whose parent always exists, so skip it there.
    if (builtin.os.tag == .linux) {
        if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| {
            var dir_buf: [108]u8 = undefined;
            if (slash > 0 and slash < dir_buf.len) {
                @memcpy(dir_buf[0..slash], path[0..slash]);
                dir_buf[slash] = 0;
                sys.mkdir(@ptrCast(&dir_buf), 0o755);
            }
        }
    }

    // Best-effort removal of a stale socket from a previous run.
    _ = sys.unlink(@ptrCast(&a.addr.path));

    // Create the node already owner-only: a permissive inherited umask must not
    // leave a window where a local user can enqueue a control datagram before
    // the fchmod below tightens it. umask is process-global, but this runs in the
    // single-threaded setup phase, so the scoped save/restore is safe.
    const prev_umask = sys.umask(0o177);
    const brc = sys.bind(fd, @ptrCast(&a.addr), a.alen);
    _ = sys.umask(prev_umask);
    if (sys.errno(brc) != .SUCCESS) return error.BindFailed;

    // Defense in depth: pin the mode to 0600 explicitly on the bound fd
    // (path-TOCTOU-free), independent of umask. The control plane mutates routing
    // policy and exposes peer state, so it must never be group/world reachable.
    // Linux: fchmod the bound fd (TOCTOU-free). macOS ignores umask for AF_UNIX
    // bind *and* rejects fchmod() on a socket fd, leaving the node 0666, so the
    // path is tightened to 0600 right after bind (sub-µs window, and in
    // production the socket lives in a root-owned 0700 runtime dir).
    if (builtin.os.tag == .linux) {
        if (sys.errno(sys.fchmod(fd, 0o600)) != .SUCCESS) return error.ChmodFailed;
    } else {
        if (sys.errno(sys.chmod(@ptrCast(&a.addr.path), 0o600)) != .SUCCESS) return error.ChmodFailed;
    }

    return fd;
}

// --- subnetra client -----------------------------------------------------------

/// Fire-and-forget delivery of one command line to the daemon socket at `path`.
/// Used for `policy add`, which expects no reply. A missing/closed socket maps
/// to `DaemonUnavailable` so the operator sees a clear "daemon down" signal.
pub fn send(path: []const u8, line: []const u8) ClientError!void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const a = fillUnixAddr(path) catch |e| return switch (e) {
        error.PathTooLong => error.PathTooLong,
        else => error.SocketFailed,
    };

    const fd = sys.socket(sys.AF.UNIX, sys.SOCK.DGRAM, 0, false, true) catch return error.SocketFailed;
    defer _ = sys.close(fd);

    const rc = sys.sendto(fd, line.ptr, line.len, 0, @ptrCast(&a.addr), a.alen);
    return switch (sys.errno(rc)) {
        .SUCCESS => {},
        .NOENT, .CONNREFUSED, .CONNRESET => error.DaemonUnavailable,
        else => error.SendFailed,
    };
}

/// Send one command and wait up to `timeout_ms` for the daemon's reply,
/// returning the reply bytes written into `out`. Used for `policy show` / `save`.
///
/// The client socket is given a unique source address via Linux abstract
/// autobind (`bind` with only the family set, addrlen == `ADDR_HDR`), so the
/// daemon's `recvfrom` captures a routable return address and `sendto`s the
/// reply back to exactly this socket. A timeout (no datagram) maps to
/// `NoResponse`.
pub fn request(path: []const u8, line: []const u8, out: []u8, timeout_ms: i32) ClientError![]u8 {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const a = fillUnixAddr(path) catch |e| return switch (e) {
        error.PathTooLong => error.PathTooLong,
        else => error.SocketFailed,
    };

    const fd = sys.socket(sys.AF.UNIX, sys.SOCK.DGRAM, 0, true, true) catch return error.SocketFailed;
    defer _ = sys.close(fd);

    // Abstract autobind: a zero-length path with addrlen == family size makes the
    // kernel assign a unique anonymous address so the daemon can reply to us.
    var bind_addr = sys.sockaddr.un{ .path = undefined };
    bind_addr.family = sys.AF.UNIX;
    const brc = sys.bind(fd, @ptrCast(&bind_addr), ADDR_HDR);
    if (sys.errno(brc) != .SUCCESS) return error.BindFailed;

    const wrc = sys.sendto(fd, line.ptr, line.len, 0, @ptrCast(&a.addr), a.alen);
    switch (sys.errno(wrc)) {
        .SUCCESS => {},
        .NOENT, .CONNREFUSED, .CONNRESET => return error.DaemonUnavailable,
        else => return error.SendFailed,
    }

    // Bounded wait: track an absolute monotonic deadline so EINTR retries cannot
    // extend the timeout, and require POLLIN (an ERR/HUP/NVAL-only wake is not a
    // reply). The socket is non-blocking, so recvfrom never stalls past poll.
    const deadline = monotonicMillis() +| timeout_ms;
    var pfd = sys.pollfd{ .fd = fd, .events = sys.POLL.IN, .revents = 0 };
    while (true) {
        const remaining = deadline -| monotonicMillis();
        const prc = sys.poll(@ptrCast(&pfd), 1, @intCast(remaining));
        switch (sys.errno(prc)) {
            .SUCCESS => {},
            .INTR => {
                if (monotonicMillis() >= deadline) return error.NoResponse;
                continue;
            },
            else => return error.NoResponse,
        }
        if (prc == 0) return error.NoResponse; // timed out
        if (pfd.revents & sys.POLL.IN == 0) return error.NoResponse; // ERR/HUP/NVAL: no reply
        break;
    }

    const rrc = sys.recvfrom(fd, out.ptr, out.len, 0, null, null);
    if (sys.errno(rrc) != .SUCCESS) return error.NoResponse;
    return out[0..@intCast(rrc)];
}

/// Monotonic clock in milliseconds; saturates to 0 on the (practically
/// impossible) clock_gettime failure so callers still make forward progress.
fn monotonicMillis() i64 {
    var ts: sys.timespec = undefined;
    if (sys.errno(sys.clock_gettime(sys.CLOCK.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

// --- policy serialization (control-plane reply / snapshot) ------------------

/// Format a host-order CIDR as `a.b.c.d/prefix` into `buf`.
fn formatCidr(c: policy.Cidr, buf: []u8) []const u8 {
    const n = c.network;
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}/{d}", .{
        (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff, c.prefix,
    }) catch buf[0..0];
}

/// Format one policy entry as a replayable `policy add ...` command line
/// (newline-terminated) into `buf`.
fn formatEntry(e: policy.PolicyEntry, buf: []u8) []const u8 {
    var sb: [20]u8 = undefined;
    var db: [20]u8 = undefined;
    const s = formatCidr(e.src, &sb);
    const d = formatCidr(e.dst, &db);
    return switch (e.action) {
        .forward => std.fmt.bufPrint(buf, "policy add --src {s} --dst {s} --action forward --target {d}\n", .{ s, d, e.target }) catch buf[0..0],
        .drop => std.fmt.bufPrint(buf, "policy add --src {s} --dst {s} --action drop\n", .{ s, d }) catch buf[0..0],
    };
}


/// Static daemon identity surfaced by `subnetra status`. Passed in from `main` so
/// the control plane never imports `build_options` or other executable-context
/// modules (keeps `uds` unit-testable and reusable).
pub const DaemonMeta = struct {
    version: []const u8 = "?",
    mode: []const u8 = "?",
    listen_port: u16 = 0,
    tun_name: []const u8 = "?",
    local_id: u32 = 0,
};

/// Render a human-readable status report into `out` from the daemon meta, the
/// peer registry, and the data-plane counters. Pure formatting (no I/O) so it is
/// unit-testable. Sensitive material (PSKs, derived keys) is NEVER printed.
pub fn formatStatus(
    out: []u8,
    meta: DaemonMeta,
    registry: *const peer.PeerRegistry,
    counters: *const stats.Counters,
) []const u8 {
    var len: usize = 0;
    const W = struct {
        fn p(buf: []u8, off: *usize, comptime fmt: []const u8, args: anytype) void {
            const s = std.fmt.bufPrint(buf[off.*..], fmt, args) catch return;
            off.* += s.len;
        }
    };

    W.p(out, &len, "subnetra v{s} [running]\n", .{meta.version});
    W.p(out, &len, "mode={s} local_id={d} udp_port={d} tun={s} peers={d}\n", .{
        meta.mode, meta.local_id, meta.listen_port, meta.tun_name, registry.len,
    });

    W.p(out, &len, "peers:\n", .{});
    var i: usize = 0;
    while (i < registry.len) : (i += 1) {
        const pr = &registry.peers[i];
        const a: u32 = std.mem.bigToNative(u32, pr.endpoint.addr);
        const port: u16 = std.mem.bigToNative(u16, pr.endpoint.port);
        const src: u32 = pr.allowed_src.network;
        const nm = pr.nameSlice();
        W.p(out, &len, "  id={d}", .{pr.id});
        // Optional human-readable label (observability only); absent → id only.
        if (nm.len != 0) W.p(out, &len, " name={s}", .{nm});
        W.p(out, &len, " endpoint={d}.{d}.{d}.{d}:{d} allowed_src={d}.{d}.{d}.{d}/{d} last_seen_wall_ns={d}\n", .{
            (a >> 24) & 0xff,   (a >> 16) & 0xff,   (a >> 8) & 0xff,   a & 0xff,   port,
            (src >> 24) & 0xff, (src >> 16) & 0xff, (src >> 8) & 0xff, src & 0xff, pr.allowed_src.prefix,
            pr.last_seen_wall_ns,
        });
    }

    const c = counters;
    W.p(out, &len, "traffic:\n", .{});
    W.p(out, &len, "  tun_rx packets={d} bytes={d}\n", .{ c.tun_rx_packets, c.tun_rx_bytes });
    W.p(out, &len, "  udp_tx packets={d} bytes={d}\n", .{ c.udp_tx_packets, c.udp_tx_bytes });
    W.p(out, &len, "  udp_rx packets={d} bytes={d}\n", .{ c.udp_rx_packets, c.udp_rx_bytes });
    W.p(out, &len, "  tun_tx packets={d} bytes={d}\n", .{ c.tun_tx_packets, c.tun_tx_bytes });
    W.p(out, &len, "  relay  packets={d} bytes={d}\n", .{ c.relay_packets, c.relay_bytes });
    W.p(out, &len, "  endpoint_learned={d}\n", .{c.udp_endpoint_learned});
    W.p(out, &len, "  keepalive rx={d} tx={d}\n", .{ c.keepalive_rx, c.keepalive_tx });
    W.p(out, &len, "drops:\n", .{});
    W.p(out, &len, "  tun: not_ipv4={d} no_route={d} drop_rule={d} local_loop={d} unknown_target={d} oversized={d} egress_err={d} send_err={d}\n", .{
        c.drop_tun_not_ipv4,      c.drop_tun_no_route,  c.drop_tun_drop_rule, c.drop_tun_local_loop,
        c.drop_tun_unknown_target, c.drop_tun_oversized, c.drop_tun_egress_err, c.drop_tun_send_err,
    });
    W.p(out, &len, "  udp: unknown_peer={d} auth_or_invalid={d} not_ipv4={d} spoof={d} no_route={d} drop_rule={d} unknown_target={d} no_reflect={d} oversized={d} send_err={d}\n", .{
        c.drop_udp_unknown_peer, c.drop_udp_auth_or_invalid, c.drop_udp_not_ipv4,       c.drop_udp_spoof,
        c.drop_udp_no_route,     c.drop_udp_drop_rule,       c.drop_udp_unknown_target, c.drop_udp_no_reflect,
        c.drop_udp_oversized,    c.drop_udp_send_err,
    });

    return out[0..len];
}

/// Wall-clock nanoseconds (REALTIME) used to derive the JSON status
/// `last_seen_age_seconds` (issue #105). Mirrors the data plane's `wallNs`:
/// observability only, never drives protocol logic; 0 on a non-Linux host (unit
/// tests) or a clock failure.
fn wallNowNs() u64 {
    if (builtin.os.tag != .linux) return 0;
    var ts: sys.timespec = undefined;
    if (sys.errno(sys.clock_gettime(sys.CLOCK.REALTIME, &ts)) != .SUCCESS) return 0;
    if (ts.sec < 0) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Render a machine-readable JSON status report into `out` (issue #105): the same
/// daemon meta, per-peer registry, and counters as `formatStatus`, plus a derived
/// per-peer `last_seen_age_seconds` and `online` flag (this folds in the #6
/// last-seen/heartbeat presentation ask). Pure formatting — no I/O and no clock
/// read — so it is unit-testable: the caller passes `now_wall_ns` and the
/// `freshness_secs` online threshold. Sensitive material (PSKs, derived keys) is
/// NEVER serialized. The counters object is emitted by reflecting over
/// `stats.Counters`, so it can never silently drift from the live field set.
pub fn formatStatusJson(
    out: []u8,
    meta: DaemonMeta,
    registry: *const peer.PeerRegistry,
    counters: *const stats.Counters,
    now_wall_ns: u64,
    freshness_secs: u64,
) []const u8 {
    var len: usize = 0;
    const W = struct {
        fn p(buf: []u8, off: *usize, comptime fmt: []const u8, args: anytype) void {
            const s = std.fmt.bufPrint(buf[off.*..], fmt, args) catch return;
            off.* += s.len;
        }
        /// Append `s` as a JSON string body, escaping `"` and `\`. The peer name
        /// is validated to printable ASCII at parse, so no control-char escapes
        /// are needed; this only guards the two structural JSON metacharacters.
        fn jstr(buf: []u8, off: *usize, s: []const u8) void {
            for (s) |ch| {
                if (ch == '"' or ch == '\\') {
                    if (off.* + 2 > buf.len) return;
                    buf[off.*] = '\\';
                    buf[off.* + 1] = ch;
                    off.* += 2;
                } else {
                    if (off.* + 1 > buf.len) return;
                    buf[off.*] = ch;
                    off.* += 1;
                }
            }
        }
    };

    W.p(out, &len, "{{\"schema_version\":{d},\"version\":\"{s}\",\"mode\":\"{s}\",\"local_id\":{d},\"listen_port\":{d},\"tun\":\"{s}\",\"peers\":[", .{
        STATUS_SCHEMA_VERSION, meta.version, meta.mode, meta.local_id, meta.listen_port, meta.tun_name,
    });

    var i: usize = 0;
    while (i < registry.len) : (i += 1) {
        const pr = &registry.peers[i];
        const a: u32 = std.mem.bigToNative(u32, pr.endpoint.addr);
        const port: u16 = std.mem.bigToNative(u16, pr.endpoint.port);
        const src: u32 = pr.allowed_src.network;

        // last_seen_wall_ns == 0 means the peer has never been authenticated, so
        // age is undefined (emitted as JSON null) and the peer is offline. A clock
        // that ran backwards (now < last_seen) clamps the age to 0 rather than
        // wrapping the unsigned subtraction.
        const seen = pr.last_seen_wall_ns != 0;
        const delta_ns: u64 = if (seen and now_wall_ns > pr.last_seen_wall_ns)
            now_wall_ns - pr.last_seen_wall_ns
        else
            0;
        const age_secs: u64 = delta_ns / std.time.ns_per_s;
        const online = seen and age_secs <= freshness_secs;

        if (i != 0) W.p(out, &len, ",", .{});
        W.p(out, &len, "{{\"id\":{d},\"name\":\"", .{pr.id});
        // Optional human-readable label (observability only); empty string when
        // unset. JSON-escaped so a name can never break the document shape.
        W.jstr(out, &len, pr.nameSlice());
        W.p(out, &len, "\",\"endpoint\":\"{d}.{d}.{d}.{d}:{d}\",\"allowed_src\":\"{d}.{d}.{d}.{d}/{d}\",\"last_seen_wall_ns\":{d},\"last_seen_age_seconds\":", .{
            (a >> 24) & 0xff,   (a >> 16) & 0xff,   (a >> 8) & 0xff,   a & 0xff,   port,
            (src >> 24) & 0xff, (src >> 16) & 0xff, (src >> 8) & 0xff, src & 0xff, pr.allowed_src.prefix,
            pr.last_seen_wall_ns,
        });
        if (seen) {
            W.p(out, &len, "{d}", .{age_secs});
        } else {
            W.p(out, &len, "null", .{});
        }
        W.p(out, &len, ",\"online\":{s}}}", .{if (online) "true" else "false"});
    }

    W.p(out, &len, "],\"counters\":{{", .{});
    inline for (std.meta.fields(stats.Counters), 0..) |f, idx| {
        if (idx != 0) W.p(out, &len, ",", .{});
        W.p(out, &len, "\"{s}\":{d}", .{ f.name, @field(counters.*, f.name) });
    }
    W.p(out, &len, "}}}}", .{});

    return out[0..len];
}
///
/// LIFETIME: `Control` must be pinned at a stable address for the daemon's
/// lifetime. `trees[i].entries` alias into `self.bufs[i]`, and the data plane's
/// `ActiveTree` is pointed at `&self.trees[cur]`; copying or moving a Control
/// after `bindInPlace` would dangle those slices. Construct as `var c: Control =
/// undefined; try c.bindInPlace(...)` and never move it.
///
/// HOT-SWAP: a policy update is built in the non-current buffer and installed
/// with a single atomic `ActiveTree.swap`. Because the reactor is strictly
/// single-threaded — data pumps and `handle()` never run concurrently — no
/// reader can retain the old tree across a control tick, so the previous buffer
/// is always safe to overwrite on the next update. No allocator, no deferred
/// reclamation list.
pub const Control = struct {
    fd: sys.fd_t = -1,
    active: *policy.ActiveTree = undefined,
    /// Double-buffered policy storage; only the non-current buffer is ever
    /// written, so the data plane never observes a half-built tree.
    bufs: [2][MAX_POLICY_ENTRIES]policy.PolicyEntry = undefined,
    trees: [2]policy.PolicyTree = undefined,
    cur: usize = 0,
    count: usize = 0,
    rxbuf: [RX_BUF]u8 = undefined,
    /// Reply/snapshot scratch (control plane only): `policy show` dumps here and
    /// `save` serializes here before the atomic file write. Sized to hold a full
    /// policy table so output is never silently truncated.
    txbuf: [MAX_REPLY]u8 = undefined,
    /// Filesystem path `save` persists the snapshot to (copied in at bind time).
    save_path_buf: [108]u8 = undefined,
    save_path_len: usize = 0,
    /// Optional status sources (issue #24), wired by `bindStatus`. When any is
    /// unset, `status` replies "status unavailable" rather than dereferencing a
    /// null — so a `Control` built without status wiring (e.g. in unit tests)
    /// stays safe.
    status_meta: ?DaemonMeta = null,
    status_registry: ?*const peer.PeerRegistry = null,
    status_counters: ?*const stats.Counters = null,

    /// Bind the control socket and install `initial` as the starting policy
    /// tree (swapped into `active`). `save_path` is the file `save` snapshots to.
    /// See the struct-level LIFETIME note: `self` must not be moved after this
    /// returns.
    pub fn bindInPlace(
        self: *Control,
        path: []const u8,
        save_path: []const u8,
        active: *policy.ActiveTree,
        initial: []const policy.PolicyEntry,
    ) ControlError!void {
        if (initial.len > MAX_POLICY_ENTRIES) return error.TooManyEntries;
        if (save_path.len > self.save_path_buf.len) return error.PathTooLong; // 108-byte sockaddr_un budget

        // Bind the socket first: if it fails we must not have published `active`
        // into this (now-discarded) Control's storage.
        self.fd = try openDgramSocket(path);

        @memcpy(self.save_path_buf[0..save_path.len], save_path);
        self.save_path_len = save_path.len;

        self.cur = 0;
        self.count = initial.len;
        @memcpy(self.bufs[0][0..initial.len], initial);
        self.trees[0] = .{ .entries = self.bufs[0][0..initial.len] };
        self.active = active;
        _ = active.swap(&self.trees[0]);

        // `Control` is constructed via `= undefined`, so field defaults do NOT
        // apply. Explicitly clear the optional status sources; `bindStatus`
        // wires them later. Without this they hold garbage and the unbound
        // `status` path treats them as non-null and dereferences junk.
        self.status_meta = null;
        self.status_registry = null;
        self.status_counters = null;
    }

    /// Wire the optional status sources for `subnetra status` (issue #24). Call
    /// after `bindInPlace`. The pointers must outlive the Control (they live in
    /// `main`'s frame alongside it).
    pub fn bindStatus(
        self: *Control,
        meta: DaemonMeta,
        registry: *const peer.PeerRegistry,
        counters: *const stats.Counters,
    ) void {
        self.status_meta = meta;
        self.status_registry = registry;
        self.status_counters = counters;
    }

    pub fn deinit(self: *Control) void {
        if (self.fd >= 0) {
            _ = sys.close(self.fd);
            self.fd = -1;
        }
    }

    /// Append one rule and atomically publish the new tree (double-buffered RCU).
    fn applyAdd(self: *Control, entry: policy.PolicyEntry) ControlError!void {
        if (self.count >= MAX_POLICY_ENTRIES) return error.TooManyEntries;
        const next: usize = 1 - self.cur;
        @memcpy(self.bufs[next][0..self.count], self.bufs[self.cur][0..self.count]);
        self.bufs[next][self.count] = entry;
        const new_count = self.count + 1;
        self.trees[next] = .{ .entries = self.bufs[next][0..new_count] };
        _ = self.active.swap(&self.trees[next]);
        self.cur = next;
        self.count = new_count;
    }

    /// Serialize the live policy tree into `txbuf` as replayable `policy add`
    /// lines. Stops at a line boundary if `txbuf` would overflow (never emits a
    /// partial line); an empty tree yields a single comment line.
    fn dumpRules(self: *Control) []const u8 {
        var len: usize = 0;
        for (self.bufs[self.cur][0..self.count]) |e| {
            var line: [128]u8 = undefined;
            const s = formatEntry(e, &line);
            if (len + s.len > self.txbuf.len) break; // bounded: drop the overflow tail
            @memcpy(self.txbuf[len..][0..s.len], s);
            len += s.len;
        }
        if (len == 0) {
            const empty = "# no policy rules\n";
            @memcpy(self.txbuf[0..empty.len], empty);
            return self.txbuf[0..empty.len];
        }
        return self.txbuf[0..len];
    }

    /// Atomically write `data` to the snapshot path via a sibling temp file +
    /// fsync + rename. Returns false on any syscall failure or short write (the
    /// old snapshot, if any, is left intact). On success the snapshot is durable:
    /// the temp file is fsync'd before rename so a crash cannot leave a truncated
    /// snapshot under the final name.
    fn writeSnapshot(self: *Control, data: []const u8) bool {
        const sp = self.save_path_buf[0..self.save_path_len];
        var finalz: [113]u8 = undefined;
        var tmpz: [113]u8 = undefined;
        @memcpy(finalz[0..sp.len], sp);
        finalz[sp.len] = 0;
        @memcpy(tmpz[0..sp.len], sp);
        @memcpy(tmpz[sp.len..][0..4], ".tmp");
        tmpz[sp.len + 4] = 0;

        const wfd = sys.openZ(@ptrCast(&tmpz), .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o600) catch return false;

        var off: usize = 0;
        while (off < data.len) {
            const rc = sys.write(wfd, data[off..].ptr, data.len - off);
            const e = sys.errno(rc);
            if (e == .INTR) continue;
            // A short write (rc == 0) before completion is a failure, not EOF:
            // never publish a partial snapshot.
            if (e != .SUCCESS or rc == 0) {
                _ = sys.close(wfd);
                _ = sys.unlink(@ptrCast(&tmpz));
                return false;
            }
            off += @intCast(rc);
        }

        // Durability: flush file contents before the rename publishes the name.
        if (sys.errno(sys.fsync(wfd)) != .SUCCESS) {
            _ = sys.close(wfd);
            _ = sys.unlink(@ptrCast(&tmpz));
            return false;
        }
        if (sys.errno(sys.close(wfd)) != .SUCCESS) {
            _ = sys.unlink(@ptrCast(&tmpz));
            return false;
        }

        if (sys.errno(sys.rename(@ptrCast(&tmpz), @ptrCast(&finalz))) != .SUCCESS) {
            _ = sys.unlink(@ptrCast(&tmpz));
            return false;
        }
        return true;
    }

    /// Best-effort reply to an addressable client. Non-blocking; a full client
    /// buffer or vanished client just drops the reply (never stalls the loop).
    fn reply(self: *Control, src: *const sys.sockaddr.un, slen: sys.socklen_t, msg: []const u8) void {
        _ = sys.sendto(self.fd, msg.ptr, msg.len, sys.MSG.DONTWAIT, @ptrCast(src), slen);
    }

    /// Apply one command line; reply to `src` for query/persist commands when the
    /// client is addressable (bound source). `policy add` never replies.
    fn applyLine(self: *Control, line: []const u8, src: *const sys.sockaddr.un, slen: sys.socklen_t) void {
        const cmd = parseCommand(line) catch return;
        const addressable = slen > ADDR_HDR;
        switch (cmd) {
            .policy_add => |e| self.applyAdd(e) catch return,
            .policy_show => {
                const dump = self.dumpRules();
                if (addressable) self.reply(src, slen, dump);
            },
            .save => {
                const dump = self.dumpRules();
                const ok = self.writeSnapshot(dump);
                if (addressable) {
                    var ack: [160]u8 = undefined;
                    const msg = if (ok)
                        std.fmt.bufPrint(&ack, "saved {d} rule(s) to {s}\n", .{ self.count, self.save_path_buf[0..self.save_path_len] }) catch "saved\n"
                    else
                        "save failed\n";
                    self.reply(src, slen, msg);
                }
            },
            .status => {
                if (!addressable) return;
                const msg = if (self.status_meta != null and self.status_registry != null and self.status_counters != null)
                    formatStatus(&self.txbuf, self.status_meta.?, self.status_registry.?, self.status_counters.?)
                else
                    "status unavailable\n";
                self.reply(src, slen, msg);
            },
            .status_json => {
                if (!addressable) return;
                const msg = if (self.status_meta != null and self.status_registry != null and self.status_counters != null)
                    formatStatusJson(&self.txbuf, self.status_meta.?, self.status_registry.?, self.status_counters.?, wallNowNs(), STATUS_ONLINE_FRESHNESS_SECS)
                else
                    "{\"error\":\"status unavailable\"}\n";
                self.reply(src, slen, msg);
            },
        }
    }

    /// Drain pending control datagrams; call when the control fd is readable.
    /// Each datagram is one or more newline-separated command lines. Bounds the
    /// work per call (the loop counter also caps EINTR retries, so a signal storm
    /// cannot livelock). Oversized datagrams are dropped whole via MSG_TRUNC so a
    /// truncated stream can never apply a valid-looking prefix. `policy show` /
    /// `save` reply to the datagram's source via the same socket.
    pub fn handle(self: *Control) void {
        var iters: usize = 0;
        while (iters < MAX_CMDS_PER_TICK) : (iters += 1) {
            var src: sys.sockaddr.un = undefined;
            var slen: sys.socklen_t = @sizeOf(sys.sockaddr.un);
            const rc = sys.recvfrom(self.fd, &self.rxbuf, self.rxbuf.len, sys.MSG.TRUNC, @ptrCast(&src), &slen);
            const e = sys.errno(rc);
            if (e == .INTR) continue; // counter-bounded retry
            if (e == .AGAIN) return; // no more datagrams queued
            if (e != .SUCCESS) return; // transient error: yield this round
            if (rc == 0) continue;
            if (rc > self.rxbuf.len) continue; // MSG_TRUNC: oversized datagram -> drop whole
            const datagram = self.rxbuf[0..@intCast(rc)];
            var it = std.mem.splitScalar(u8, datagram, '\n');
            while (it.next()) |raw| {
                const line = std.mem.trim(u8, raw, " \t\r");
                if (line.len == 0) continue;
                self.applyLine(line, &src, slen);
            }
        }
    }
};

test "parseCommand: policy add" {
    const cmd = try parseCommand("policy add --src 192.168.1.0/24 --dst 192.168.2.0/24 --action forward --target 3");
    const e = cmd.policy_add;
    try std.testing.expectEqual(@as(u32, 0xC0A8_0200), e.dst.network);
    try std.testing.expectEqual(policy.Action.forward, e.action);
    try std.testing.expectEqual(@as(u32, 3), e.target);
}

test "parseCommand: show / save / status / errors" {
    try std.testing.expect(try parseCommand("policy show") == .policy_show);
    try std.testing.expect(try parseCommand("save") == .save);
    try std.testing.expect(try parseCommand("status") == .status);
    try std.testing.expect(try parseCommand("status --json") == .status_json);
    try std.testing.expectError(ParseError.UnknownCommand, parseCommand("status --bogus"));
    try std.testing.expectError(ParseError.UnknownCommand, parseCommand("bogus"));
    try std.testing.expectError(ParseError.MissingArgument, parseCommand("policy add --src 10.0.0.0/24"));
    // `--target` is required for forward (docs/CONTROL-PROTOCOL.md §3.1); a
    // missing target must not silently become target=0 (local delivery).
    try std.testing.expectError(ParseError.MissingArgument, parseCommand("policy add --src 10.0.0.0/24 --dst 10.0.1.0/24 --action forward"));
    // `drop` does not need a target.
    try std.testing.expect(try parseCommand("policy add --src 10.0.0.0/24 --dst 10.0.1.0/24 --action drop") == .policy_add);
}

test "formatStatus: renders meta, peers, and counters; never prints secrets" {
    var reg = peer.PeerRegistry.init(1);
    const psk: @import("crypto.zig").Key = [_]u8{0xAB} ** 32;
    const ep = try @import("config.zig").parseEndpoint("203.0.113.7:51820");
    _ = try reg.add(psk, 2, ep, try @import("config.zig").parseCidr("10.0.0.2/32"), 1_700_000_000_000_000_000);
    // A second, NAMED peer: the human line gains `name=<...>` (observability only).
    const psk2: @import("crypto.zig").Key = [_]u8{0xCD} ** 32;
    const ep2 = try @import("config.zig").parseEndpoint("203.0.113.9:51820");
    const np = try reg.add(psk2, 5, ep2, try @import("config.zig").parseCidr("10.0.0.5/32"), 1_700_000_000_000_000_000);
    np.name_len = try @import("config.zig").parsePeerName(&np.name, "core-hub");

    var c = stats.Counters{};
    c.tun_rx_packets = 5;
    c.udp_tx_bytes = 1234;
    c.drop_udp_spoof = 2;

    const meta = DaemonMeta{
        .version = "9.9.9",
        .mode = "raw_direct",
        .listen_port = 51820,
        .tun_name = "snr0",
        .local_id = 1,
    };

    var buf: [4096]u8 = undefined;
    const s = formatStatus(&buf, meta, &reg, &c);

    try std.testing.expect(std.mem.indexOf(u8, s, "subnetra v9.9.9 [running]") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "local_id=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "id=2 endpoint=203.0.113.7:51820 allowed_src=10.0.0.2/32") != null);
    // The named peer surfaces its label; the anonymous peer above stays id-only.
    try std.testing.expect(std.mem.indexOf(u8, s, "id=5 name=core-hub endpoint=203.0.113.9:51820") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "tun_rx packets=5") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "udp_tx packets=0 bytes=1234") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "spoof=2") != null);
    // The PSK byte 0xAB must never appear in the rendered status.
    try std.testing.expect(std.mem.indexOf(u8, s, &[_]u8{0xAB}) == null);
}

test "formatStatusJson: valid versioned schema, derived age/online, no secrets (issue #105)" {
    var reg = peer.PeerRegistry.init(1);
    const psk: @import("crypto.zig").Key = [_]u8{0xAB} ** 32;
    const ep = try @import("config.zig").parseEndpoint("203.0.113.7:51820");
    const ep2 = try @import("config.zig").parseEndpoint("198.51.100.9:51820");
    // Peer 2 was last seen 5s before `now` (online); peer 3 was never seen.
    const now: u64 = 1_700_000_100_000_000_000;
    const boot: u64 = 1_700_000_000_000_000_000;
    const p2 = try reg.add(psk, 2, ep, try @import("config.zig").parseCidr("10.0.0.2/32"), boot);
    p2.last_seen_wall_ns = 1_700_000_095_000_000_000;
    // Peer 2 carries a name (with a JSON metacharacter to exercise escaping);
    // peer 3 is anonymous and must serialize an empty name.
    p2.name_len = try @import("config.zig").parsePeerName(&p2.name, "gw \"alpha\"");
    _ = try reg.add(psk, 3, ep2, try @import("config.zig").parseCidr("10.0.0.3/32"), boot);

    var c = stats.Counters{};
    c.tun_rx_packets = 5;
    c.keepalive_tx = 7;
    c.drop_udp_spoof = 2;

    const meta = DaemonMeta{
        .version = "9.9.9",
        .mode = "raw_direct",
        .listen_port = 51820,
        .tun_name = "snr0",
        .local_id = 1,
    };

    var buf: [8192]u8 = undefined;
    const s = formatStatusJson(&buf, meta, &reg, &c, now, 90);

    // No secret bytes may leak into the machine-readable form either.
    try std.testing.expect(std.mem.indexOf(u8, s, &[_]u8{0xAB}) == null);

    // Must be valid JSON and carry the documented, versioned schema.
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, s, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqual(@as(i64, STATUS_SCHEMA_VERSION), root.get("schema_version").?.integer);
    try std.testing.expectEqualStrings("9.9.9", root.get("version").?.string);
    try std.testing.expectEqualStrings("raw_direct", root.get("mode").?.string);
    try std.testing.expectEqual(@as(i64, 1), root.get("local_id").?.integer);
    try std.testing.expectEqual(@as(i64, 51820), root.get("listen_port").?.integer);
    try std.testing.expectEqualStrings("snr0", root.get("tun").?.string);

    const peers = root.get("peers").?.array;
    try std.testing.expectEqual(@as(usize, 2), peers.items.len);

    // Look peers up by id rather than assuming registry slot order.
    var p_seen: ?std.json.ObjectMap = null;
    var p_never: ?std.json.ObjectMap = null;
    for (peers.items) |pv| {
        const o = pv.object;
        switch (o.get("id").?.integer) {
            2 => p_seen = o,
            3 => p_never = o,
            else => try std.testing.expect(false),
        }
    }

    const p0 = p_seen.?;
    try std.testing.expectEqualStrings("203.0.113.7:51820", p0.get("endpoint").?.string);
    try std.testing.expectEqualStrings("10.0.0.2/32", p0.get("allowed_src").?.string);
    // The name round-trips through JSON (escaping preserved) for the named peer.
    try std.testing.expectEqualStrings("gw \"alpha\"", p0.get("name").?.string);
    try std.testing.expectEqual(@as(i64, 5), p0.get("last_seen_age_seconds").?.integer);
    try std.testing.expect(p0.get("online").?.bool);

    // Never-seen peer: age is null and the peer is offline.
    const p1 = p_never.?;
    // An anonymous peer serializes an empty name (stable schema).
    try std.testing.expectEqualStrings("", p1.get("name").?.string);
    switch (p1.get("last_seen_age_seconds").?) {
        .null => {},
        else => try std.testing.expect(false),
    }
    try std.testing.expect(!p1.get("online").?.bool);
    try std.testing.expectEqual(@as(i64, 0), p1.get("last_seen_wall_ns").?.integer);

    // Counters are reflected wholesale, so every field is present and stable.
    const ctr = root.get("counters").?.object;
    try std.testing.expectEqual(@as(i64, 5), ctr.get("tun_rx_packets").?.integer);
    try std.testing.expectEqual(@as(i64, 7), ctr.get("keepalive_tx").?.integer);
    try std.testing.expectEqual(@as(i64, 2), ctr.get("drop_udp_spoof").?.integer);
    try std.testing.expect(ctr.get("drop_udp_auth_or_invalid") != null);
}

/// Send one command datagram to a bound control socket at `path`.
fn sendCommand(path: []const u8, msg: []const u8) !void {
    const cfd = try sys.socket(sys.AF.UNIX, sys.SOCK.DGRAM, 0, false, true);
    defer _ = sys.close(cfd);

    var addr = sys.sockaddr.un{ .path = undefined };
    @memset(&addr.path, 0);
    @memcpy(addr.path[0..path.len], path);
    const alen: sys.socklen_t = @intCast(@offsetOf(sys.sockaddr.un, "path") + path.len + 1);

    const wrc = sys.sendto(cfd, msg.ptr, msg.len, 0, @ptrCast(&addr), alen);
    try std.testing.expect(sys.errno(wrc) == .SUCCESS);
}

fn unlinkPath(path: []const u8) void {
    var pz: [108]u8 = undefined;
    @memcpy(pz[0..path.len], path);
    pz[path.len] = 0;
    _ = sys.unlink(@ptrCast(&pz));
}

test "openDgramSocket: control socket is bound 0600 regardless of umask (#37)" {

    // A permissive umask must not widen the control socket: fchmod is explicit.
    const prev = sys.umask(0);
    defer _ = sys.umask(prev);

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/subnetra-perm-{d}.sock", .{sys.getpid()});
    defer unlinkPath(path);

    const fd = try openDgramSocket(path);
    defer _ = sys.close(fd);

    // The on-disk control socket node must be owner-only (0600). Stat the path
    // (not the fd): macOS fstat(socket_fd) reports the kernel socket object's
    // mode, not the bound node's, and the raw Linux layer has no fstat anyway.
    var pz: [72]u8 = undefined;
    @memcpy(pz[0..path.len], path);
    pz[path.len] = 0;
    const mode = try sys.statMode(@ptrCast(&pz));
    try std.testing.expectEqual(@as(u16, 0o600), mode & 0o777);
}

test "control: policy add datagram hot-swaps the active tree" {

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/subnetra-add-{d}.sock", .{sys.getpid()});

    var empty = policy.PolicyTree{ .entries = &.{} };
    var active = policy.ActiveTree.init(&empty);

    var ctl: Control = undefined;
    try ctl.bindInPlace(path, "/tmp/subnetra-add.policy", &active, &.{});
    defer ctl.deinit();
    defer unlinkPath(path);

    // No route before the command lands.
    try std.testing.expect(active.load().match(0xC0A8_0905) == null); // 192.168.9.5

    try sendCommand(path, "policy add --src 0.0.0.0/0 --dst 192.168.9.0/24 --action forward --target 5\n");
    ctl.handle();

    const hit = active.load().match(0xC0A8_0905) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(policy.Action.forward, hit.action);
    try std.testing.expectEqual(@as(u32, 5), hit.target);

    // A second rule is published over the first via the double-buffer swap.
    try sendCommand(path, "policy add --src 0.0.0.0/0 --dst 10.0.0.0/8 --action drop\n");
    ctl.handle();
    try std.testing.expectEqual(@as(usize, 2), ctl.count);
    try std.testing.expectEqual(policy.Action.drop, active.load().match(0x0A00_0001).?.action);
    // The earlier rule survives the swap.
    try std.testing.expectEqual(@as(u32, 5), active.load().match(0xC0A8_0905).?.target);
}

test "control: malformed datagram leaves the tree unchanged" {

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/subnetra-bad-{d}.sock", .{sys.getpid()});

    var empty = policy.PolicyTree{ .entries = &.{} };
    var active = policy.ActiveTree.init(&empty);

    var ctl: Control = undefined;
    try ctl.bindInPlace(path, "/tmp/subnetra-bad.policy", &active, &.{});
    defer ctl.deinit();
    defer unlinkPath(path);

    try sendCommand(path, "bogus garbage line\npolicy add --src 10.0.0.0/24\n");
    ctl.handle();

    try std.testing.expectEqual(@as(usize, 0), ctl.count);
    try std.testing.expect(active.load().match(0xC0A8_0905) == null);
}

test "control: policy show replies with replayable rules to an addressable client" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/subnetra-show-{d}.sock", .{sys.getpid()});

    var empty = policy.PolicyTree{ .entries = &.{} };
    var active = policy.ActiveTree.init(&empty);

    var ctl: Control = undefined;
    try ctl.bindInPlace(path, "/tmp/subnetra-show.policy", &active, &.{});
    defer ctl.deinit();
    defer unlinkPath(path);

    try sendCommand(path, "policy add --src 0.0.0.0/0 --dst 192.168.9.0/24 --action forward --target 5\n");
    ctl.handle();

    // Addressable client: abstract autobind gives the daemon a return address.
    const cfd = try sys.socket(sys.AF.UNIX, sys.SOCK.DGRAM, 0, false, true);
    defer _ = sys.close(cfd);
    var ba = sys.sockaddr.un{ .path = undefined };
    ba.family = sys.AF.UNIX;
    try std.testing.expect(sys.errno(sys.bind(cfd, @ptrCast(&ba), ADDR_HDR)) == .SUCCESS);

    var sa = sys.sockaddr.un{ .path = undefined };
    @memset(&sa.path, 0);
    @memcpy(sa.path[0..path.len], path);
    const alen: sys.socklen_t = @intCast(ADDR_HDR + path.len + 1);
    const wrc = sys.sendto(cfd, "policy show\n", 12, 0, @ptrCast(&sa), alen);
    try std.testing.expect(sys.errno(wrc) == .SUCCESS);

    ctl.handle(); // serves the reply

    var out: [512]u8 = undefined;
    const rrc = sys.recvfrom(cfd, &out, out.len, 0, null, null);
    try std.testing.expect(sys.errno(rrc) == .SUCCESS);
    const reply = out[0..@intCast(rrc)];
    try std.testing.expect(std.mem.indexOf(u8, reply, "policy add --src 0.0.0.0/0 --dst 192.168.9.0/24 --action forward --target 5") != null);
}

test "control: status replies 'unavailable' until bound, then a full report" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/subnetra-status-{d}.sock", .{sys.getpid()});

    var empty = policy.PolicyTree{ .entries = &.{} };
    var active = policy.ActiveTree.init(&empty);

    var ctl: Control = undefined;
    try ctl.bindInPlace(path, "/tmp/subnetra-status.policy", &active, &.{});
    defer ctl.deinit();
    defer unlinkPath(path);

    // Addressable client socket (abstract autobind return address).
    const cfd = try sys.socket(sys.AF.UNIX, sys.SOCK.DGRAM, 0, false, true);
    defer _ = sys.close(cfd);
    var ba = sys.sockaddr.un{ .path = undefined };
    ba.family = sys.AF.UNIX;
    try std.testing.expect(sys.errno(sys.bind(cfd, @ptrCast(&ba), ADDR_HDR)) == .SUCCESS);

    var sa = sys.sockaddr.un{ .path = undefined };
    @memset(&sa.path, 0);
    @memcpy(sa.path[0..path.len], path);
    const alen: sys.socklen_t = @intCast(ADDR_HDR + path.len + 1);

    // Before bindStatus: status is gracefully unavailable (no null deref).
    _ = sys.sendto(cfd, "status\n", 7, 0, @ptrCast(&sa), alen);
    ctl.handle();
    var out: [2048]u8 = undefined;
    var rrc = sys.recvfrom(cfd, &out, out.len, 0, null, null);
    try std.testing.expect(sys.errno(rrc) == .SUCCESS);
    try std.testing.expect(std.mem.indexOf(u8, out[0..@intCast(rrc)], "status unavailable") != null);

    // After bindStatus: a full report is served.
    var reg = peer.PeerRegistry.init(1);
    var c = stats.Counters{};
    ctl.bindStatus(.{ .version = "1.2.3", .mode = "raw_direct", .listen_port = 51820, .tun_name = "snr0", .local_id = 1 }, &reg, &c);

    _ = sys.sendto(cfd, "status\n", 7, 0, @ptrCast(&sa), alen);
    ctl.handle();
    rrc = sys.recvfrom(cfd, &out, out.len, 0, null, null);
    try std.testing.expect(sys.errno(rrc) == .SUCCESS);
    try std.testing.expect(std.mem.indexOf(u8, out[0..@intCast(rrc)], "subnetra v1.2.3 [running]") != null);
    try std.testing.expect(std.mem.indexOf(u8, out[0..@intCast(rrc)], "traffic:") != null);

    // `status --json` is served over the same socket path (issue #105): the
    // handler dispatches to the JSON renderer and the reply is valid JSON.
    _ = sys.sendto(cfd, "status --json\n", 14, 0, @ptrCast(&sa), alen);
    ctl.handle();
    rrc = sys.recvfrom(cfd, &out, out.len, 0, null, null);
    try std.testing.expect(sys.errno(rrc) == .SUCCESS);
    const jbody = out[0..@intCast(rrc)];
    try std.testing.expect(std.mem.indexOf(u8, jbody, "\"schema_version\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, jbody, "\"version\":\"1.2.3\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, jbody, "\"counters\":{") != null);
}

test "control: save persists a replayable snapshot and acks" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/subnetra-save-{d}.sock", .{sys.getpid()});
    var snap_buf: [64]u8 = undefined;
    const snap = try std.fmt.bufPrint(&snap_buf, "/tmp/subnetra-save-{d}.policy", .{sys.getpid()});

    var empty = policy.PolicyTree{ .entries = &.{} };
    var active = policy.ActiveTree.init(&empty);

    var ctl: Control = undefined;
    try ctl.bindInPlace(path, snap, &active, &.{});
    defer ctl.deinit();
    defer unlinkPath(path);
    defer unlinkPath(snap);

    try sendCommand(path, "policy add --src 10.1.0.0/16 --dst 10.2.0.0/16 --action drop\n");
    ctl.handle();

    const cfd = try sys.socket(sys.AF.UNIX, sys.SOCK.DGRAM, 0, false, true);
    defer _ = sys.close(cfd);
    var ba = sys.sockaddr.un{ .path = undefined };
    ba.family = sys.AF.UNIX;
    try std.testing.expect(sys.errno(sys.bind(cfd, @ptrCast(&ba), ADDR_HDR)) == .SUCCESS);

    var sa = sys.sockaddr.un{ .path = undefined };
    @memset(&sa.path, 0);
    @memcpy(sa.path[0..path.len], path);
    const alen: sys.socklen_t = @intCast(ADDR_HDR + path.len + 1);
    try std.testing.expect(sys.errno(sys.sendto(cfd, "save\n", 5, 0, @ptrCast(&sa), alen)) == .SUCCESS);

    ctl.handle();

    var ack: [256]u8 = undefined;
    const rrc = sys.recvfrom(cfd, &ack, ack.len, 0, null, null);
    try std.testing.expect(sys.errno(rrc) == .SUCCESS);
    try std.testing.expect(std.mem.indexOf(u8, ack[0..@intCast(rrc)], "saved 1 rule") != null);

    // Snapshot file holds the replayable command.
    var snapz: [108]u8 = undefined;
    @memcpy(snapz[0..snap.len], snap);
    snapz[snap.len] = 0;
    const rfd = try sys.openZ(@ptrCast(&snapz), .{ .ACCMODE = .RDONLY }, 0);
    defer _ = sys.close(rfd);
    var fbuf: [256]u8 = undefined;
    const frc = sys.read(rfd, &fbuf, fbuf.len);
    try std.testing.expect(sys.errno(frc) == .SUCCESS);
    try std.testing.expect(std.mem.indexOf(u8, fbuf[0..@intCast(frc)], "policy add --src 10.1.0.0/16 --dst 10.2.0.0/16 --action drop") != null);
}

test "client: send/request to an absent daemon report DaemonUnavailable" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/subnetra-absent-{d}.sock", .{sys.getpid()});
    unlinkPath(path); // ensure nothing is bound there

    try std.testing.expectError(error.DaemonUnavailable, send(path, "policy add --src 0.0.0.0/0 --dst 10.0.0.0/8 --action drop\n"));

    var out: [64]u8 = undefined;
    try std.testing.expectError(error.DaemonUnavailable, request(path, "policy show\n", &out, 200));
}

test "client: request times out as NoResponse when the daemon never replies" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/subnetra-silent-{d}.sock", .{sys.getpid()});

    // A bound socket that accepts the datagram but never replies.
    const sfd = try sys.socket(sys.AF.UNIX, sys.SOCK.DGRAM, 0, false, true);
    defer _ = sys.close(sfd);
    defer unlinkPath(path);
    var sa = sys.sockaddr.un{ .path = undefined };
    @memset(&sa.path, 0);
    @memcpy(sa.path[0..path.len], path);
    const alen: sys.socklen_t = @intCast(ADDR_HDR + path.len + 1);
    try std.testing.expect(sys.errno(sys.bind(sfd, @ptrCast(&sa), alen)) == .SUCCESS);

    var out: [64]u8 = undefined;
    try std.testing.expectError(error.NoResponse, request(path, "policy show\n", &out, 150));
}

test "client: round-trips a real request() against a served control socket" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/subnetra-rt-{d}.sock", .{sys.getpid()});

    var empty = policy.PolicyTree{ .entries = &.{} };
    var active = policy.ActiveTree.init(&empty);

    var ctl: Control = undefined;
    try ctl.bindInPlace(path, "/tmp/subnetra-rt.policy", &active, &.{});
    defer ctl.deinit();
    defer unlinkPath(path);

    try send(path, "policy add --src 0.0.0.0/0 --dst 172.16.0.0/12 --action forward --target 7\n");
    ctl.handle();

    const Server = struct {
        fn loop(c: *Control, stop: *std.atomic.Value(bool)) void {
            const ts = sys.timespec{ .sec = 0, .nsec = 1 * std.time.ns_per_ms };
            while (!stop.load(.acquire)) {
                c.handle();
                _ = sys.nanosleep(&ts, null);
            }
        }
    };
    var stop = std.atomic.Value(bool).init(false);
    var th = try std.Thread.spawn(.{}, Server.loop, .{ &ctl, &stop });
    defer {
        stop.store(true, .release);
        th.join();
    }

    var out: [512]u8 = undefined;
    const reply = try request(path, "policy show\n", &out, 2000);
    try std.testing.expect(std.mem.indexOf(u8, reply, "--dst 172.16.0.0/12 --action forward --target 7") != null);
}

