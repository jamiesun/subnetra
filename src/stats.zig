//! Issue #24: data-plane counters for runtime observability.
//!
//! A flat struct of plain `u64` counters. The reactor is strictly
//! single-threaded (iron law #3): the data pumps and the control `handle()`
//! never run concurrently, so a plain `+= 1` needs no atomics and no locks. The
//! struct lives in `main`'s frame and is shared by reference: the reactor
//! increments it, the control plane reads it for `subnetra status`.
//!
//! Drop reasons are split only as finely as the data plane can HONESTLY
//! distinguish them. `decodeIngress` collapses authentication failure, replay,
//! and a malformed header into a single `null`, so those share one counter
//! (`drop_udp_auth_or_invalid`) rather than pretending to a precision the code
//! does not have.

const std = @import("std");

pub const Counters = struct {
    // --- successful flow ---
    /// IP packets read off the local TUN (locally-originated egress).
    tun_rx_packets: u64 = 0,
    tun_rx_bytes: u64 = 0,
    /// Datagrams sealed and sent to a peer for locally-originated traffic.
    udp_tx_packets: u64 = 0,
    udp_tx_bytes: u64 = 0,
    /// Datagrams received on the UDP socket (before any validation).
    udp_rx_packets: u64 = 0,
    udp_rx_bytes: u64 = 0,
    /// Authenticated inner packets delivered to the local TUN.
    tun_tx_packets: u64 = 0,
    tun_tx_bytes: u64 = 0,
    /// Authenticated inner packets relayed on to another peer (hub forwarding).
    relay_packets: u64 = 0,
    relay_bytes: u64 = 0,
    /// Times a peer's UDP endpoint was relearned from an authenticated datagram
    /// arriving from a new source endpoint (issue #34 roaming).
    udp_endpoint_learned: u64 = 0,
    /// Authenticated spoke→hub keepalives received (issue #96). Counted on the hub
    /// after a flagged keepalive authenticates; it refreshes the learned endpoint
    /// and is dropped before routing (never reaches the TUN), so it shows up here
    /// and NOT in `tun_tx_packets`.
    keepalive_rx: u64 = 0,
    /// Keepalives a spoke emitted to its hub (issue #96). Counted on the spoke
    /// after a successful send; 0 on a hub/manual node.
    keepalive_tx: u64 = 0,

    // --- TUN egress drops ---
    drop_tun_not_ipv4: u64 = 0,
    drop_tun_no_route: u64 = 0,
    drop_tun_drop_rule: u64 = 0,
    drop_tun_local_loop: u64 = 0,
    drop_tun_unknown_target: u64 = 0,
    drop_tun_oversized: u64 = 0,
    drop_tun_egress_err: u64 = 0,
    drop_tun_send_err: u64 = 0,

    // --- UDP ingress drops ---
    /// Header `key_id` selector matched no configured peer (issue #34). Identity
    /// is now keyed on `key_id`, not the source endpoint, so a roaming spoke is
    /// no longer dropped here merely for arriving from a new endpoint.
    drop_udp_unknown_peer: u64 = 0,
    /// Malformed header (incl. too short to parse), authentication failure,
    /// replay, or stale/zero epoch (collapsed: see the module note).
    drop_udp_auth_or_invalid: u64 = 0,
    /// Obfuscation full-scan budget spent (issue #174): a datagram from an
    /// unknown source endpoint needed a full-registry key trial after this
    /// drain's `OBFS_SCAN_BUDGET` was exhausted. Under a spoofed-source flood
    /// this counts the junk kept off the CPU; a genuinely roaming peer landing
    /// here simply retries next drain. Only ever increments with obfuscation on.
    drop_udp_scan_budget: u64 = 0,
    drop_udp_not_ipv4: u64 = 0,
    /// Inner source outside the peer's allowed_src prefix (anti-spoofing).
    drop_udp_spoof: u64 = 0,
    drop_udp_no_route: u64 = 0,
    drop_udp_drop_rule: u64 = 0,
    drop_udp_unknown_target: u64 = 0,
    /// Would reflect a packet back to its own source peer (no-reflect guard).
    drop_udp_no_reflect: u64 = 0,
    drop_udp_oversized: u64 = 0,
    drop_udp_send_err: u64 = 0,

    pub fn inc(self: *Counters, comptime field: []const u8) void {
        @field(self, field) += 1;
    }

    pub fn add(self: *Counters, comptime field: []const u8, n: u64) void {
        @field(self, field) += n;
    }
};

test "counters start at zero and increment" {
    var c = Counters{};
    try std.testing.expectEqual(@as(u64, 0), c.tun_rx_packets);
    c.inc("tun_rx_packets");
    c.add("tun_rx_bytes", 100);
    c.inc("drop_udp_spoof");
    try std.testing.expectEqual(@as(u64, 1), c.tun_rx_packets);
    try std.testing.expectEqual(@as(u64, 100), c.tun_rx_bytes);
    try std.testing.expectEqual(@as(u64, 1), c.drop_udp_spoof);
}
