# Subnetra Control-Plane Protocol — v1

> **Status: stable, machine-facing contract.** This document specifies the local
> control-plane interface that the `subnetra` CLI uses to talk to the `subnetrad`
> daemon. It is the supported way for **any language** to manage, inspect, and
> monitor a running daemon — read peer health, drive policy routing at runtime,
> snapshot state, and scrape metrics — **without** linking against the daemon.
>
> The cross-language integration boundary is this **IPC protocol**, not a C ABI /
> FFI library. The daemon is a single-threaded reactor that owns the event loop,
> the TUN device, and (on Linux) `NET_ADMIN`; it is not an in-process library.
> Everything you can do with the bundled `subnetra` CLI you can do by speaking the
> few plaintext datagrams below over a Unix domain socket.
>
> For the on-wire *data-plane* protocol between peers (encryption, framing,
> anti-replay), see [`docs/PROTOCOL.md`](PROTOCOL.md) — that is a different,
> network-facing contract. This document is **host-local only**.

The reference implementation lives in [`src/uds.zig`](../src/uds.zig) and is the
executable source of truth; where this prose disagrees with the code, the code
wins. The CLI client that speaks it is [`src/subnetra.zig`](../src/subnetra.zig).

---

## 1. Transport

| Property         | Value                                                                 |
|------------------|-----------------------------------------------------------------------|
| Address family   | `AF_UNIX`                                                             |
| Socket type      | `SOCK_DGRAM` (one datagram == one message; no stream framing)        |
| Scope            | **Host-local only.** Never exposed on the network.                   |
| Default path     | Linux: `/run/subnetra/subnetra.sock` · macOS: `/var/run/subnetra.sock` |
| Path override    | `SUBNETRA_SOCK` env var (honoured by **both** the daemon and the CLI) |
| Node permissions | `0600`, owner-only (in production inside a root-owned `0700` runtime dir) |
| Max request size | **4096 bytes** per datagram; oversized datagrams are dropped whole    |
| Encoding         | ASCII plaintext, space-tokenized; commands separated by `\n`          |

A request datagram may carry one **or** several newline-separated command lines.
For request/reply commands (§3) send **one command per datagram** — each query
line produces its own reply datagram, so batching makes correlation harder.

The daemon drains the control socket in bounded batches (64 command lines per
reactor wake-up; the fd is level-triggered, so a backlog is processed across
subsequent wakes). This caps how much a local control flood can perturb the data
plane — it is not something a well-behaved client needs to manage.

---

## 2. Authorization model

There is **no in-band authentication**. The socket's filesystem permissions
**are** the authorization boundary:

- The node is created `0600` (owner-only) and, in the shipped deployment, lives
  in a root-owned `0700` runtime directory (`RuntimeDirectory=subnetra` under
  systemd). A client must run as the user that owns the socket (typically
  `root`).
- Anyone who can `sendto` the socket can **mutate routing policy** and **read**
  peer endpoints, last-seen times, and counters.
- **Secrets are never exposed.** PSKs and derived keys are never serialized into
  any reply, in any command.

Treat "can open the control socket" as equivalent to "can administer this node's
routing." Do not relax the socket permissions or relocate it somewhere
world-writable.

---

## 3. Commands

Each command is a single line of space-separated tokens. Flags may appear in any
order. There are two interaction shapes:

- **Fire-and-forget** — the daemon applies it and sends **no reply**.
- **Request/reply** — the daemon replies to the client's source address (see §4).

### 3.1 `policy add` — install a routing rule (fire-and-forget)

```
policy add --src <CIDR> --dst <CIDR> --action forward --target <peer-id>
policy add --src <CIDR> --dst <CIDR> --action drop
```

- `--src`, `--dst` — required. Host-order IPv4 CIDR, e.g. `10.0.0.0/24`,
  `192.168.1.5/32`.
- `--action` — `forward` or `drop`. **Defaults to `drop`** if omitted.
- `--target` — required for `forward`: the destination **peer id** (the `id` of a
  configured peer). Ignored for `drop`.

The rule is published into the live data plane via a lock-free atomic swap (RCU)
with **zero downtime** — no restart, no dropped packets. There is **no reply** and
no inline validation error returned to the client; a malformed line is dropped by
the daemon. Confirm the result with `policy show`.

### 3.2 `policy show` — dump the live policy tree (request/reply)

Reply: the active rules serialized as **replayable** `policy add …` command lines
(newline-terminated). An empty tree replies with the single line
`# no policy rules`. Because the output *is* the command grammar, it can be piped
straight back in to reproduce state.

### 3.3 `save` — snapshot the policy tree to disk (request/reply)

Persists the live tree to `<socket-path>.policy` (e.g.
`/run/subnetra/subnetra.policy`) via a fsync + atomic-rename write.

Reply: `saved <n> rule(s) to <path>` on success, or `save failed` on any I/O
error (the previous snapshot, if any, is left intact).

### 3.4 `status` — human-readable status (request/reply)

Reply: a multi-line text report — daemon identity, per-peer table, traffic
counters, and the per-reason drop taxonomy. **For automation, prefer
`status --json` (§3.5)**; this text form is operator-facing and is not a parsing
contract.

### 3.5 `status --json` — machine-readable status (request/reply)

Reply: a single-line JSON object — the **stable, versioned** monitoring contract.
See §5 for the schema. This is the form to parse from other languages.

### 3.6 Errors

The grammar is small and strict:

- An unknown verb, an unknown flag, or a stray token (e.g. `status --bogus`) is
  rejected as a parse error.
- `policy add` without both `--src` and `--dst` is a missing-argument error.

For **request/reply** commands the daemon simply sends no reply on a parse failure
(the client observes a timeout — see §4). For **fire-and-forget** `policy add`,
the line is silently dropped. Validate your command strings before sending; the
`subnetra` CLI rejects malformed input locally with exit code `2`.

---

## 4. Reply addressing (request/reply commands)

`SOCK_DGRAM` has no connection, so the daemon can only reply if the request
arrived from an **addressable** source. The client **must bind its socket to a
return address** before sending a request/reply command, otherwise the reply is
silently discarded.

- **Linux:** use **abstract autobind** — bind the client socket with only the
  address family set (a zero-length / abstract name). The kernel assigns a unique
  abstract address; the daemon replies to it.
- **macOS / other:** bind the client socket to a **unique filesystem path** the
  client can receive on, then clean it up. (The abstract-socket namespace is a
  Linux feature.)
- **Fire-and-forget** `policy add` needs **no** bind.

Reply mechanics:

- The daemon replies best-effort and non-blocking (`MSG_DONTWAIT`). A slow or
  vanished client just loses the reply — the daemon never stalls.
- Each reply is a **single datagram**. Size your receive buffer to hold a full
  policy dump: the worst case is `MAX_POLICY_ENTRIES × 112` bytes (≈ **30 KB**
  with the default build of `MAX_PEERS = 32`). A **64 KiB** receive buffer never
  truncates.
- Apply a timeout. The bundled CLI waits **2000 ms**; a missing reply means the
  daemon is down, the command was malformed, or the client never bound a return
  address.

> **Platform note (bundled CLI):** the Zig client helpers `uds.send` /
> `uds.request` are currently **Linux-only** (they use abstract autobind) and
> return `error.Unsupported` elsewhere. The *protocol* is platform-neutral — a
> native client on macOS that binds a filesystem return address works against the
> macOS daemon. Only the shipped helper is gated.

---

## 5. `status --json` schema

`schema_version` is the stability pin. It is **`1`** today and is bumped **only**
on a breaking change — a removed/renamed key or a changed type. **Adding** a new
counter is *not* breaking (the `counters` object is reflected from the daemon's
counter struct, so new fields appear automatically). Pin the version your monitor
expects and treat an unknown bump as "re-check the schema."

```jsonc
{
  "schema_version": 1,              // u32 — bump only on a breaking change
  "version": "0.9.0",              // daemon build version
  "mode": "raw_direct",            // egress mode (v1: always "raw_direct")
  "local_id": 1,                    // u32 — this node's id
  "listen_port": 18020,             // u16 — primary UDP listen port
  "tun": "snr0",                   // TUN interface name
  "peers": [
    {
      "id": 2,                      // u32 — peer id (matches policy --target)
      "name": "bj-office-gw",      // operator label; "" when unset (JSON-escaped)
      "endpoint": "203.0.113.7:51822", // last known UDP endpoint "ip:port"
      "allowed_src": "10.66.0.2/32",   // anti-spoof inner-source prefix
      "last_seen_wall_ns": 1700000095000000000, // u64 wall-clock ns; 0 if never seen
      "last_seen_age_seconds": 5,   // u64 seconds, or null if never authenticated
      "online": true                // last_seen within the freshness window (~90 s)
    }
  ],
  "counters": {                     // every data-plane counter, name -> u64
    "tun_rx_packets": 3,
    "udp_tx_packets": 0
    /* …all stats.Counters fields: traffic + per-reason drop counters… */
  }
}
```

Key ordering is fixed by the serializer (the order shown above). Notes:

- `online` / `last_seen_age_seconds` give a per-peer heartbeat. The freshness
  window is ~90 s — long enough to absorb a few missed keepalives without
  flapping. A never-authenticated peer reports `last_seen_age_seconds: null` and
  `online: false`.
- `counters` carries **every** counter from the human `status` view (successful
  traffic flow plus the per-reason drop taxonomy), so a scrape never misses a
  field. See [observability docs](../docs-site/en/src/operations/observability.md)
  for the meaning of each drop reason.
- Secrets are never present anywhere in this object.

---

## 6. Stability promise

| Surface                         | Stability |
|---------------------------------|-----------|
| `status --json` shape           | **Versioned** by `schema_version`; the stable machine contract. |
| Command grammar (`policy add` / `policy show` / `save` / `status`) | Stable within v1. |
| `policy show` reply             | Stable — it is the replayable `policy add` grammar. |
| `save` ack / `status` text      | Operator-facing text; **do not parse** — use `status --json`. |
| Socket path, env override, perms | Stable. |

Build a long-lived integration on `status --json` + the command grammar. Treat
the free-form human text as a convenience, not an API.

---

## 7. Prometheus / metrics

There is **deliberately no HTTP server in the daemon** (extra attack surface,
against the single-binary ethos). Metrics are produced **host-side** by converting
`status --json`:

- [`deploy/subnetra-textfile-exporter.sh`](../deploy/subnetra-textfile-exporter.sh)
  (requires `jq`) renders `status --json` into node_exporter **textfile
  collector** `.prom` output. Drive it from the bundled systemd timer or cron;
  your existing node_exporter scrapes the file.
- It always publishes `subnetra_up {0|1}` so "the exporter ran but the daemon is
  down" is itself alertable.

Emitted metrics: `subnetra_up`, `subnetra_schema_version`,
`subnetra_build_info{…}`, `subnetra_peer_online{id,allowed_src}`,
`subnetra_peer_last_seen_age_seconds{id,allowed_src}`, and
`subnetra_<counter>_total` for every `counters` field (drift-proof). Full table
and alert expressions:
[observability docs](../docs-site/en/src/operations/observability.md).

To integrate from another language, replicate that pattern: call
`status --json`, map fields to your metrics format. You do not need this script —
it is one reference implementation of the mapping.

---

## 8. Client examples

### 8.1 Shell — the zero-code path

The simplest "client" in any environment is the bundled CLI plus `jq`:

```sh
subnetra status --json | jq .
subnetra status --json | jq -r '.peers[] | select(.online | not) | .id'
subnetra policy add --src 10.0.0.0/24 --dst 10.0.1.0/24 --action forward --target 3
subnetra policy show
```

### 8.2 Python (Linux) — request/reply with abstract autobind

```python
import os, socket

SOCK = os.environ.get("SUBNETRA_SOCK", "/run/subnetra/subnetra.sock")

def request(line: str, timeout: float = 2.0) -> bytes:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    # Abstract autobind so the daemon can reply (Linux: name starts with NUL).
    s.bind("\0subnetra-client-%d" % os.getpid())
    s.settimeout(timeout)
    try:
        s.sendto(line.encode(), SOCK)
        data, _ = s.recvfrom(65536)   # 64 KiB: never truncates a full dump
        return data
    finally:
        s.close()

import json
status = json.loads(request("status --json"))
print(status["version"], "peers online:",
      sum(1 for p in status["peers"] if p["online"]))
```

### 8.3 Python — fire-and-forget `policy add` (no bind, no reply)

```python
import os, socket
SOCK = os.environ.get("SUBNETRA_SOCK", "/run/subnetra/subnetra.sock")
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.sendto(b"policy add --src 10.0.0.0/24 --dst 10.0.1.0/24 --action forward --target 3", SOCK)
s.close()
# Confirm with a follow-up `policy show` request.
```

### 8.4 Go (Linux) — request/reply over `unixgram`

```go
laddr := &net.UnixAddr{Name: "@subnetra-client", Net: "unixgram"} // abstract (Go maps @ -> NUL)
raddr := &net.UnixAddr{Name: "/run/subnetra/subnetra.sock", Net: "unixgram"}
c, _ := net.DialUnix("unixgram", laddr, raddr)
defer c.Close()
c.SetDeadline(time.Now().Add(2 * time.Second))
c.Write([]byte("status --json"))
buf := make([]byte, 65536)
n, _ := c.Read(buf)
fmt.Println(string(buf[:n]))
```

> Run these as the user that owns the socket (usually `root`, e.g. via `sudo`).
> The `\0`-prefixed bind names above are Linux abstract addresses; on macOS bind a
> unique filesystem path instead (see §4).
