# Subnetra Wire Protocol Specification — v1

> **Status: normative.** This document is the interoperability contract for the
> Subnetra data plane. Any implementation — regardless of operating system or
> programming language — that reproduces the behaviour below is a conformant
> Subnetra endpoint and can join a mesh alongside the reference implementation.
>
> The reference implementation (pure Zig) lives in `src/` and is the executable
> source of truth. The machine-checkable companion to this document is the
> known-answer-test (KAT) vector set in
> [`tests/protocol-vectors.json`](../tests/protocol-vectors.json) — a **sender**
> suite (`vectors`) that pins key derivation and emitted datagram bytes, a
> **receiver** suite (`receiver_cases`) that pins the accept/drop decision,
> recovered plaintext, and post-step session epoch for a sequence of crafted
> datagrams, and an **obfuscation** suite (`obfuscated_vectors`, §3.4) that pins
> the masked on-wire bytes of each sender vector. All are pinned to the code by
> `src/protocol_conformance.zig` (runs under `zig build test`) and regenerated
> with `zig build vectors`.
>
> **Authority:** for the KDF, header serialization, AEAD, and emitted sender
> datagram bytes, the KAT `vectors` are authoritative — if this prose disagrees
> with them, the vectors win. Receiver accept/drop behaviour is normative in §5
> and is mechanically exercised by `receiver_cases`; the inner-source filter,
> `key_id` peer selection, endpoint learning, and no-reflect relay guard (§5
> steps 1, 7, 8, 9) are normative prose that the reference implementation enforces
> in its reactor loop but that the cross-implementation KAT does not yet encode.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as in
RFC 2119.

---

## 1. Scope and model

Subnetra forwards raw IPv4 packets between mesh nodes over an encrypted UDP
underlay in a **single-hub hub-and-spoke** topology. Each node has a numeric
mesh **id** that is non-zero and **MUST** fit a `u16` (`0 < id ≤ 65535`), so it
can serve as the on-wire `key_id` selector (§3.1, §5). Every directional link
`(from_id → to_id)` has its own keys, so a node's transmit key to a peer equals
that peer's receive key for traffic from the node.

This specification covers the **on-wire datagram**: how a plaintext inner IP
packet becomes a UDP payload, and the rules a receiver applies to accept or
silently drop one. It does **not** mandate *how* an endpoint sources or delivers
inner packets (a kernel TUN device, a userspace IP stack, or an application
buffer are all permitted) nor the host's eventing model (epoll, kqueue, threads,
async — all permitted).

**`wire_version` for this document is `1`.** It is carried in byte 0 of every
datagram (see §3).

---

## 2. Cryptographic primitives

| Primitive | Choice | Parameters |
|-----------|--------|------------|
| AEAD | **ChaCha20-Poly1305 (IETF, 96-bit nonce)** | key 32 B, nonce 12 B, tag 16 B |
| KDF / keyed hash | **BLAKE2b with 256-bit (32 B) digest, keyed mode** | key = the parent key; **native BLAKE2 keyed mode, NOT HMAC** |

Implementers **MUST** use BLAKE2b's built-in keyed hashing (the key occupies the
first input block per the BLAKE2 spec), **not** HMAC-BLAKE2b. The digest length
parameter is 32 and the key length parameter equals the key's byte length (32).

### 2.1 Key schedule

All multi-byte integers fed into the KDF are **big-endian**. The label strings
are ASCII with **no NUL terminator**.

```
link_key(psk, from_id, to_id) =
    BLAKE2b-256( key = psk,
                 msg = "subnetra-v1-link"            // 15 bytes
                     || u32_be(from_id)             //  4 bytes
                     || u32_be(to_id) )             //  4 bytes   → 32-byte key

session_key(link_key, epoch) =
    BLAKE2b-256( key = link_key,
                 msg = "subnetra-v1-session"         // 18 bytes
                     || u64_be(epoch) )             //  8 bytes   → 32-byte key
```

- The **sender** of a datagram uses `link_key(psk, local_id, peer_id)`.
- The **receiver** derives the matching key with `link_key(psk, peer_id,
  local_id)` (the same ordered pair the sender used). The two agree.
- `psk` is a **per-link 32-byte pre-shared key**. A node **MUST NOT** reuse one
  PSK across different peers.

> **Why per-link keys are mandatory:** under a shared PSK, two independent
> per-peer monotonic counters could emit the same `(key, nonce)` pair for
> different plaintexts, which catastrophically breaks ChaCha20-Poly1305. Giving
> every directional link its own key makes each link's nonce space disjoint.

### 2.2 Nonce

The 96-bit AEAD nonce is derived from the 64-bit sequence number:

```
nonce(seq) = u64_le(seq) || 0x00 0x00 0x00 0x00      // 8 bytes LE + 4 zero bytes
```

The AEAD is invoked with **empty associated data (AAD)**. The 16-byte Poly1305
tag is appended **after** the ciphertext.

### 2.3 Session epoch (stateless session establishment)

Each daemon lifetime samples a **boot epoch** once at startup:
`epoch = wall-clock time in nanoseconds` (`u64`).

- The epoch **MUST** be `>= 1_704_067_200_000_000_000` (2024-01-01T00:00:00Z in
  ns) and **MUST NOT** be `0`. An endpoint whose clock cannot satisfy this
  **MUST** fail closed (refuse to start) rather than emit a low/zero epoch.
- The epoch is carried in every datagram (§3), so a receiver derives the
  matching `session_key` **statelessly, with no handshake**.
- A fresh epoch on every restart re-keys the session, which is what lets the
  transmit sequence number safely restart at `1` after a reboot without ever
  reproducing a previous lifetime's `(key, nonce)` pair.
- **Accepted consequence (by design — no handshake).** Because epoch ordering is
  forward-only (§5) and there is **no** epoch-exchange handshake, a node whose
  wall clock runs *backward* across a restart emits a lower epoch that peers
  reject until their clocks advance past the old value. This is a deliberate
  trade-off of the stateless, handshake-free design, **not** a deferred fix; it
  is mitigated operationally (NTP/RTC), never in-protocol — see the deployment
  guide.

---

## 3. Datagram format

A Subnetra UDP payload is:

```
+------------------+---------------------------+----------------+
|  header (20 B)   |  ciphertext (len(inner))  |  tag (16 B)    |
+------------------+---------------------------+----------------+
```

### 3.1 Header (20 bytes, fixed)

| Offset | Size | Field      | Encoding   | v1 value / meaning                                   |
|-------:|-----:|------------|------------|------------------------------------------------------|
| 0      | 1    | `version`  | u8         | **MUST be `1`**                                      |
| 1      | 1    | `flags`    | u8         | bit 0 = `KEEPALIVE` (§3.3); bits 1–7 reserved, **MUST be `0`** |
| 2      | 2    | `key_id`   | u16 **LE** | sender's mesh id — the receiver's peer selector (§5) |
| 4      | 8    | `epoch`    | u64 **LE** | sender boot epoch (§2.3); never `0`                 |
| 12     | 8    | `seq`      | u64 **LE** | per-session monotonic sequence number / nonce basis |

> **`key_id` is an *unauthenticated* selector.** It is **not** covered by the AEAD
> (AAD is empty, §2.2), so an on-path attacker can flip it freely. This is safe by
> construction: `key_id` only chooses *which* peer's link key the receiver tries.
> A wrong or forged `key_id` selects the wrong key, authentication fails, and the
> datagram is dropped (fail-closed). It never weakens authentication; it only lets
> a roaming/NATed sender be recognised by identity rather than by source endpoint
> (§5). A peer's mesh id therefore **MUST** fit `u16` (`0 < id ≤ 65535`).

> **Endianness trap (read carefully):** the header fields `epoch` and `seq` are
> **little-endian**, but the *same* `epoch` value fed into the session KDF
> (§2.1) and the `from_id`/`to_id` fed into the link KDF are **big-endian**. The
> KAT vectors exist precisely to catch implementations that get this wrong.

### 3.2 Body

`ciphertext || tag = ChaCha20-Poly1305-Seal(key = session_key, nonce =
nonce(seq), aad = "", plaintext = inner_ip_packet)`.

The inner plaintext is a complete IPv4 packet. The ciphertext has the **same
length** as the plaintext; the tag adds a fixed 16 bytes.

### 3.3 Keepalive (`flags` bit 0)

A datagram with `flags` bit 0 (`KEEPALIVE = 0x01`) set is a one-way spoke→hub
keepalive (issue #96), not a tunnelled packet. It is sealed exactly like a data
datagram (§3.2) but over an **empty** inner plaintext, so its body is just the
16-byte tag and the total wire length is `20 + 16 = 36` bytes. It rides the same
monotonic `seq` + epoch + anti-replay machinery as data; it is **not** a handshake
and is **never** acknowledged. Its only purpose is to hold a NATed spoke's UDP
pinhole open and refresh the hub's learned endpoint (§5 step 6a) when no host
traffic would otherwise flow. The `KEEPALIVE` bit is a **backward-compatible**
addition under `wire_version = 1`: a sender that never emits keepalives is
unaffected, and a receiver that predates this bit simply drops keepalives (its
strict `flags == 0` check) without any effect on data delivery.

### 3.4 Header obfuscation (optional, on by default)

The header in §3.1 is **cleartext and unauthenticated** (the AAD is empty). That
is safe by construction (a tampered selector only fails authentication, §3.1,
§7), but it is also a **fingerprint**: to a passive on-path observer the constant
`version = 1`, the 8-byte `epoch` that repeats unchanged for a whole session, and
the low, monotonically increasing `seq` are a recognisable signature even though
there are no magic bytes. Active port-scan resistance (§7) does **not** imply
resistance to passive traffic classification.

Header obfuscation is a **deployment-wide** countermeasure that removes this
fingerprint. It is **on by default** (`obfuscate`; set `false` to opt out, e.g. for
packet-capture debugging). When enabled, a sender XOR-masks the **20-byte header** (and
only the header) with a per-packet pseudorandom pad before transmission; the body
(`ciphertext || tag`) is already indistinguishable from random and is left
untouched. The pad is:

```
pad = Blake2b-256(key = link_key, msg = "subnetra-v1-obfs" || tag)[0 .. 20]
masked_header[i] = header[i] XOR pad[i]   for i in 0..20
```

where `link_key` is the directional link key (§2.1) — shared by both ends of the
link — and `tag` is the datagram's own 16-byte AEAD tag, which travels in the
clear at the end of the datagram (the body is unmasked) and is unique per packet.
Because XOR masking is symmetric, a receiver reverses it by recomputing the same
`pad` from the (cleartext) `tag` and the link key.

**Selection under obfuscation.** The `key_id` selector (§5 step 1) is itself
masked, so a receiver cannot read it directly. Instead it **trials** a candidate
peer's receive link key: it recomputes `pad`, de-masks the header, and
accepts the candidate when the recovered header is self-consistent
(`version == 1` **and** the embedded `key_id` equals that peer's id). A wrong key
yields effectively random bytes that clear both checks with probability `< 2⁻²⁴`,
so the trial resolves the real sender; the AEAD authentication of §5 step 4
remains the actual security gate, so a (vanishingly rare) false pre-filter match
simply fails there and the datagram is dropped. A spoke trials one key (its hub);
a hub resolves the candidate as follows (issue #174 — a naive full scan per
datagram would let an off-path attacker amplify one cheap junk datagram into
`MAX_PEERS` keyed hashes on the single-threaded data plane):

1. **Source-endpoint fast path.** The peer whose *current* (learned, §5 roaming)
   endpoint equals the datagram's outer UDP source is trialed first — address
   comparisons plus **one** keyed hash. All steady-state traffic, including from
   previously-roamed peers, resolves here in O(1).
2. **Metered full scan.** Only a datagram from an unknown source endpoint (a
   genuinely roamed/restarted peer, or junk with a spoofed source) falls back to
   trialing every configured peer's key, and each ingress drain performs at most
   a fixed budget of such scans (`OBFS_SCAN_BUDGET`, 8 per drain). A datagram
   needing a scan after the budget is spent is dropped for that drain
   (`drop_udp_scan_budget` counter); a real roaming peer simply retries — its
   next datagram or keepalive wins a scan slot, authenticates, and its new
   endpoint is learned back onto the fast path. This bounds the worst-case
   unauthenticated CPU at `8 × MAX_PEERS` keyed hashes per drain regardless of
   flood rate, while junk beyond the budget costs only address comparisons.

**Properties and limits.**

- It is a **traffic-analysis** countermeasure, **not** a confidentiality or
  authentication mechanism. The pad is reproducible by any mesh member holding
  the link PSK; its sole purpose is to deny a non-member observer the fixed-byte
  fingerprint. It does **not** hide datagram **length** (a 36-byte keepalive is still
  36 bytes) or packet **timing** in general; as a partial timing measure, an
  obfuscating spoke randomizes its keepalive interval (see below) so the keepalive
  *cadence* is not a fixed-period signature.
- It is **not negotiated.** Subnetra performs no handshake (iron law #8), so every
  node in a mesh **MUST** be configured identically (`obfuscate`). A mismatch
  fails closed and loudly: an unmasked datagram reaching an obfuscation-enabled
  receiver de-masks to garbage that matches no peer and is dropped, and vice
  versa, so no traffic flows until the configuration agrees.
- The **inner** `wire_version` is unchanged (`1`): obfuscation is an outer
  envelope over the §3 datagram, not a new wire version. A node with obfuscation
  **off** emits and accepts byte-identical v1 datagrams (§3.1).

**Keepalive de-periodization.** When obfuscation is enabled, a spoke emitting the
built-in NAT keepalive (issue #96) randomizes each interval uniformly within
`[keepalive_secs / 2, keepalive_secs]`, never exceeding the configured (NAT-safe)
interval. This denies a passive observer the fixed period that an otherwise-idle
spoke would expose. With obfuscation off, the keepalive fires at the exact interval.

The `obfuscated_vectors` KAT suite pins the masked bytes of every sender vector;
a conformant implementation that offers this feature **MUST** reproduce them.

---

## 4. Sender behaviour (egress)

To send inner IPv4 packet `P` to peer `D`:

1. `key = session_key(link_key(psk, local_id, D.id), local_epoch)`.
2. `seq = ` next value of this link's monotonic counter (starts at `1`, strictly
   increasing, **MUST NOT** repeat within a session/epoch).
3. Emit header (§3.1) with `version=1, flags=0, key_id=local_id, epoch=local_epoch,
   seq`.
4. Append `ChaCha20-Poly1305-Seal(key, nonce(seq), "", P)`.
5. Send the datagram to `D`'s UDP endpoint.

A sender **MUST** treat the `(session_key, nonce)` uniqueness invariant as
absolute. On any event that could reset the counter (e.g. process restart) it
**MUST** also obtain a fresh `epoch` (and therefore a fresh `session_key`).

A NATed spoke **MAY** additionally emit a **keepalive** (§3.3) to its hub on an
idle timer: identical steps, but with `flags = KEEPALIVE` and an **empty**
plaintext `P = ""`. The keepalive consumes a `seq` from the same counter like any
datagram, so the uniqueness invariant above applies unchanged.

---

## 5. Receiver behaviour (ingress)

On a received UDP datagram from source endpoint `S`:

> **If header obfuscation (§3.4) is enabled**, the header is masked on the wire,
> so step 1 cannot read `key_id` directly. The receiver instead trial-de-masks
> the header against candidate peers' receive link keys — source-endpoint fast
> path first, then a budget-metered full scan (§3.4, "Selection under
> obfuscation") — and proceeds with the recovered cleartext header from step 2
> onward. Steps 2–9 are unchanged.

1. **Identity selection (by `key_id`, not by endpoint).** Read `key_id` from the
   header and look up the peer `P` whose mesh id equals it. If no peer matches,
   **drop silently** (§7). The source endpoint `S` is **not** the identity here — a
   NATed or roaming peer may legitimately arrive from an unexpected `S`. `key_id`
   is only a *hint* until the datagram authenticates in step 4; a forged `key_id`
   selects the wrong key and fails there.
2. **Header validation** — drop silently if **any** of:
   - `len(datagram) < 20`;
   - `version != 1`;
   - any reserved `flags` bit is set (i.e. `flags & ~KEEPALIVE != 0`; bit 0
     `KEEPALIVE` is permitted, all other bits **MUST** be `0`);
   - `epoch == 0`.
3. **Epoch ordering (forward-only).** Let `cur` be the highest epoch already
   accepted on this link (`0` if none).
   - If `epoch < cur`: **drop silently** (retired session / cross-epoch replay)
     before spending any crypto.
   - If `epoch == cur`: use the cached `session_key`.
   - If `epoch > cur`: derive a **candidate** `session_key(link_key, epoch)` but
     do **not** commit it yet.
4. **Authenticate & decrypt** with `P`'s link key and `nonce(seq)`. On
   authentication failure or truncation, **drop silently**. (No state has been
   mutated yet — a forged higher `epoch` or a wrong `key_id` cannot poison the
   session.)
5. **Commit a newer epoch.** Only now, if `epoch > cur`, adopt it: set
   `cur = epoch`, cache its key, and **reset** the anti-replay window.
6. **Anti-replay.** Apply the 64-entry sliding window (§6) to `seq`. If the
   sequence is a replay or older than the window, **drop silently**.
6a. **Keepalive short-circuit (§3.3).** If `flags & KEEPALIVE != 0`, the datagram
   has fully authenticated (steps 4–6) and is genuinely `P`. The receiver records
   `S` as `P`'s current endpoint (the endpoint-learning of step 8) and refreshes
   `P`'s last-seen time, then **stops**: a keepalive carries no inner packet, so
   the inner-source check (step 7) and routing (step 9) are skipped and nothing is
   delivered to the TUN. An **unauthenticated** keepalive never reaches this step —
   it was already dropped at step 4 — so the `flags` bit being outside the AEAD
   grants an attacker no endpoint-move or delivery power they did not already have.
7. **Inner source check.** The decrypted IPv4 packet's **source address MUST**
   fall within `P`'s `allowed_src` prefix. Otherwise **drop silently** (defeats
   inner-source spoofing by an authenticated peer).
8. **Endpoint learning (roaming).** The datagram has now fully authenticated
   (steps 4–6) **and** passed the inner-source check (step 7), so it is genuinely
   `P`. The receiver **MAY** record `S` as `P`'s current endpoint so that replies
   and hub relays follow a roamed/NATed peer without operator intervention. This
   step **MUST** come strictly after steps 4–7, so a replayed, forged, or
   inner-source-spoofed datagram can never move an endpoint. Learning is runtime
   state only — it is never written back to configuration.
9. **Route.** Look up the inner destination. Deliver to the local node, or (hub
   only) relay to another peer. A hub **MUST NOT** reflect a packet back to its
   source peer.

The order of steps 3–5 (authenticate **before** mutating any receive state) and
of step 8 (learn the endpoint **only after** steps 4–7) is **normative** and
security-critical.

> **Endpoint uniqueness is not an invariant.** Because peers are selected by
> `key_id`, two peers may transiently share a learned endpoint (e.g. behind the
> same NAT) with no loss of correctness — selection never depends on `S`. An
> implementation **MAY** reject duplicate endpoints at *configuration* load as a
> sanity check, but **MUST NOT** rely on endpoint uniqueness at runtime.
>
> **Residual risk — pre-observation epoch replay.** An on-path attacker who
> captures an authenticated datagram for epoch `E` and replays it *before* the
> receiver has observed `E` (`cur < E`) will pass steps 3–7 (adopt-epoch, reset
> window, accept) and thus also *learn the attacker's endpoint*. This requires
> on-path capture; an off-path attacker cannot forge an authenticator. It is the
> standard trade-off of stateless-epoch establishment plus endpoint learning,
> and it is **accepted by design, not deferred**: Subnetra performs no handshake
> as a deliberate constraint (the design contract's iron law #8), so there is no
> challenge/response to close it. The harm is also transient — the peer's next
> genuine packet relocates the endpoint back — and an off-path attacker cannot
> forge the authenticator.

---

## 6. Anti-replay window

Each receive session maintains a 64-bit sliding window over accepted sequence
numbers (`highest` + a 64-bit `bitmap`, where bit *i* means `highest - i` was
seen):

- `seq > highest`: accept; shift the window forward by `seq - highest`; set
  `highest = seq`.
- `highest - seq >= 64`: **reject** (too old).
- Otherwise: **reject** if the corresponding bit is already set (replay); else
  accept and set it.

The window is **reset** whenever a strictly newer epoch is adopted (§5.5).

---

## 7. Stealth / failure handling

On **any** rejection — unknown `key_id`, malformed header, an unknown reserved
`flags` bit, stale/zero epoch, authentication failure, replay, or inner-source
violation — the endpoint **MUST silently drop** the datagram. It **MUST NOT** emit
a TCP RST, an ICMP error, or any other observable response. The ciphertext **MUST
NOT** contain any fixed magic number. These rules make Subnetra
indistinguishable from background noise to an external prober.

---

## 8. MTU and overhead

Per-datagram overhead on top of the inner IP packet:

```
header(20) + tag(16) + outer IPv4(20) + outer UDP(8) = 64 bytes
```

For the v1 `raw_direct` egress mode the inner tunnel MTU is **1452**. On a 1500-
byte underlay path the largest safe inner MTU is `1500 - 64 = 1436`; operators
**SHOULD** size the tunnel interface MTU accordingly (see
`--print-network-plan`).

---

## 9. Versioning and forward compatibility

- This document specifies **`wire_version = 1`**. A v1 receiver **MUST** drop any
  datagram whose `version` byte is not `1` (there is no in-band negotiation in
  v1).
- The `flags` byte carries `KEEPALIVE` (bit 0, §3.3); bits 1–7 remain **reserved
  for future static per-link mode selection** (there is **no** on-wire handshake
  or in-band negotiation — a deliberate design constraint) and **MUST be zero** in
  v1, on both send and receive. Adding `KEEPALIVE` did **not** bump `wire_version`
  because it is backward compatible: it only widens the set of datagrams a v1
  receiver accepts (an empty-bodied, flagged keepalive that an older receiver
  simply drops), and never changes how a `flags == 0` data datagram is emitted or
  decided. Header bytes [2..4] carry the `key_id` selector (§3.1) — in v1 this is
  the sender's mesh id; it is **not** a free negotiation field.
- Two egress modes are reserved for v2 and are **not** part of the v1 wire
  contract: `kcp_arq` (in-house ARQ, MTU 1428) and `fec_xor` (forward error
  correction). A v1 implementation does not implement them.
- **Any change that alters the bytes a conformant endpoint emits or the
  accept/drop decision it makes is a breaking change** and **MUST** bump
  `wire_version`. Mechanically, a sender-byte change moves the `vectors` golden
  and a receiver accept/drop change moves the `receiver_cases` golden; either
  way the conformance sentinel forces a deliberate regeneration
  (`zig build vectors > tests/protocol-vectors.json`) and review.
- **Wire-compatibility contract.** Two builds interoperate **iff** they derive the
  same keys and make the same emit/accept/drop decisions for `wire_version = 1`.
  The `version` byte alone is **not** a sufficient compatibility signal: v0.5.0
  changed the HKDF key-derivation label (`btunnel-v1-*` → `subnetra-v1-*`, the
  project rename) **without** bumping `version`, which silently broke interop with
  `≤ v0.4.x` — every cross-version datagram fails AEAD auth (fail-closed). That was
  a one-time rebrand exception. Going forward, **any** change to the bytes a
  conformant endpoint emits, the keys it derives, or the accept/drop decision it
  makes MUST bump `wire_version` (the conformance-golden sentinel above forces it)
  **and** MUST be recorded in the deployment wire-compatibility matrix. Operators
  planning a cross-version upgrade consult that matrix and runbook
  ([`docs/deployment.md`](deployment.md) §6).

---

## 10. Conformance vectors

[`tests/protocol-vectors.json`](../tests/protocol-vectors.json) carries two
suites.

**`vectors` (sender KAT)** maps fixed inputs to their canonical outputs:

```
input:  { psk, from_id, to_id, epoch, seq, plaintext }
output: { link_key, session_key, datagram }   // all lowercase hex
```

An implementation is **sender-conformant** iff, for every vector, it reproduces
`link_key`, `session_key`, and the full `datagram` byte-for-byte from `input`.

**`receiver_cases` (receiver KAT)** drives a sequence of datagrams through a
single receive session:

```
case:  { name, link: { psk, from_id, to_id }, init_epoch, steps: [...] }
step:  { note, datagram, expect: "accept"|"drop", plaintext, epoch_after }
```

An implementation is **receiver-conformant** iff, replaying each case's `steps`
in order against a session preloaded to `init_epoch` (0 = fresh), it reaches the
same `accept`/`drop` decision, recovers the same `plaintext` on accept, and ends
each step at the same `epoch_after`. These cases exercise header validation,
zero/stale-epoch rejection, authentication failure, replay, in-window reorder,
and forward-only epoch adoption with window reset (§5–§6).

The top-level `max_plaintext` field pins the v1 `raw_direct` inner MTU (§8); a
boundary-sized vector exercises it.

New vectors/cases **MAY** be appended; existing ones **MUST NOT** be reordered
or mutated except by an intentional, reviewed wire-format change (which also
bumps `wire_version`).
