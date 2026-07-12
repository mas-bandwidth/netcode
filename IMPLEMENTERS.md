# Notes for other netcode implementations

netcode has independent implementations in C#, Go, Rust, and TypeScript (linked from the
README). Most were ported from this C reference, so a defect or a documentation error
here tends to be present there too. This file collects the findings that other
implementations should check themselves against. None change the wire protocol — an
implementation that fixes these stays interoperable with every other conforming one.

## 1. Integer overflow in replay protection (check your port)

**Where:** the "already received" test in replay protection.

The reference implementation computed, in effect:

```
if ( sequence + REPLAY_BUFFER_SIZE <= most_recent_sequence )
    return AlreadyReceived;
```

For sequence numbers within `REPLAY_BUFFER_SIZE` of `UINT64_MAX`, `sequence +
REPLAY_BUFFER_SIZE` wraps past zero, so legitimate packets at the very top of the
sequence space are falsely rejected as replays. Written subtraction-side it cannot
overflow:

```
if ( most_recent_sequence >= REPLAY_BUFFER_SIZE &&
     sequence <= most_recent_sequence - REPLAY_BUFFER_SIZE )
    return AlreadyReceived;
```

**Exploitability:** low in practice — sequence numbers start at 0 (per-client) or
`1 << 63` (server global) and increment by one per packet, so reaching the top 256 of
the space is not attacker-driven. But it is a real correctness bug in security-relevant
code, and a language that traps on unsigned overflow (or a debug build that does) will
abort rather than mis-answer. Ports that copied the addition-side form should switch to
the subtraction-side form. Found by fuzzing the packet reader's write/read round-trip
invariant. Fixed here in commit `7c638bd`.

## 2. Errata in older copies of STANDARD.md

The following were wrong in `STANDARD.md` through netcode 1.02 and are now corrected
(commit `8de93eb`). The wire format never changed — these were prose/table errors, so
an implementation built from the corrected text matches one built from the code. If your
implementation was written from the older document rather than from the code, verify:

- **Challenge token data size in the connection response packet.** The document listed it
  as `360 bytes` in one place; it is **300 bytes**, consistent with the challenge token
  layout, the connection challenge packet, and the 308-byte per-packet read check
  (8-byte sequence + 300).

- **Address type range.** The client/server validation prose said types outside `[0,1]`
  are invalid. The valid on-the-wire values are **1 (IPv4) and 2 (IPv6)**, as the format
  tables state. Read literally the old range rejected IPv6 and accepted the undefined
  type 0.

- **Nonce construction.** "The sequence number is extended by padding high bits with zero
  to create a 96 bit nonce" is ambiguous and, read against the document's little-endian
  convention, backwards. The 12-byte nonce is **four zero bytes followed by the sequence
  number as a 64-bit little-endian value** — i.e. `[0 0 0 0][seq0..seq7]`. Building the
  nonce the other way round produces incompatible ciphertext. This is the erratum most
  likely to break a fresh from-scratch implementation.

- **Read-packet step order.** The decrypted per-packet-data size check is necessarily
  performed *after* decryption (it validates the decrypted length); the old step list
  placed it before. The corrected list also notes the replay window advances only after
  a successful decrypt.

## 3. Server global packet sequence must be re-seeded on restart (check your port)

**Where:** the server start/stop lifecycle.

Global packets — the packets a server sends before a client occupies a slot, i.e.
_connection challenge_ and _connection denied_ — are encrypted with the same
per-connect-token server-to-client key as per-client packets, whose sequence numbers
start at zero. To keep the AEAD nonces disjoint under that shared key, the server's
global sequence number starts at `1 << 63`, the top half of the sequence space.

The reference implementation applied that seed only in `netcode_server_create`, and
`netcode_server_stop` reset the global sequence to zero. A server object that was
stopped and then started again sent challenge packets from global sequence 0, 1, 2 ...
— inside the per-client sequence space. Once a client connected, the server encrypted
two different plaintexts (a challenge packet and a keep-alive or payload packet) with
the same key and the same nonce, which voids the confidentiality and authenticity
guarantees of the AEAD for those packets.

The fix is to seed the global sequence in server start as well as create, so the
invariant holds for every running lifetime of the server object. Not a wire format
change — the sequence seed is server-local behavior. Fixed here in commit `dc21b70`,
pinned by `test_server_restart_global_sequence`. Ports that copied the create/stop
behavior from this codebase should check what their restart path does to the global
sequence. Found while porting netcode to Rust
([netcode.rs](https://github.com/mas-bandwidth/netcode.rs), which seeds on start).

## Reporting back

If you maintain a netcode implementation and confirm (or refute) any of the above in your
port, an issue or PR on this repo is welcome so this file can track which implementations
are known-good.
