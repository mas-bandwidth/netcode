# Notes for other netcode implementations

netcode has independent implementations in C#, Go, Rust, and TypeScript (linked from the
README). Most were ported from this C reference, so a defect or a documentation error
here tends to be present there too. This file collects the findings that other
implementations should check themselves against. Items 1–4 do not change the wire
protocol; item 5 upgrades the wire protocol from `NETCODE 1.02` to `NETCODE 1.03`.

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

## 4. Console builds must supply their own RNG (check your port)

**Where:** wherever your implementation gets its random bytes.

The C reference gets every key and nonce from libsodium's `randombytes_buf`. libsodium
ships no system RNG backend for the PlayStation platforms (`__ORBIS__` / `__PROSPERO__`):
its `randombytes_sysrandom_buf` there is a stub that leaves the buffer untouched, with no
build-time warning. A console build that takes the default backend therefore generates
keys from uninitialised memory.

**Exploitability:** total, on an affected build — the connect token keys are predictable
to whatever extent the uninitialised memory is. It is not reachable on any platform
netcode builds and tests on (Linux, macOS, Windows all have a real system RNG), so it is a
porting trap rather than a live defect. Documented here and in `sodium/NOTES.md`. If your
implementation targets a platform whose crypto library has a stubbed or weak default RNG,
check what it actually returns rather than assuming the call filled the buffer.

## 5. Protocol upgrade to `NETCODE 1.03`: per-connection key derivation (1.5.0)

**Where:** connect token version string, packet 0/1/2 framing, per-connection key derivation,
and server connect token history.

In `NETCODE 1.02`, packets were encrypted directly with the connect token's
`client_to_server_key` and `server_to_client_key`. That permitted AEAD nonce reuse in two
cases: (a) a client whose handshake timed out or was aborted after receiving a challenge
(having already encrypted connection responses from sequence 0) reconnecting with the same
unexpired connect token while the server's history entry was still _pending_, and (b) a
connect token naming multiple freshly started servers, each sending a pre-slot packet
(`connection denied` on server 1, `connection challenge` on server 2) at `global_sequence =
1 << 63` under the shared `server_to_client_key`.

`NETCODE 1.03` (`netcode` 1.5.0, `STANDARD.md`) eliminates both at the protocol level:

- **Version info** is `"NETCODE 1.03\0"` (13 bytes) in connect tokens, `connection request`
  packets, and AEAD associated data.
- **Per-connection key derivation (`HChaCha20`):** connect token keys never encrypt packets
  directly. Given `client_salt` (8 bytes) and `server_nonce` (8 bytes), let `input =
  client_salt || server_nonce` (16 bytes) and derive:
  - `packet_c2s_key = crypto_core_hchacha20(input, token_c2s_key, NULL)`
  - `packet_s2c_key = crypto_core_hchacha20(input, token_s2c_key, NULL)`
- **Packet 0 (`connection request`)** appends `client_salt[8]` (`1086` bytes total, up from
  `1078`). The client draws a fresh random `client_salt` on every connect call and every
  failover to the next server address in the connect token.
- **Packets 1 (`connection denied`) and 2 (`connection challenge`)** carry `server_nonce[8]`
  in cleartext immediately after the variable-length sequence number and before the encrypted
  payload, and append `server_nonce[8]` to AEAD associated data (`30` bytes total instead of
  `22`). Packets 3–6 are unchanged (`22`-byte associated data).
- **Client state machine:** in _sending connection request_, only packet types 1 and 2 are
  accepted (keyed per candidate `server_nonce`); once a valid `connection challenge` is
  received, `server_nonce` and both derived packet keys are locked in, further `connection
  challenge` packets are ignored, `connection denied` in _sending challenge response_ must
  match the recorded `server_nonce`, and `connection disconnect` packets are sent only once
  `server_nonce` has been established.
- **Server connect token history:** _pending_ entries bind `client_salt` (constant-time 8-byte
  comparison) and admit retransmissions only within `timeout_seconds` of entry creation (when
  `timeout_seconds > 0`); valid `connection disconnect` packets arriving on a half-open
  encryption mapping mark its history entry _consumed_ and remove the mapping.

Pinned by `test_derive_packet_keys_kat`, `test_wire_kat_vectors`, and the five `test_wire`
nonce-audit regression tests in `netcode.c`.

## Reporting back

If you maintain a netcode implementation and confirm (or refute) any of the above in your
port, an issue or PR on this repo is welcome so this file can track which implementations
are known-good.
