# Security Policy

netcode implements an encrypted, connection-oriented protocol over UDP. It parses
untrusted data straight off the wire — packets, connect tokens, and the challenge
exchange — and it holds the keys, so we take memory-safety and protocol bugs seriously.

## Reporting a vulnerability

**Please do not report security issues in public GitHub issues or pull requests.**

Report privately through either channel:

- **GitHub private vulnerability reporting** (preferred): on this repository, go to the
  **Security** tab → **Report a vulnerability**. This opens a private advisory visible only
  to the maintainers.
- **Email**: glenn@mas-bandwidth.com.

Please include enough detail to reproduce: the affected component and version/commit, a
description of the flaw, and — where possible — a proof-of-concept input or a small patch.
Fuzzing crash artifacts (a crashing input file plus the target name) are ideal.

We will acknowledge your report, keep you updated on our assessment, and coordinate
disclosure timing with you. We prefer coordinated disclosure and will credit reporters who
wish to be named.

## Scope

In scope — bugs in this repository:

- the netcode library itself (`netcode.c`, `netcode.h`);
- the pruned **libsodium** subset under `sodium/` **as vendored** (e.g. an amalgamation or
  pruning mistake). Vulnerabilities in upstream libsodium itself should be reported to the
  [libsodium project](https://github.com/jedisct1/libsodium); we track upstream and pull in
  fixes — see `sodium/NOTES.md` for the review log.

Especially of interest: memory-safety issues (out-of-bounds read/write, use-after-free,
overflow) reachable from a received packet or connect token; and protocol flaws that let a
peer bypass authentication, encryption, or replay protection.

The protocol itself is specified in `STANDARD.md`. A flaw in the *specification* — as
opposed to this implementation of it — is in scope and is more valuable to us, because it
affects every implementation of netcode rather than one.

## Known issue: AEAD nonce reuse on unfinished handshakes and multi-server connect tokens (fixed in 1.5.0)

**Advisory: [GHSA-8mrq-q9c6-h23v](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-8mrq-q9c6-h23v)** (published 2026-11-19).

**Affected: netcode 1.4.10 and earlier (`NETCODE 1.02`). Fixed in 1.5.0 (`NETCODE 1.03`).**

In `NETCODE 1.02`, packets encrypted directly under the 32-byte `client_to_server_key` and
`server_to_client_key` carried inside a connect token, which allowed two AEAD nonce-reuse
paths within a single connect token's lifetime:

1. **Retried unfinished handshakes.** If a client received a connection challenge and sent
   one or more connection response packets that were lost (or aborted the handshake before a
   client slot was assigned), the server's connect token history entry remained _pending_. If
   the caller reconnected with the same unexpired connect token, the client reset its packet
   sequence to zero and encrypted new connection response packets under the same
   `client_to_server_key` at already-used nonces.
2. **Multi-server connect tokens.** When a connect token listed multiple dedicated servers,
   two freshly started servers shared the connect token's `server_to_client_key` and both
   began their global packet sequence at `2^63` (e.g. a full first server sending a
   connection denied packet at `2^63` and the next server sending a connection challenge
   packet at `2^63`).

Fixed in **1.5.0** by upgrading the wire protocol to **`NETCODE 1.03`**:

- Per-connection packet keys are derived via `HChaCha20(token_key, client_salt || server_nonce)`
  from a fresh 8-byte client salt per attempt (`connection request`, now 1086 bytes) and a
  fresh 8-byte server nonce per server mapping or full-server denial (`connection denied` and
  `connection challenge` headers, bound into 30-byte AEAD associated data). Connect token root
  keys never encrypt packets directly.
- Pending connect token history entries bind the 8-byte client salt and expire as admissible
  after `timeout_seconds` from creation; valid `connection disconnect` packets on a half-open
  mapping consume the history entry and remove the mapping.

Thank you to [@magicaldave](https://github.com/magicaldave) ([DreamWeave-MP/dream-net](https://github.com/DreamWeave-MP/dream-net)) for discovering and privately reporting the unfinished-handshake connect-token reuse issue.

### If you are using an affected version

Upgrade to **netcode 1.5.0** or later (`netcode.rs`, `netcode.go`, and `netcode.cs` **1.2.0**
or later; **yojimbo 1.16.0** or later). Because `NETCODE 1.03` changes the wire protocol
version string and handshake packet headers, clients, servers, and token-issuing backends must
be upgraded together.

## Known issue: connect token reuse after disconnect (fixed in 1.4.5)

**Advisory: [GHSA-v29p-3vj4-vg4f](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-v29p-3vj4-vg4f)** (published 2026-09-04).

**Affected: netcode 1.4.4 and earlier. Fixed in 1.4.5.**

A connect token that had already established a session could establish another one once that
client disconnected, and the second session encrypts under the same keys from a packet
sequence that starts over, so it repeats AEAD nonces.

Fixed by spending a connect token on the connection it admits, so a token the server has
accepted a client with is refused from then on
([`8eb9583`](https://github.com/mas-bandwidth/netcode/commit/8eb9583)), first released in
**1.4.5**.

### If you are using an affected version

Upgrade to 1.4.5 or later. There is no configuration that avoids this in an affected version.

**yojimbo** vendors netcode. A yojimbo release is affected if the netcode it carries is 1.4.4
or earlier — that is **yojimbo 1.12.0 and earlier**; yojimbo 1.12.1 was the first to vendor
netcode 1.4.5.

## Known issue: nonce reuse between global and per-client packets (fixed in 1.4.0)

**Advisory: [GHSA-3x95-24j9-7448](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-3x95-24j9-7448)** (published 2026-07-26; a CVE has been requested and is pending assignment).

**Affected: netcode 1.3.5 and earlier. Fixed in 1.4.0.**

Global packets (connection challenge, connection denied) encrypt with the same
per-connect-token server→client key as per-client packets. The server's global packet
sequence was seeded only when the server was *created*, not when it was *started*, so a
server that was stopped and started again could emit global packets at sequence numbers
already used under the same key. Since netcode uses the packet sequence as the AEAD nonce,
that is nonce reuse.

Fixed by re-seeding the global sequence on start as well as on create
([`dc21b70`](https://github.com/mas-bandwidth/netcode/commit/dc21b70)), first released in
**1.4.0**.

### If you are using an affected version

Upgrade to 1.4.0 or later. If you cannot, avoid restarting a server in-process; a fresh
process is unaffected because the sequence is seeded at creation.

### Where affected versions can still be obtained

We are recording these because we cannot remove them all, and a user has no other way to
find out:

- **Conan (legacy `center.conan.io`)** — serves `yojimbo/1.2.1`, which vendors an affected
  netcode. That remote is frozen: nobody, including us, can update or withdraw it.
- **Debian mentors** — has served `netcode 1.3.5+ds-1`. Only the uploading account can
  supersede it.

**Ports:** `netcode.go` carries a `retract [v1.0.0, v1.0.2]` directive in its `go.mod`, so
`go get` will warn. `netcode.rs` and the C library are fixed from 1.4.0 / 1.1.0 onward.

**yojimbo** vendors netcode. A yojimbo release is affected if the netcode it carries is
1.3.5 or earlier — that is **yojimbo 1.6.3 and earlier**; yojimbo 1.7.0 was the first to
vendor netcode 1.4.0.

## Supported versions

Security fixes land on the latest release. We do not backport to older release lines.
