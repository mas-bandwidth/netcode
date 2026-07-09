# CLAUDE.md

## What this is

netcode is a secure connection-oriented protocol over UDP for multiplayer games:
connect-token authentication against a trusted backend, challenge/response handshake,
encrypted/signed packets via libsodium, client slots, keep-alives, timeouts, and clean
disconnect. The protocol is specified in STANDARD.md (netcode 1.02) and has multiple
independent implementations (C#, Go, Rust, TypeScript).

- `netcode.h` / `netcode.c` — the entire library. `netcode.c` is ~8,800 lines: ~5,300
  of implementation and ~3,500 of tests gated behind `NETCODE_ENABLE_TESTS`.
- `client.c`, `server.c`, `client_server.c`, `soak.c`, `profile.c` — examples and harnesses.
- `sodium/` — vendored subset of libsodium, amalgamated into a single `sodium.h` +
  `sodium.c` pair (see `sodium/NOTES.md` for how it is generated and validated).
- Build: CMake. `cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel`,
  then `ctest --test-dir build --output-on-failure` runs the suite (40 tests). The
  `netcode_test` target compiles netcode.c into itself with `NETCODE_ENABLE_TESTS`, so it
  links only sodium. `-DNETCODE_SANITIZE=ON` adds ASan+UBSan (sodium gets ASan only);
  `-DNETCODE_FUZZ=ON` builds the `fuzz/` harnesses (libFuzzer where available, else a
  standalone file replayer). CI (`.github/workflows/ci.yml`) builds and tests Debug +
  Release on Linux x64, macOS Apple Silicon, and Windows x64, plus a Linux ASan+UBSan
  leg and a bounded smoke-fuzz leg.
- `fuzz/` — fuzz harnesses over the untrusted-input surface (`netcode_read_packet`, the
  connect token readers, `netcode_parse_address`), each with write/read round-trip
  invariants. See `fuzz/README.md`.

## Honest assessment

### The short version

This is a mature, disciplined, security-conscious C library that does exactly one thing
and does it well. The protocol design is its strongest asset. The main weaknesses are
maintainability of the single-file implementation (internal duplication) and error
reporting that goes quiet at creation time and on the server side — the client's
state machine covers connection errors well, but create returning NULL and the server
API tell the integrator nothing about why something failed.

### What's genuinely good

**The protocol design is the real product, and it's excellent.** Authentication is
delegated to a trusted backend via encrypted connect tokens, so the server never has to
trust the network. The security details are handled with visible care:

- AEAD everywhere, with version info, protocol id, and the packet prefix byte bound as
  associated data — you can't transplant ciphertext across packet types or protocol
  versions (`netcode_write_packet`, netcode.c:1606).
- Nonce-space separation: server global packets start sequence at `1ULL << 63`
  (netcode.c:3940) so pre-connection and per-client packet nonces can't collide under a
  shared key.
- Replay protection does a cheap pre-decrypt rejection of stale sequence numbers, but only
  advances the window *after* authentication succeeds (netcode.c:1863, 1907) — plaintext
  sequence numbers can't be spoofed to poison the window. This is the correct fix for the
  vulnerability class credited in the README.
- Connect-token single-use tracking is a deliberately constant-time worst-case scan, and
  says so in a comment (netcode.c:3701).
- Per-packet address lookups (`netcode_server_find_client_index_by_address`, the
  encryption mapping search) are deliberately flat linear scans, not hash maps. A hash
  was considered and rejected: netcode targets ~100 players or fewer per server, and an
  attacker who controls the keys (source addresses) can drive a hash table into
  worst-case behavior, while a linear scan over small n is predictable — slower in the
  best case, but with no attacker-controllable worst case. Same philosophy as the
  connect-token scan above.
- The challenge/response step defeats source-address spoofing, and "server is full" is
  only revealed after the token decrypts — no free oracle for random scanners.
- Every read path length-checks before it touches or allocates anything; connection
  requests must be *exactly* the right size (netcode.c:1722).

**The engineering shows production scars.** `SIO_UDP_CONNRESET` on Windows so a
hard-disconnecting client doesn't wedge `recvfrom` (netcode.c:554), `IPV6_V6ONLY`,
4MB socket buffers, DSCP packet tagging with a documented MinGW/Qwave workaround, true
dual-stack IPv4+IPv6 sockets, loopback clients for integrated host-and-play, allocator
override hooks, and full send/receive transport overrides. A built-in network simulator
(latency/jitter/loss/duplication) makes the connection tests deterministic without
touching real sockets. Few networking libraries ship this complete a test story: 40
unit + integration tests covering every client error state, reconnect, multi-server
fallback, dual-stack, loopback — plus a soak test and a profiler. All pass today.

**The API is small and honest.** Opaque structs, create/update/destroy lifecycle,
explicit `netcode_client_update(client, time)` — time is injected, not sampled, which
makes the state machines testable and frame-loop friendly. The header is a clean ~300
lines with zero dependencies beyond stdint.

### What's not so good

**Internal duplication is the biggest code-quality issue.**
`netcode_server_process_packet` (netcode.c:4590) and
`netcode_server_read_and_process_packet` (netcode.c:4650) are near-identical ~55-line
functions; a fix applied to one has to be remembered in the other. The client builds the
same `allowed_packets` table and makes the same `netcode_read_packet` call in three
places (netcode.c:2976, 3011, 3082). The IPv4/IPv6 sockaddr conversion logic is repeated
in four spots. None of this is wrong, but it's the kind of duplication that breeds
divergence bugs — and the git history (e.g. "Fix soak and profile sending all server
packets to client 0") suggests it already has.

**Per-packet heap allocation.** Every accepted packet is malloc'd, and non-payload
packets are freed moments later after a switch statement reads one or two fields
(netcode.c:2966, 4587). The allocator hooks let integrators pool this away, but the
default behavior is allocation churn proportional to packet rate, and the internal
design (allocate → inspect → free) makes even keep-alives cost a round trip through the
allocator.

**Error reporting goes quiet outside the client state machine.** Client connection
errors are reported well: denial, timeouts, and token problems are asynchronous by
nature, and the negative `NETCODE_CLIENT_STATE_*` values polled from the game loop are
the right mechanism for them — that is by design, not a gap. Per-packet socket errors
being ignored (`sendto` results cast to void, `recvfrom` errors logged and dropped) is
also by design, not a gap: UDP is unreliable, so a send error is semantically identical
to a dropped packet, and the protocol must tolerate drops anyway. A persistently dead
socket surfaces the same way persistent packet loss does — as a connection timeout
through the state machine, which is the correct channel for an unreliable protocol.
The actual gaps are the places the state machine can't reach. Creation failures
collapse to NULL: a bad address string, a socket creation failure, and a bind failure
(the operationally common one — port already in use) are indistinguishable to the
caller, even though the internal `NETCODE_SOCKET_ERROR_*` codes (netcode.c:486)
enumerate exactly these cases before being discarded. And the server has no
state-machine equivalent at all — its failures reduce to `netcode_server_running()`
returning false with no why.

**Small sharp edges:**
- Global mutable state (log level, printf/assert hooks, the `netcode_init` reference
  count, static timers) means the library is single-threaded by design. The header now
  documents this at the top, but the state is still global.
- The real-socket connect tests advance virtual time while pumping real sockets; they
  sleep 10ms per iteration so OS packet delivery can keep up. Without that yield they
  are timing-sensitive on loaded CI runners (this bit once: macOS Release, run 28993111836).

(Fixed in July 2026: `atoi` port truncation now rejects invalid ports; the public
`netcode_assert` macro no longer force-exits, so a custom assert handler may choose to
continue; zero-byte payload sends are rejected at the API instead of silently vanishing
at the receiver; thread-safety expectations are documented in netcode.h; the
`NETCODE_ADDRESS_BUFFER_SAFETY` margin in `netcode_parse_address` is removed — port
parsing is validated and the indexing is guarded, verified by fuzz_parse_address under
ASan; the leftover void casts in `netcode_client_process_packet` are gone; public entry
points that take `max_clients`, a client index, or a loopback packet size now pair their
asserts with runtime bounds guards, so out-of-range values from the application can't
index past the per-client arrays in release builds — covered by test_runtime_guards,
which runs with a continuing assert handler so it exercises the guards in debug too;
`netcode_init`/`netcode_term` are reference counted, so multiple subsystems can init and
term independently; a zeroed client/server config gets default allocators instead of
crashing; the network simulator uses a per-instance seeded xorshift64* instead of global
`rand()`, so simulator runs are deterministic — pinned by
test_network_simulator_determinism.)

**Process gaps.** CI now builds and runs the tests on all three platforms in Debug and
Release, runs an ASan+UBSan leg, and smoke-fuzzes the parsing surface
(`netcode_read_packet`, the token readers, `netcode_parse_address`) — the biggest gaps
are closed. Remaining opportunities: continuous deep fuzzing (OSS-Fuzz) rather than a
bounded CI run, and a nightly soak leg. The vendored sodium subset makes builds trivially
reliable, at the cost of decoupling from upstream security updates and risking symbol
collisions if the host app links its own libsodium.

### Verdict

As a protocol and reference implementation, this is top-tier work — the threat model is
correct, the crypto usage is careful, the tests actually exercise the state machines,
and the operational details reflect someone who has shipped real multiplayer games.