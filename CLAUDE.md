# CLAUDE.md

## What this is

netcode is a secure connection-oriented protocol over UDP for multiplayer games:
connect-token authentication against a trusted backend, challenge/response handshake,
encrypted/signed packets via libsodium, client slots, keep-alives, timeouts, and clean
disconnect. The protocol is specified in STANDARD.md (netcode 1.02) and has multiple
independent implementations (C#, Go, Rust, TypeScript).

- `netcode.h` / `netcode.c` — the entire library. `netcode.c` is ~9,300 lines: ~5,400
  of implementation and ~3,900 of tests gated behind `NETCODE_ENABLE_TESTS`.
- `client.c`, `server.c`, `client_server.c`, `soak.c`, `profile.c` — examples and harnesses.
- `sodium/` — vendored subset of libsodium, amalgamated into a single `sodium.h` +
  `sodium.c` pair (see `sodium/NOTES.md` for how it is generated and validated).
- Build: CMake. `cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel`,
  then `ctest --test-dir build --output-on-failure` runs the suite (42 tests). The
  `netcode_test` target compiles netcode.c into itself with `NETCODE_ENABLE_TESTS`, so it
  links only sodium. `-DNETCODE_SANITIZE=ON` adds ASan+UBSan (sodium gets ASan only);
  `-DNETCODE_FUZZ=ON` builds the `fuzz/` harnesses (libFuzzer where available, else a
  standalone file replayer). For packaging: `-DNETCODE_SYSTEM_SODIUM=ON` links the
  system libsodium instead of the vendored copy, `-DBUILD_SHARED_LIBS=ON` builds
  libnetcode shared, and `cmake --install` installs netcode.h + the library
  (this is the homebrew configuration, covered by a CI leg). CI (`.github/workflows/ci.yml`) builds and tests Debug +
  Release on Linux x64, Linux arm64, macOS Apple Silicon, and Windows x64 (MSVC + a
  MinGW leg), plus a Linux ASan+UBSan leg and a bounded smoke-fuzz leg. A separate
  nightly workflow (`.github/workflows/scheduled.yml`) runs deep fuzzing with an
  accumulating cached corpus, a 15-minute ASan soak, and a libsodium-upstream-release
  check that opens a tracking issue when the vendored version falls behind.
- `fuzz/` — fuzz harnesses over the untrusted-input surface (`netcode_read_packet`, the
  connect token readers, `netcode_parse_address`), each with write/read round-trip
  invariants, plus a checked-in seed corpus under `fuzz/corpus/`. See `fuzz/README.md`.
- `IMPLEMENTERS.md` — findings other-language ports should check against (the
  replay-protection overflow, the STANDARD.md errata).

## Honest assessment

### The short version

This is a mature, disciplined, security-conscious C library that does exactly one thing
and does it well. The protocol design is its strongest asset. The weaknesses called out
by earlier passes of this assessment — thin error reporting, internal duplication,
assert-only input validation, per-packet allocation — have each been either fixed or
documented below as deliberate design. What remains is one genuinely external step —
OSS-Fuzz enrollment for continuous rather than nightly-bounded fuzzing — and the inherent
contribution cost of a single ~9,300-line file, a deliberate style choice that trades
contribution ergonomics for trivial integration.

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
touching real sockets. Few networking libraries ship this complete a test story: 42
unit + integration tests covering every client error state, reconnect, multi-server
fallback, dual-stack, loopback — plus a soak test and a profiler. All pass today.

**The API is small and honest.** Opaque structs, create/update/destroy lifecycle,
explicit `netcode_client_update(client, time)` — time is injected, not sampled, which
makes the state machines testable and frame-loop friendly. The header is a clean ~300
lines with zero dependencies beyond stdint.

**Error reporting matches the transport's nature.** Asynchronous connection failures
(denial, timeouts, token problems) surface through the client's negative
`NETCODE_CLIENT_STATE_*` values polled from the game loop — the only channel that can
carry errors that happen seconds after the call that caused them. Create failures are
queryable: `netcode_client_create_error()` / `netcode_server_create_error()` report why
create returned NULL, with server bind failures (port already in use — the common
operational failure) distinguished from other socket errors per address family.
Per-packet socket errors are deliberately ignored: UDP is unreliable, so a send error
is semantically identical to a dropped packet, and a persistently dead socket surfaces
the same way persistent loss does — as a connection timeout through the state machine.
The running server deliberately has no state machine of its own: its only states are
stopped and started (`netcode_server_running`), and everything else is per-client.

### What's not so good

**Allocation is the integrator's contract.** Every allocation inside the library goes
through the allocator hooks in the client/server config. Per-packet allocation on the
receive path is by design: games that care are expected to supply an allocator whose
alloc and free are cheap and don't call out to the OS (a pool or arena), and that is
how shipped games actually use it — yojimbo, the author's higher-level library built on
netcode, provides its own allocator through these exact hooks. The library defines
*where* allocations happen; the application decides *how fast* they are. The default
malloc/free is a convenience for getting started, not the intended production
configuration.

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
test_network_simulator_determinism; `netcode_client_create_error()` and
`netcode_server_create_error()` report why create returned NULL, with server bind
failures distinguished per address family; the internal duplication that used to be the
biggest code-quality issue is consolidated — `netcode_server_process_packet` delegates
to the shared read-and-process path, the client receive loops feed
`netcode_client_process_packet`, sockaddr conversion and simulator/override/socket send
dispatch are single helpers, and client slot reset is shared between the disconnect
paths, for a net −116 lines with no public header or wire change; the server re-seeds
its global packet sequence to `1ULL << 63` in `netcode_server_start`, not just in
create — `netcode_server_stop` zeroes it, so a stopped-and-restarted server used to
send challenge packets from sequence 0 and reuse AEAD nonces against per-client packets
under the same per-token key — pinned by test_server_restart_global_sequence and
written up as finding 3 in IMPLEMENTERS.md.)

**Process.** CI builds and tests every push across Linux x64, Linux arm64, macOS Apple
Silicon, and Windows (MSVC + MinGW) in Debug and Release, runs an ASan+UBSan leg, and
smoke-fuzzes the parsing surface. A nightly workflow adds deep fuzzing with a cached
accumulating corpus, a 15-minute ASan soak, and a libsodium-release watch that files a
tracking issue when the vendored subset falls behind upstream — which is the one real
liability of vendoring (decoupling from upstream security updates; that plus symbol
collision risk if the host app links its own libsodium are the price of trivially
reliable builds). The remaining process step that is genuinely external is OSS-Fuzz
enrollment — the harnesses are already libFuzzer-shaped, so it is mostly a submission to
google/oss-fuzz — which would turn the nightly bounded run into continuous coverage.

### Verdict

As a protocol and reference implementation, this is top-tier work — the threat model is
correct, the crypto usage is careful, the tests actually exercise the state machines,
and the operational details reflect someone who has shipped real multiplayer games.