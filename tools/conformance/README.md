# Conformance: STANDARD.md vs the implementation

`STANDARD.md` is the public protocol specification. Independent implementations
— including the Go and Rust ports — are written against it, so if it drifts
from `netcode.c` those implementations are wrong and nobody finds out.

This checks the two against each other. `gen_vectors.c` links the real library
and emits artifacts; `verify_standard.py` parses them using **only what
STANDARD.md says**, with no reference to netcode.c, and asserts every field.

    python3 tools/conformance/verify_standard.py

Exit 0 means the document and the code agree. A failure means one of them is
wrong — decide which, and fix that one.

## What is covered

* the 2048-byte connect token: every public field, both address forms, and the
  zero padding
* the packet prefix byte: type in the low 4 bits, sequence byte count in the high 4
* the variable-length sequence encoding, including that the byte count is
  **minimal** (high zero bytes omitted) and the little-endian order
* the challenge token's plaintext layout: client id, 256 bytes of user data,
  the zero pad to 300, and that the pad leaves room for the 16-byte HMAC

## The client state machine, separately

`verify_state_machine.py` checks the client state machine STANDARD.md specifies
— behaviour over time rather than bytes on the wire, so a different instrument.
It drives a real client and server through a full connection lifecycle over UDP,
records every state transition, and checks that:

* the initial state is *disconnected*;
* every observed transition is one the document permits (all ten states and
  their licensed transitions are transcribed into the checker);
* the happy path is exactly *disconnected -> sending connection request ->
  sending challenge response -> connected -> disconnected*;
* nothing reaches *connected* except from *sending challenge response* — the
  document admits exactly one route to the goal state;
* a connected, idle client produces **no** transitions at all;
* a clean disconnect ends in *disconnected* and never in an error state.

    python3 tools/conformance/verify_state_machine.py

## What is NOT covered, and why

Encrypted packet bodies. Everything from the sequence number onward in packet
types >= 1 is AEAD-encrypted, so checking it would mean reimplementing
libsodium's xchacha20poly1305 against the same keys — which tests the crypto
library, not the specification. The plaintext framing is what an independent
implementation gets wrong, and that is what is covered here.

The server-side connection process now has coverage too (drive_server.c):
baseline zero clients, a client connecting into a valid slot with its own id
visible to the server, num_connected tracking, no spurious idle change, and the
slot freeing on disconnect. What remains on the server side: multi-client slot
allocation (only one client is driven here) and server-side rejection paths.

ONE error path is now exercised: the connection-request timeout, provoked
deterministically by a token pointed at an address where nothing listens
(drive_error_paths.c). It confirms the machine takes the licensed failure route
— sending-request -> request-timed-out — rather than some other path.

Two error paths are now exercised: the connection-REQUEST timeout (dead
address) and INVALID_CONNECT_TOKEN (num_server_addresses corrupted to 0 — the
client rejects before it ever sends, and the driver self-verifies the byte
offset by asserting the pre-corruption value).

Three error states remain untaken, and honestly so: CONNECT_TOKEN_EXPIRED needs
wall-clock manipulation (generate_connect_token stamps real time, the drivers
run on simulated time); CONNECTION_DENIED and CONNECTION_RESPONSE_TIMED_OUT need
a server that rejects or goes silent mid-handshake. Worth adding when a
configurable test server exists.
