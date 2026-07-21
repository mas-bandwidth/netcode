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

## What is NOT covered, and why

Encrypted packet bodies. Everything from the sequence number onward in packet
types >= 1 is AEAD-encrypted, so checking it would mean reimplementing
libsodium's xchacha20poly1305 against the same keys — which tests the crypto
library, not the specification. The plaintext framing is what an independent
implementation gets wrong, and that is what is covered here.

The client and server state machines are also unverified. They are specified in
STANDARD.md but they are behaviour over time rather than bytes on the wire, so
they belong in a behavioural test rather than here.
