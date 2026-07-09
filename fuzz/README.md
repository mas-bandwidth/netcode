# netcode fuzzing

Fuzz harnesses for netcode's untrusted-input surface — the code paths that parse bytes
arriving off a socket or in a connect token from the backend:

- `fuzz_read_packet.c` — `netcode_read_packet`, the packet reader every client and server
  runs on received datagrams. Covers pre-decryption parsing and rejection, and (for
  packets it builds and encrypts with real keys) the post-decryption parsing plus a
  write/read round-trip invariant.
- `fuzz_connect_token.c` — the public and private connect token readers, plus a
  write/read round-trip over the private token.
- `fuzz_parse_address.c` — `netcode_parse_address`, plus a parse → to_string → parse
  round-trip.

## Build and run

Requires a compiler with libFuzzer (LLVM clang; AppleClang and GCC do not ship it):

```
CC=clang cmake -B build -DCMAKE_BUILD_TYPE=Debug -DNETCODE_SANITIZE=ON -DNETCODE_FUZZ=ON
cmake --build build --target fuzz_read_packet fuzz_connect_token fuzz_parse_address
./build/bin/fuzz_read_packet            # fuzz until a crash, or Ctrl-C
./build/bin/fuzz_read_packet -max_total_time=60   # bounded run, as CI does
```

## Reproducing a crash

libFuzzer writes the offending input to `crash-<sha>` (CI uploads these as the
`fuzz-crashes` artifact). Replay it with the same binary:

```
./build/bin/fuzz_read_packet crash-<sha>
```

On a compiler without libFuzzer the harnesses still build (with AddressSanitizer /
UndefinedBehaviorSanitizer where available) as a standalone replayer that takes input
files on the command line, so a crashing input can be reproduced anywhere:

```
CC=clang cmake -B build -DNETCODE_FUZZ=ON -DNETCODE_SANITIZE=ON   # or default cc
cmake --build build --target fuzz_read_packet
./build/bin/fuzz_read_packet crash-<sha> other-input.bin
```
