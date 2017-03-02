Just some high level notes of things I come across so I don't forget them later.

Netcode:
- Callback for logs to connect to rust logger.
- More error codes for create/etc.
- Can we unify server_free_packet/client_free_packet?
- Do we have to allocate/free on each packet if we know the max length is 1200? Can we just pass a scratch buffer instead?
- Not totally clear what client index represents(is this client_id?)

Rust todo:
- Docs
- Doc tests
- Unit tests
- Need to handle platform-specific code via #ifdef in build.rs
- Need more robust libsodium search paths