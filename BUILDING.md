How to build netcode
====================

netcode builds with [CMake](https://cmake.org) (3.16 or later) on Windows, MacOS and Linux.

libsodium is vendored in this repository, so there is nothing else to install.

## Building on MacOS and Linux

Go to the command line under the netcode directory and enter:

    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel

Run the unit tests:

    ctest --test-dir build --output-on-failure

Then you can run binaries like this:

    ./build/bin/test
    ./build/bin/server
    ./build/bin/client

For a debug build, use `-DCMAKE_BUILD_TYPE=Debug` and a separate build directory, e.g. `-B build-debug`.

## Installing, shared libraries, and system libsodium

By default netcode builds as a static library against the vendored libsodium subset, and nothing needs to be installed. For packaging (e.g. homebrew), three options change that:

    cmake -B build -DCMAKE_BUILD_TYPE=Release \
        -DNETCODE_SYSTEM_SODIUM=ON \
        -DBUILD_SHARED_LIBS=ON
    cmake --build build --parallel
    cmake --install build --prefix /some/prefix

- `NETCODE_SYSTEM_SODIUM=ON` links the system libsodium instead of the vendored copy (they are interchangeable — the vendored subset is a byte-identical slice of upstream).
- `BUILD_SHARED_LIBS=ON` builds `libnetcode` as a shared library.
- `cmake --install` installs `netcode.h` and the library (`NETCODE_INSTALL=OFF` disables the install target, e.g. when embedding netcode as a subproject).

## Floating point: netcode builds with -ffp-contract=off

Estate policy for mas-bandwidth network libraries: builds are strict about floating point
contraction. This build sets the right flag on every target, so nothing is required of you to
build netcode itself:

  - GCC/Clang: `-ffp-contract=off`. Not merely the absence of `-ffast-math` — GCC's default
    is `-ffp-contract=fast`, which contracts across statement boundaries, and clang's default
    `=on` still fuses within a single expression.
  - MSVC: `/fp:precise`.

netcode's wire format carries no floating point, so no flag is required of consumers for
correct wire bytes today. The strict build is the family floor: contraction is
architecture-dependent (FMA is in the aarch64 baseline and absent from the x86-64 one), so
float arithmetic near a wire diverges bit-wise between architectures without it. If you
compile `netcode.c` into your own build rather than linking the library, carry the same flag.

## Sanitizers and fuzzing

To build everything with AddressSanitizer and UndefinedBehaviorSanitizer, configure with `-DNETCODE_SANITIZE=ON` and run the tests as usual:

    cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DNETCODE_SANITIZE=ON
    cmake --build build-asan --parallel
    ctest --test-dir build-asan --output-on-failure

Fuzz harnesses for the untrusted-input surface live in `fuzz/` and are built with `-DNETCODE_FUZZ=ON`. See [fuzz/README.md](fuzz/README.md) for details.

## Building on Windows

You need Visual Studio to build the source code. If you don't have Visual Studio you can [download the community edition for free](https://visualstudio.microsoft.com/downloads/).

Go to the command line under the netcode directory and type:

    cmake -B build
    cmake --build build --config Release

Run the unit tests:

    ctest --test-dir build --build-config Release --output-on-failure

Binaries are placed under `build\bin\Release` (or `build\bin\Debug` for `--config Debug`).

If you prefer working inside Visual Studio, open the generated `build\netcode.sln` and build and run the projects from there.

If you have questions please create an issue at https://github.com/mas-bandwidth/netcode and I'll do my best to help you out.

cheers

 - Glenn
