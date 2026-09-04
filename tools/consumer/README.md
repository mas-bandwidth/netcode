The consumer test
=================

A minimal program that links an installed netcode and calls `netcode_init`. CI installs
netcode to an empty prefix and builds this against it, in both the default vendored build
and the system libsodium build, so an install that is missing a header, a library, or the
crypto it needs to link fails the build.

To run it by hand:

    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel
    cmake --install build --prefix /tmp/netcode-prefix

    cmake -S tools/consumer -B /tmp/consumer-build -DCMAKE_PREFIX_PATH=/tmp/netcode-prefix
    cmake --build /tmp/consumer-build
    /tmp/consumer-build/consumer
