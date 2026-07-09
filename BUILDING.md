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
