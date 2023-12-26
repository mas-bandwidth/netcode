How to build netcode
====================

## Building on Windows

Download [premake 5](https://premake.github.io/download.html) and copy the **premake5** executable somewhere in your path.

You need Visual Studio to build the source code. If you don't have Visual Studio you can [download the community edition for free](https://visualstudio.microsoft.com/downloads/).

Once you have Visual Studio installed, go to the command line under the netcode directory and type:

    premake5 vs2019

Open the generated netcode.sln file.

Now you can build the library and run individual test programs as you would for any other Visual Studio solution.

## Building on MacOS and Linux

First, download and install [premake 5](https://premake.github.io/download.html).

Next, install libsodium.

Linux:

    sudo apt install libsodium-dev

Mac:

    brew install libsodium

Now go to the command line under the netcode directory and enter:

    premake5 gmake

Which creates makefiles which you can use to build the source via:

    make -j

Then you can run binaries like this:

    ./bin/test
    ./bin/server
    ./bin/client

If you have questions please create an issue at https://github.com/mas-bandwidth/netcode and I'll do my best to help you out.

cheers

 - Glenn
