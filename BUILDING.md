How to build netcode.io
=======================

## Building on Windows

Download [premake 5](https://premake.github.io/download.html) and copy the **premake5** executable somewhere in your path. Please make sure you have at least premake5 alpha 13.

You need Visual Studio to build the source code. If you don't have Visual Studio 2015 you can [download the community edition for free](https://www.visualstudio.com/en-us/downloads/download-visual-studio-vs.aspx).

Once you have Visual Studio installed, go to the command line under the netcode.io/c directory and type:

    premake5 solution

This creates netcode.sln and opens it in Visual Studio for you.

Now you can build the library and run individual test programs as you would for any other Visual Studio solution.

## Building on MacOS and Linux

First, download and install [premake 5](https://premake.github.io/download.html) alpha 13 or greater.

Next, install libsodium.

On MacOS X, this can be done most easily with `brew install libsodium`. 

If you don't have Brew, you can install it from <http://brew.sh>.

On Linux, depending on your particular distribution there may be prebuilt packages for libsodium, or you may have to build from source from here [libsodium](https://github.com/jedisct1/libsodium/releases).

Now go to the command line under the netcode.io/c directory and enter:

    premake5 gmake

Which creates makefiles which you can use to build the source via:

    make all

Alternatively, you can use the following shortcuts to build and run test programs directly:

    premake5 test           // build and run unit tests

    premake5 server         // build run a netcode.io server on localhost on UDP port 40000

    premake5 client         // build and run a netcode.io client that connects to the server running on localhost 

    premake5 stress         // connect 256 netcode.io clients to a running server as a stress test
   
If you have questions please create an issue at http://www.netcode.io and I'll do my best to help you out.

cheers

 - Glenn
