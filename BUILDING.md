How to build netcode
====================

## Building on Windows

Download [premake 5](https://premake.github.io/download.html) and copy the **premake5** executable somewhere in your path.

You need Visual Studio to build the source code. If you don't have Visual Studio you can [download the community edition for free](https://visualstudio.microsoft.com/downloads/).

Once you have Visual Studio installed, go to the command line under the netcode directory and type:

    premake5 solution

This creates netcode.sln and opens it in Visual Studio for you.

Now you can build the library and run individual test programs as you would for any other Visual Studio solution.

## Building on MacOS and Linux

First, download and install [premake 5](https://premake.github.io/download.html).

Now go to the command line under the netcode directory and enter:

    premake5 gmake

Which creates makefiles which you can use to build the source via:

    make

Then you can run binaries like this:

    ./bin/test
    ./bin/client
    ./bin/server

Alternatively, you can use the following shortcuts to build and run test programs directly:

    premake5 test           // build and run unit tests

    premake5 server         // build run a netcode server on localhost on UDP port 40000

    premake5 client         // build and run a netcode client that connects to the server running on localhost 
   
If you have questions please create an issue at https://github.com/networkprotocol/netcode and I'll do my best to help you out.

cheers

 - Glenn
