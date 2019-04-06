
if os.istarget "windows" then
    debug_libs = { "sodium-debug" }
    release_libs = { "sodium-release" }
else
    debug_libs = { "sodium" }
    release_libs = debug_libs
end

solution "netcode"
    kind "ConsoleApp"
    language "C"
    platforms { "x64" }
    configurations { "Debug", "Release" }
    if os.istarget "windows" then
        includedirs { ".", "./windows" }
        libdirs { "./windows" }
    else
        includedirs { ".", "/usr/local/include" }       -- for clang scan-build only. for some reason it needs this to work =p
        targetdir "bin/"  
    end
    rtti "Off"
    warnings "Extra"
    staticruntime "On"
    floatingpoint "Fast"
    vectorextensions "SSE2"
    configuration "Debug"
        symbols "On"
        links { debug_libs }
    configuration "Release"
        symbols "Off"
        optimize "Speed"
        defines { "NDEBUG" }
        links { release_libs }
    configuration { "gmake" }
        linkoptions { "-lm" }    

project "test"
    files { "test.cpp" }

project "soak"
    files { "soak.c", "netcode.c" }

project "profile"
    files { "profile.c", "netcode.c" }

project "client"
    files { "client.c", "netcode.c" }

project "server"
    files { "server.c", "netcode.c" }

project "client_server"
    files { "client_server.c", "netcode.c" }

if os.ishost "windows" then

    -- Windows

    newaction
    {
        trigger     = "solution",
        description = "Create and open the netcode.io solution",
        execute = function ()
            os.execute "premake5 vs2015"
            os.execute "start netcode.sln"
        end
    }

    -- todo: create shortcuts here too for windows for consistency

else

    -- MacOSX and Linux.
    
    newaction
    {
        trigger     = "test",
        description = "Build and run all unit tests",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j32 test" then
                os.execute "./bin/test"
            end
        end
    }

    newaction
    {
        trigger     = "soak",
        description = "Build and run soak test",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j32 soak" then
                os.execute "./bin/soak"
            end
        end
    }

    newaction
    {
        trigger     = "profile",
        description = "Build and run profile tet",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j32 profile" then
                os.execute "./bin/profile"
            end
        end
    }

    newaction
    {
        trigger     = "client",
        description = "Build and run the client",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j32 client" then
                os.execute "./bin/client"
            end
        end
    }

    newaction
    {
        trigger     = "server",
        description = "Build and run the server",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j32 server" then
                os.execute "./bin/server"
            end
        end
    }

    newaction
    {
        trigger     = "client_server",
        description = "Build and run the client/server testbed",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j32 client_server" then
                os.execute "./bin/client_server"
            end
        end
    }

    newaction
    {
        trigger     = "docker",
        description = "Build and run a netcode.io server inside a docker container",
        execute = function ()
            os.execute "docker run --rm --privileged alpine hwclock -s" -- workaround for clock getting out of sync on macos. see https://docs.docker.com/docker-for-mac/troubleshoot/#issues
            os.execute "rm -rf docker/netcode.io && mkdir -p docker/netcode.io && cp *.h docker/netcode.io && cp *.c docker/netcode.io && cp *.cpp docker/netcode.io && cp premake5.lua docker/netcode.io && cd docker && docker build -t \"networkprotocol:netcode.io-server\" . && rm -rf netcode.io && docker run -ti -p 40000:40000/udp networkprotocol:netcode.io-server"
        end
    }

    newaction
    {
        trigger     = "valgrind",
        description = "Run valgrind over tests inside docker",
        execute = function ()
            os.execute "rm -rf valgrind/netcode.io && mkdir -p valgrind/netcode.io && cp *.h valgrind/netcode.io && cp *.c valgrind/netcode.io && cp *.cpp valgrind/netcode.io && cp premake5.lua valgrind/netcode.io && cd valgrind && docker build -t \"networkprotocol:netcode.io-valgrind\" . && rm -rf netcode.io && docker run -ti networkprotocol:netcode.io-valgrind"
        end
    }

    newaction
    {
        trigger     = "stress",
        description = "Launch 256 client instances to stress test the server",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j32 client" then
                for i = 0, 255 do
                    os.execute "./bin/client &"
                end
            end
        end
    }

    newaction
    {
        trigger     = "cppcheck",
        description = "Run cppcheck over the source code",
        execute = function ()
            os.execute "cppcheck netcode.c"
        end
    }

    newaction
    {
        trigger     = "scan-build",
        description = "Run clang scan-build over the project",
        execute = function ()
            os.execute "premake5 clean && premake5 gmake && scan-build make all -j32"
        end
    }

    newaction
    {
        trigger     = "loc",
        description = "Count lines of code",
        execute = function ()
            os.execute "wc -l *.h *.c *.cpp"
        end
    }

end

newaction
{
    trigger     = "clean",

    description = "Clean all build files and output",

    execute = function ()

        files_to_delete = 
        {
            "Makefile",
            "*.make",
            "*.txt",
            "*.zip",
            "*.tar.gz",
            "*.db",
            "*.opendb",
            "*.vcproj",
            "*.vcxproj",
            "*.vcxproj.user",
            "*.vcxproj.filters",
            "*.sln",
            "*.xcodeproj",
            "*.xcworkspace"
        }

        directories_to_delete = 
        {
            "obj",
            "ipch",
            "bin",
            ".vs",
            "Debug",
            "Release",
            "release",
            "cov-int",
            "docs",
            "xml",
            "docker/netcode.io",
            "valgrind/netcode.io"
        }

        for i,v in ipairs( directories_to_delete ) do
          os.rmdir( v )
        end

        if not os.ishost "windows" then
            os.execute "find . -name .DS_Store -delete"
            for i,v in ipairs( files_to_delete ) do
              os.execute( "rm -f " .. v )
            end
        else
            for i,v in ipairs( files_to_delete ) do
              os.execute( "del /F /Q  " .. v )
            end
        end

    end
}
