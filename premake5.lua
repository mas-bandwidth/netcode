
if os.is "windows" then
    debug_libs = { "sodium-debug" }
    release_libs = { "sodium-release" }
else
    debug_libs = { "sodium" }
    release_libs = debug_libs
end

solution "netcode"
    kind "ConsoleApp"
    language "C++"
    platforms { "x64" }
    configurations { "Debug", "Release" }
    if os.is "windows" then
        includedirs { ".", "./windows" }
        libdirs { "./windows" }
    else
        includedirs { ".", "/usr/local/include" }       -- for clang scan-build only. for some reason it needs this to work =p
        targetdir "bin/"  
    end
    rtti "Off"
    flags { "ExtraWarnings", "StaticRuntime", "FloatFast", "EnableSSE2" }
    configuration "Debug"
        symbols "On"
        links { debug_libs }
    configuration "Release"
        optimize "Speed"
        defines { "NDEBUG" }
        links { release_libs }
        
project "test"
    files { "test.c", "netcode.c" }

project "client"
    files { "client.c", "netcode.c" }
    defines { "NETCODE_ENABLE_TESTS=0" }

project "server"
    files { "server.c", "netcode.c" }
    defines { "NETCODE_ENABLE_TESTS=0" }

project "client_server"
    files { "client_server.c", "netcode.c" }
    defines { "NETCODE_ENABLE_TESTS=0" }

if os.is "windows" then

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

else

    -- MacOSX and Linux.
    
    newaction
    {
        trigger     = "test",
        description = "Build and run all unit tests",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j32 test" == 0 then
                os.execute "./bin/test"
            end
        end
    }

    newaction
    {
        trigger     = "client",
        description = "Build and run the client",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j32 client" == 0 then
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
            if os.execute "make -j32 server" == 0 then
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
            if os.execute "make -j32 client_server" == 0 then
                os.execute "./bin/client_server"
            end
        end
    }

    newaction
    {
        trigger     = "stress",
        description = "Launch 256 client instances to stress test the server",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j32 client" == 0 then
                for i = 0, 255 do
                    os.execute "./bin/client &"
                end
            end
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
            "xml"
        }

        for i,v in ipairs( directories_to_delete ) do
          os.rmdir( v )
        end

        if not os.is "windows" then
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
