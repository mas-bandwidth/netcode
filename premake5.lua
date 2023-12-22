
solution "netcode"
    kind "ConsoleApp"
    language "C"
    configurations { "Debug", "Release" }
    includedirs { "sodium" }
    targetdir "bin/"
    rtti "Off"
    warnings "Extra"
    staticruntime "On"
    floatingpoint "Fast"
    filter "configurations:Debug"
        symbols "On"
        defines { "NETCODE_DEBUG" }
    filter "configurations:Release"
        symbols "Off"
        optimize "Speed"
        defines { "NETCODE_RELEASE" }

project "sodium"
    kind "StaticLib"
    files {
        "sodium/**.c",
        "sodium/**.h",
    }
    filter { "system:not windows", "platforms:*x64 or *avx or *avx2" }
        files {
            "sodium/**.S"
        }
    filter { "action:gmake" }
        buildoptions { "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-unknown-pragmas", "-Wno-unused-variable", "-Wno-type-limits" }

project "test"
    files { "test.cpp" }
    links { "sodium" }

project "soak"
    files { "soak.c", "netcode.c" }
    links { "sodium" }

project "profile"
    files { "profile.c", "netcode.c" }
    links { "sodium" }

project "client"
    files { "client.c", "netcode.c" }
    links { "sodium" }

project "server"
    files { "server.c", "netcode.c" }
    links { "sodium" }

project "client_server"
    files { "client_server.c", "netcode.c" }
    links { "sodium" }

if os.ishost "windows" then

    -- Windows

    newaction
    {
        trigger     = "solution",
        description = "Create and open the netcode solution",
        execute = function ()
            os.execute "premake5 vs2019"
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
            if os.execute "make -j test" then
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
            if os.execute "make -j client" then
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
            if os.execute "make -j server" then
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
            if os.execute "make -j client_server" then
                os.execute "./bin/client_server"
            end
        end
    }

    newaction
    {
        trigger     = "soak",
        description = "Build and run soak test",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j soak" then
                os.execute "./bin/soak"
            end
        end
    }

    newaction
    {
        trigger     = "profile",
        description = "Build and run profile",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j profile" then
                os.execute "./bin/profile"
            end
        end
    }

    newaction
    {
        trigger     = "stress",
        description = "Launch 256 client instances to stress test the server",
        execute = function ()
            os.execute "test ! -e Makefile && premake5 gmake"
            if os.execute "make -j client" then
                for i = 0, 255 do
                    os.execute "./bin/client &"
                end
            end
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
            "docker/netcode",
            "valgrind/netcode"
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
