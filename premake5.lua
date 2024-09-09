
solution "netcode"
    kind "ConsoleApp"
    language "C"
    configurations { "Debug", "Release" }
    includedirs { "sodium" }
    targetdir "bin/"
    rtti "Off"
    warnings "Extra"
    flags { "FatalWarnings" }
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
    language "C"
    files {
        "sodium/**.c",
        "sodium/**.h",
    }
    filter { "system:not windows", "platforms:*x64 or *avx or *avx2" }
        files {
            "sodium/**.S"
        }
    filter { "action:gmake*" }
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
