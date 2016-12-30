
if os.is "windows" then
    debug_libs = { "sodium-debug" }
    release_libs = { "sodium-release" }
else
    debug_libs = { "sodium" }
    release_libs = debug_libs
end

solution "speednet"
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
    files { "test.c" }
    links { "speednet" }

project "speednet"
    kind "StaticLib"
    files { "speednet.h", "speednet.c" }

if os.is "windows" then

    -- Windows

    newaction
    {
        trigger     = "solution",
        description = "Create and open the SPEEDNET solution",
        execute = function ()
            os.execute "premake5 vs2015"
            os.execute "start speednet.sln"
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
