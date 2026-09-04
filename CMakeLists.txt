cmake_minimum_required(VERSION 3.16)

# A no-op build prints nothing (rowan-new#110). The per-target "Built target" lines are
# the only output a rebuild with nothing to do produces, and they carry no information; a
# real build still prints its [ x%] progress lines, and errors are untouched. This sits
# above project() because CMAKE_TARGET_MESSAGES initializes the TARGET_MESSAGES global
# property there and has no effect if set after it, and under the same top-level test as the
# NETCODE_TOP_LEVEL guard below, so a consumer that pulls this library in through FetchContent
# keeps its own messages.
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(CMAKE_TARGET_MESSAGES OFF)
endif()

project(netcode VERSION 1.4.5 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# is this the top level project, or pulled in via add_subdirectory / FetchContent?
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(NETCODE_TOP_LEVEL TRUE)
else()
    set(NETCODE_TOP_LEVEL FALSE)
endif()

# static MSVC runtime by default, matching the previous premake configuration. package
# managers (e.g. vcpkg) pass their own CMAKE_MSVC_RUNTIME_LIBRARY to match the CRT
# linkage their consumers expect.
if(NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# netcode.h selects debug/release behavior from these rather than NDEBUG
add_compile_definitions(
    $<$<CONFIG:Debug>:NETCODE_DEBUG>
    $<$<NOT:$<CONFIG:Debug>>:NETCODE_RELEASE>
)

# strict floating point. Estate policy for mas-bandwidth network libraries: "generally
# speaking, network libraries we work on require -ffp-contract=off" (Glenn, 2026-08-24).
#   - GCC/Clang: -ffp-contract=off. Not merely "no -ffast-math" -- GCC's default is
#     -ffp-contract=fast, which contracts across statements, and clang's default =on still
#     fuses within a single expression.
#   - MSVC: /fp:precise, which since VS 2022 does not imply contraction.
# netcode's wire format carries no floating point -- the floats here are connection stats
# and the network simulator -- so this is the family floor rather than a wire fix:
# contraction is architecture-dependent (FMA is in the aarch64 baseline and absent from
# the x86-64 one), so any float arithmetic that ever nears the wire diverges bit-wise
# between architectures without it. CI builds through this file, so every CI leg builds
# with these flags.
if(MSVC)
    add_compile_options(/fp:precise)
    set(NETCODE_WARNINGS /W4)
else()
    add_compile_options(-ffp-contract=off)
    set(NETCODE_WARNINGS -Wall -Wextra)
endif()

option(NETCODE_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(NETCODE_FUZZ "Build the fuzz targets" OFF)
option(NETCODE_BUILD_TESTS "Build netcode tests and examples" ${NETCODE_TOP_LEVEL})
option(NETCODE_SYSTEM_SODIUM "Link against the system libsodium instead of the vendored copy" OFF)
option(NETCODE_INSTALL "Generate the install target (netcode.h and the netcode library)" ON)
option(NETCODE_NONCE_AUDIT "Record the key and nonce of every packet the tests encrypt and fail on a repeat" OFF)

# netcode.h declares no export macro, so a Windows DLL built from these sources exports
# nothing and every consumer fails to link. Static is the supported shape on Windows: link
# the static library, or compile netcode.c straight into your application.

if(BUILD_SHARED_LIBS AND WIN32)
    message(FATAL_ERROR "netcode does not support shared library builds on Windows. Build the static library (the default), or compile netcode.c into your application.")
endif()

include(GNUInstallDirs)

# sanitizers apply to the whole build. the vendored crypto is exempted from UBSan
# below (third-party SIMD code uses intentional type punning / unaligned access that
# UBSan flags but is not netcode's to fix); it still gets AddressSanitizer.

if(NETCODE_SANITIZE)
    if(MSVC)
        add_compile_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

if(NETCODE_SYSTEM_SODIUM)

    # link the system libsodium (e.g. homebrew or apt) instead of the vendored copy.
    # the vendored subset is a byte-identical slice of upstream, so the two are
    # interchangeable. package managers prefer this so their libsodium supplies the
    # crypto and receives security updates.

    find_path(NETCODE_SODIUM_INCLUDE_DIR sodium.h REQUIRED)
    find_library(NETCODE_SODIUM_LIBRARY sodium REQUIRED)

    add_library(sodium INTERFACE)
    target_include_directories(sodium INTERFACE ${NETCODE_SODIUM_INCLUDE_DIR})
    target_link_libraries(sodium INTERFACE ${NETCODE_SODIUM_LIBRARY})

else()

    # vendored libsodium subset, amalgamated into a single header + source pair.
    # see sodium/NOTES.md for how it is generated and validated.

    add_library(sodium OBJECT sodium/sodium.c sodium/sodium.h)
    target_include_directories(sodium PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/sodium)
    set_target_properties(sodium PROPERTIES POSITION_INDEPENDENT_CODE ON)
    if(NOT MSVC)
        target_compile_options(sodium PRIVATE
            -Wall -Wextra
            -Wno-unused-parameter
            -Wno-unused-function
            -Wno-unknown-pragmas
            -Wno-unused-variable
            -Wno-type-limits)
        if(NETCODE_SANITIZE)
            target_compile_options(sodium PRIVATE -fno-sanitize=undefined)
        endif()
    endif()

endif()

# the netcode library. static by default; -DBUILD_SHARED_LIBS=ON builds it shared on the
# platforms that support it (the vendored sodium objects are position independent, so they
# fold in either way).
#
# in the default vendored build the sodium objects are compiled into libnetcode itself, so
# the installed library is self contained: a consumer links netcode and nothing else. the
# system-sodium build exports the libsodium it found instead, because that libsodium is the
# package manager's to supply and update.

if(NETCODE_SYSTEM_SODIUM)
    add_library(netcode netcode.c netcode.h)
    target_include_directories(netcode PRIVATE ${NETCODE_SODIUM_INCLUDE_DIR})
    target_link_libraries(netcode PUBLIC ${NETCODE_SODIUM_LIBRARY})
else()
    add_library(netcode netcode.c netcode.h $<TARGET_OBJECTS:sodium>)
    target_include_directories(netcode PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sodium)
endif()

target_include_directories(netcode PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_options(netcode PRIVATE ${NETCODE_WARNINGS})
set_target_properties(netcode PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
if(WIN32)
    target_link_libraries(netcode PUBLIC ws2_32 iphlpapi)
endif()

if(NETCODE_INSTALL)
    include(CMakePackageConfigHelpers)

    install(TARGETS netcode EXPORT netcodeTargets
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(FILES netcode.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    install(EXPORT netcodeTargets
            FILE netcodeTargets.cmake
            NAMESPACE netcode::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/netcode)

    configure_package_config_file(cmake/netcodeConfig.cmake.in
                                  ${CMAKE_CURRENT_BINARY_DIR}/netcodeConfig.cmake
                                  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/netcode)

    write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/netcodeConfigVersion.cmake
                                     VERSION ${PROJECT_VERSION}
                                     COMPATIBILITY SameMajorVersion)

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/netcodeConfig.cmake
                  ${CMAKE_CURRENT_BINARY_DIR}/netcodeConfigVersion.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/netcode)
endif()

if(NETCODE_BUILD_TESTS)

    # examples and long-running harnesses

    foreach(example client server client_server soak profile)
        add_executable(${example} ${example}.c)
        target_compile_options(${example} PRIVATE ${NETCODE_WARNINGS})
        target_link_libraries(${example} PRIVATE netcode)
    endforeach()

    # unit tests. test.cpp compiles netcode.c into itself with NETCODE_ENABLE_TESTS,
    # so it links sodium directly, not the netcode library. the target cannot be
    # named "test" (reserved by CTest) so the output name is set instead.

    enable_testing()

    add_executable(netcode_test test.cpp)
    set_target_properties(netcode_test PROPERTIES OUTPUT_NAME test)
    target_compile_options(netcode_test PRIVATE ${NETCODE_WARNINGS})
    target_link_libraries(netcode_test PRIVATE sodium)
    if(WIN32)
        target_link_libraries(netcode_test PRIVATE ws2_32 iphlpapi)
    endif()
    if(NETCODE_NONCE_AUDIT)
        target_compile_definitions(netcode_test PRIVATE NETCODE_ENABLE_NONCE_AUDIT=1)
    endif()

    add_test(NAME netcode_test COMMAND netcode_test)

endif()

# fuzz targets. each harness compiles netcode.c into itself (like the test runner)
# so it links sodium directly, not the netcode library.
#
# where the compiler ships libFuzzer (real LLVM clang) these are libFuzzer targets.
# elsewhere (AppleClang, GCC, MSVC) they build standalone with a main() that replays
# input files, so the harnesses compile and reproduce crashes everywhere -- CI can
# verify they build on all platforms even where it cannot fuzz.

if(NETCODE_FUZZ)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
    check_c_source_compiles("
        #include <stdint.h>
        #include <stddef.h>
        int LLVMFuzzerTestOneInput( const uint8_t * d, size_t s ) { (void) d; (void) s; return 0; }
    " NETCODE_HAVE_LIBFUZZER)
    unset(CMAKE_REQUIRED_FLAGS)

    foreach(fuzzer fuzz_read_packet fuzz_connect_token fuzz_parse_address)
        add_executable(${fuzzer} fuzz/${fuzzer}.c)
        target_include_directories(${fuzzer} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(${fuzzer} PRIVATE sodium)   # provides the sodium include dir, vendored or system
        if(WIN32)
            target_link_libraries(${fuzzer} PRIVATE ws2_32 iphlpapi)
        endif()

        if(NETCODE_HAVE_LIBFUZZER)
            target_compile_options(${fuzzer} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
            target_link_options(${fuzzer} PRIVATE -fsanitize=fuzzer,address,undefined)
        else()
            target_compile_definitions(${fuzzer} PRIVATE NETCODE_FUZZ_STANDALONE)
            if(NOT MSVC)
                target_compile_options(${fuzzer} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
                target_link_options(${fuzzer} PRIVATE -fsanitize=address,undefined)
            endif()
        endif()
    endforeach()
endif()
