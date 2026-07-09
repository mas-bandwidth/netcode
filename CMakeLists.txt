cmake_minimum_required(VERSION 3.16)

project(netcode LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# static MSVC runtime, matching the previous premake configuration
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

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

if(MSVC)
    add_compile_options(/fp:fast)
    set(NETCODE_WARNINGS /W4)
else()
    add_compile_options(-ffast-math)
    set(NETCODE_WARNINGS -Wall -Wextra)
endif()

# vendored libsodium subset. the SIMD variants guard themselves by target
# architecture, and the .S assembly files are not part of the build.

file(GLOB SODIUM_SOURCES CONFIGURE_DEPENDS sodium/*.c sodium/*.h)

add_library(sodium STATIC ${SODIUM_SOURCES})
target_include_directories(sodium PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/sodium)
if(NOT MSVC)
    target_compile_options(sodium PRIVATE
        -Wall -Wextra
        -Wno-unused-parameter
        -Wno-unused-function
        -Wno-unknown-pragmas
        -Wno-unused-variable
        -Wno-type-limits)
endif()

# the netcode library

add_library(netcode STATIC netcode.c netcode.h)
target_include_directories(netcode PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(netcode PRIVATE ${NETCODE_WARNINGS})
target_link_libraries(netcode PUBLIC sodium)
if(WIN32)
    target_link_libraries(netcode PUBLIC ws2_32 iphlpapi)
endif()

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

add_test(NAME netcode_test COMMAND netcode_test)
