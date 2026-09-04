# A consumer of an installed netcode, built against a clean prefix in CI. It proves the
# install is complete: the package is found by find_package, the header is where the target
# says it is, and the library brings its own crypto to the link line.

cmake_minimum_required(VERSION 3.16)

project(netcode_consumer LANGUAGES C)

find_package(netcode CONFIG REQUIRED)

add_executable(consumer consumer.c)

target_link_libraries(consumer PRIVATE netcode::netcode)
