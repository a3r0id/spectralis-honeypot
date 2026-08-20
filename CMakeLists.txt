cmake_minimum_required(VERSION 3.19)
project(spectralis-honeypot VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(HONEYPOT_BUILD_TESTS "Build unit tests" ON)

find_package(Threads REQUIRED)

add_library(honeypot
    src/cli.cpp
    src/constants.cpp
    src/device_registry.cpp
    src/ip_utils.cpp
    src/iso_on_tcp.cpp
    src/modbus_tcp.cpp
    src/net.cpp
    src/s7comm.cpp
    src/session_file.cpp
    src/sock_server.cpp
    src/unique_socket.cpp
)
add_library(honeypot::honeypot ALIAS honeypot)

target_include_directories(honeypot
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(honeypot PUBLIC cxx_std_17)
target_link_libraries(honeypot PUBLIC Threads::Threads)
target_compile_options(honeypot PRIVATE
    $<$<CONFIG:Debug>:-g;-O0;-Wall;-Wextra;-fno-omit-frame-pointer>
    $<$<CONFIG:Release>:-O2;-Wall;-Wextra>
)

add_executable(spectralis-honeypot src/main.cpp)
target_link_libraries(spectralis-honeypot PRIVATE honeypot::honeypot)
target_compile_options(spectralis-honeypot PRIVATE
    $<$<CONFIG:Debug>:-g;-O0;-Wall;-Wextra;-fno-omit-frame-pointer>
    $<$<CONFIG:Release>:-O2;-Wall;-Wextra>
)

include(CTest)
if(HONEYPOT_BUILD_TESTS AND BUILD_TESTING)
    add_subdirectory(tests)
endif()
