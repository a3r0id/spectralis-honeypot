include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(honeypot_tests
    test_iso_on_tcp.cpp
    test_ip_utils.cpp
    test_cli.cpp
    test_modbus_tcp.cpp
)
target_link_libraries(honeypot_tests
    PRIVATE
        honeypot::honeypot
        GTest::gtest_main
)
target_compile_options(honeypot_tests PRIVATE -Wall -Wextra)

include(GoogleTest)
gtest_discover_tests(honeypot_tests)

# post build - run the tests
add_custom_command(TARGET honeypot_tests POST_BUILD
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
)
