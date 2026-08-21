#include <cstdlib>
#include <sstream>

#include <gtest/gtest.h>

#include "honeypot/cli.hpp"
#include "honeypot/device_registry.hpp"

using honeypot::parse_args;

namespace {

void clear_honeypot_env() {
    unsetenv("HONEYPOT_PORT");
    unsetenv("HONEYPOT_BIND_ADDR");
    unsetenv("HONEYPOT_PLC_TYPE");
    unsetenv("HONEYPOT_DEVICE");
}

}

TEST(Cli, DefaultsWithoutArgs) {
    clear_honeypot_env();
    char arg0[] = "honeypot";
    char* argv[] = {arg0};
    const auto args = parse_args(1, argv);
    EXPECT_TRUE(args.success);
    EXPECT_FALSE(args.help);
    EXPECT_FALSE(args.list);
    EXPECT_EQ(args.port, 102);
    EXPECT_EQ(args.bind_addr, "0.0.0.0");
    EXPECT_EQ(args.device, "S7-200");
}

TEST(Cli, ReadsEnvironment) {
    clear_honeypot_env();
    setenv("HONEYPOT_PORT", "10200", 1);
    setenv("HONEYPOT_BIND_ADDR", "127.0.0.1", 1);
    setenv("HONEYPOT_DEVICE", "S7-300", 1);

    char arg0[] = "honeypot";
    char* argv[] = {arg0};
    const auto args = parse_args(1, argv);
    EXPECT_TRUE(args.success);
    EXPECT_EQ(args.port, 10200);
    EXPECT_EQ(args.bind_addr, "127.0.0.1");
    EXPECT_EQ(args.device, "S7-300");

    clear_honeypot_env();
}

TEST(Cli, PlcTypeEnvBackCompat) {
    clear_honeypot_env();
    setenv("HONEYPOT_PLC_TYPE", "s7-400", 1);

    char arg0[] = "honeypot";
    char* argv[] = {arg0};
    const auto args = parse_args(1, argv);
    EXPECT_TRUE(args.success);
    EXPECT_EQ(args.device, "S7-400");

    clear_honeypot_env();
}

TEST(Cli, CliOverridesEnvironment) {
    clear_honeypot_env();
    setenv("HONEYPOT_PORT", "10200", 1);

    char arg0[] = "honeypot";
    char arg1[] = "2048";
    char arg2[] = "10.0.0.1";
    char arg3[] = "M221";
    char* argv[] = {arg0, arg1, arg2, arg3};
    const auto args = parse_args(4, argv);
    EXPECT_TRUE(args.success);
    EXPECT_EQ(args.port, 2048);
    EXPECT_EQ(args.bind_addr, "10.0.0.1");
    EXPECT_EQ(args.device, "M221");

    clear_honeypot_env();
}

TEST(Cli, CanonicalizesDeviceCase) {
    clear_honeypot_env();
    char arg0[] = "honeypot";
    char arg1[] = "102";
    char arg2[] = "0.0.0.0";
    char arg3[] = "s7-200";
    char* argv[] = {arg0, arg1, arg2, arg3};
    const auto args = parse_args(4, argv);
    EXPECT_TRUE(args.success);
    EXPECT_EQ(args.device, "S7-200");
}

TEST(Cli, HelpFlag) {
    clear_honeypot_env();
    char arg0[] = "honeypot";
    char arg1[] = "--help";
    char* argv[] = {arg0, arg1};
    const auto args = parse_args(2, argv);
    EXPECT_TRUE(args.success);
    EXPECT_TRUE(args.help);
}

TEST(Cli, ListFlag) {
    clear_honeypot_env();
    char arg0[] = "honeypot";
    char arg1[] = "--list";
    char* argv[] = {arg0, arg1};
    const auto args = parse_args(2, argv);
    EXPECT_TRUE(args.success);
    EXPECT_TRUE(args.list);
}

TEST(Cli, RejectsBadDevice) {
    clear_honeypot_env();
    char arg0[] = "honeypot";
    char arg1[] = "102";
    char arg2[] = "0.0.0.0";
    char arg3[] = "s7-999";
    char* argv[] = {arg0, arg1, arg2, arg3};
    const auto args = parse_args(4, argv);
    EXPECT_FALSE(args.success);
}

TEST(DeviceRegistry, ListsBuiltinDevices) {
    honeypot::ensure_builtin_devices();
    std::ostringstream oss;
    honeypot::print_device_list(oss);
    const std::string text = oss.str();
    EXPECT_NE(text.find("S7-200"), std::string::npos);
    EXPECT_NE(text.find("M221"), std::string::npos);
    EXPECT_NE(text.find("Modicon"), std::string::npos);
}
