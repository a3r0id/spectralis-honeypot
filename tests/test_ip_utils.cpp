#include <gtest/gtest.h>

#include "honeypot/ip_utils.hpp"

using honeypot::ip_in_cidr;
using honeypot::ip_to_uint32;
using honeypot::is_scanner_ip;
using honeypot::uint32_to_ip;

TEST(IpUtils, RoundTripIpv4) {
    EXPECT_EQ(ip_to_uint32("192.168.1.10"), 0xC0A8010Au);
    EXPECT_EQ(uint32_to_ip(0xC0A8010Au), "192.168.1.10");
}

TEST(IpUtils, RejectsInvalidIpv4) {
    EXPECT_EQ(ip_to_uint32("1.2.3"), 0u);
    EXPECT_EQ(ip_to_uint32("1.2.3.256"), 0u);
    EXPECT_EQ(ip_to_uint32("not-an-ip"), 0u);
}

TEST(IpUtils, CidrMembership) {
    EXPECT_TRUE(ip_in_cidr("207.90.244.10", "207.90.244.0/24"));
    EXPECT_FALSE(ip_in_cidr("207.90.245.10", "207.90.244.0/24"));
    EXPECT_TRUE(ip_in_cidr("199.45.154.1", "199.45.154.0/23"));
    EXPECT_TRUE(ip_in_cidr("199.45.155.1", "199.45.154.0/23"));
    EXPECT_FALSE(ip_in_cidr("199.45.156.1", "199.45.154.0/23"));
}

TEST(IpUtils, ExactMatchWithoutSlash) {
    EXPECT_TRUE(ip_in_cidr("10.0.0.1", "10.0.0.1"));
    EXPECT_FALSE(ip_in_cidr("10.0.0.2", "10.0.0.1"));
}

TEST(IpUtils, ScannerRanges) {
    EXPECT_TRUE(is_scanner_ip("207.90.244.50"));   // Shodan
    EXPECT_TRUE(is_scanner_ip("162.142.125.10"));  // Censys
    EXPECT_FALSE(is_scanner_ip("8.8.8.8"));
}
