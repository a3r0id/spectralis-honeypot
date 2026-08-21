#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "honeypot/iso_on_tcp.hpp"

using honeypot::build_cotp_cc;
using honeypot::cotp_pdu_type;
using honeypot::handle_iso_on_tcp;
using honeypot::is_tpkt;
using honeypot::tpkt_length;

namespace {

const std::vector<uint8_t> kCotpCr = {
    0x03, 0x00, 0x00, 0x16,
    0x11, 0xE0,
    0x00, 0x00,
    0x00, 0x01,
    0x00,
    0xC1, 0x02, 0x01, 0x00,
    0xC2, 0x02, 0x01, 0x02,
    0xC0, 0x01, 0x0A,
};

}

TEST(IsoOnTcp, DetectsTpkt) {
    EXPECT_TRUE(is_tpkt(kCotpCr.data(), kCotpCr.size()));
    EXPECT_EQ(tpkt_length(kCotpCr.data()), 0x16);
    EXPECT_EQ(cotp_pdu_type(kCotpCr.data(), kCotpCr.size()), 0xE0);
}

TEST(IsoOnTcp, RejectsNonTpkt) {
    const uint8_t junk[] = {0x01, 0x02, 0x03, 0x04};
    EXPECT_FALSE(is_tpkt(junk, sizeof(junk)));
    EXPECT_TRUE(handle_iso_on_tcp(junk, sizeof(junk)).empty());
}

TEST(IsoOnTcp, BuildsConnectionConfirm) {
    const auto cc = build_cotp_cc(kCotpCr.data(), kCotpCr.size());
    ASSERT_EQ(cc.size(), kCotpCr.size());
    EXPECT_EQ(cc[5] & 0xF0, 0xD0);
    EXPECT_EQ(cc[6], kCotpCr[8]);
    EXPECT_EQ(cc[7], kCotpCr[9]);
    EXPECT_EQ(cc[8], 0x00);
    EXPECT_EQ(cc[9], 0x01);
}

TEST(IsoOnTcp, HandleReturnsCcForCr) {
    const auto response = handle_iso_on_tcp(kCotpCr.data(), kCotpCr.size());
    ASSERT_FALSE(response.empty());
    EXPECT_EQ(response[5] & 0xF0, 0xD0);
}

TEST(IsoOnTcp, HandleRejectsLengthMismatch) {
    auto bad = kCotpCr;
    bad[3] = 0x20;  // claim longer than buffer
    EXPECT_TRUE(handle_iso_on_tcp(bad.data(), bad.size()).empty());
}

TEST(IsoOnTcp, BuildsS7SetupAck) {
    // TPKT + COTP DT + S7 Job Setup Communication (0xF0)
    const std::vector<uint8_t> setup = {
        0x03, 0x00, 0x00, 0x19,
        0x02, 0xF0, 0x80,
        0x32, 0x01, 0x00, 0x00,
        0x12, 0x34,        // PDU ref
        0x00, 0x08,        // param length
        0x00, 0x00,        // data length
        0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0,
    };

    const auto response = handle_iso_on_tcp(setup.data(), setup.size());
    ASSERT_FALSE(response.empty());
    ASSERT_GE(response.size(), 19u);
    EXPECT_EQ(response[0], 0x03);
    EXPECT_EQ(response[7], 0x32);   // S7
    EXPECT_EQ(response[8], 0x03);   // Ack_Data
    EXPECT_EQ(response[11], 0x12);  // echoed PDU ref
    EXPECT_EQ(response[12], 0x34);
}
