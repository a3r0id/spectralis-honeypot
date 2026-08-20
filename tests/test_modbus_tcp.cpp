#include <cstdint>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "honeypot/modbus_tcp.hpp"
#include "honeypot/protocol.hpp"

using honeypot::ProtocolHandler;

namespace {

std::shared_ptr<ProtocolHandler> proto() {
    return honeypot::make_modbus_tcp_protocol();
}

// Read Holding Registers: txn=1, unit=1, addr=0, qty=2
const std::vector<uint8_t> kReadHolding = {
    0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
    0x01, 0x03, 0x00, 0x00, 0x00, 0x02,
};

}  // namespace

TEST(ModbusTcp, FramesCompleteRequest) {
    auto p = proto();
    size_t frame_len = 0;
    EXPECT_EQ(p->try_frame(kReadHolding, frame_len), ProtocolHandler::FrameStatus::Complete);
    EXPECT_EQ(frame_len, kReadHolding.size());
}

TEST(ModbusTcp, NeedsMoreWhenShort) {
    auto p = proto();
    std::vector<uint8_t> partial(kReadHolding.begin(), kReadHolding.begin() + 8);
    size_t frame_len = 0;
    EXPECT_EQ(p->try_frame(partial, frame_len), ProtocolHandler::FrameStatus::NeedMore);
}

TEST(ModbusTcp, RejectsNonZeroProtocolId) {
    auto p = proto();
    std::vector<uint8_t> bad = kReadHolding;
    bad[3] = 0x01;
    size_t frame_len = 0;
    EXPECT_EQ(p->try_frame(bad, frame_len), ProtocolHandler::FrameStatus::NotThisProtocol);
}

TEST(ModbusTcp, RepliesToReadHoldingRegisters) {
    auto p = proto();
    const auto resp = p->handle(kReadHolding.data(), kReadHolding.size());
    ASSERT_GE(resp.size(), 9u);
    EXPECT_EQ(resp[0], 0x00);
    EXPECT_EQ(resp[1], 0x01);
    EXPECT_EQ(resp[7], 0x03);  // function
    EXPECT_EQ(resp[8], 0x04);  // 2 registers * 2 bytes
}

TEST(ModbusTcp, IllegalFunctionException) {
    auto p = proto();
    std::vector<uint8_t> req = {
        0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
        0x01, 0x99,
    };
    const auto resp = p->handle(req.data(), req.size());
    ASSERT_EQ(resp.size(), 9u);
    EXPECT_EQ(resp[7], static_cast<uint8_t>(0x99 | 0x80));
    EXPECT_EQ(resp[8], 0x01);
}
