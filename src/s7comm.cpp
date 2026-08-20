#include "honeypot/s7comm.hpp"

#include "honeypot/iso_on_tcp.hpp"

namespace honeypot {
namespace {

class S7commProtocol final : public ProtocolHandler {
public:
    const char* name() const override { return "S7comm (RFC 1006)"; }

    FrameStatus try_frame(const std::vector<uint8_t>& pending, size_t& frame_len) const override {
        if (pending.size() < 4) {
            return FrameStatus::NeedMore;
        }
        if (!is_tpkt(pending.data(), pending.size())) {
            return FrameStatus::NotThisProtocol;
        }
        const uint16_t pkt_len = tpkt_length(pending.data());
        if (pkt_len < 4) {
            return FrameStatus::NotThisProtocol;
        }
        frame_len = pkt_len;
        if (pending.size() < frame_len) {
            return FrameStatus::NeedMore;
        }
        return FrameStatus::Complete;
    }

    std::vector<uint8_t> handle(const uint8_t* data, size_t len) const override {
        return handle_iso_on_tcp(data, len);
    }
};

}  // namespace

std::shared_ptr<ProtocolHandler> make_s7comm_protocol() {
    return std::make_shared<S7commProtocol>();
}

}  // namespace honeypot
