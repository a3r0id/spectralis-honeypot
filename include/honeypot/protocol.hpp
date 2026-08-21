#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace honeypot {

// Transport/application protocol used by a mocked device (RFC 1006, Modbus TCP, …).
class ProtocolHandler {
public:
    enum class FrameStatus {
        Complete,         // frame_len is set; a full frame is ready
        NeedMore,         // looks like this protocol; wait for more bytes
        NotThisProtocol,  // buffer does not start with this protocol
    };

    virtual ~ProtocolHandler() = default;

    virtual const char* name() const = 0;

    // Inspect the start of `pending`. On Complete, set `frame_len` to the frame size.
    virtual FrameStatus try_frame(const std::vector<uint8_t>& pending,
                                  size_t& frame_len) const = 0;

    // Build a reply for one complete frame. Empty = log only, no reply.
    virtual std::vector<uint8_t> handle(const uint8_t* data, size_t len) const = 0;
};

}
