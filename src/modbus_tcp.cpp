#include "honeypot/modbus_tcp.hpp"

namespace honeypot {
namespace {

uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

void write_be16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

bool looks_like_modbus(const std::vector<uint8_t>& pending) {
    if (pending.size() < 6) {
        return false;
    }
    // Protocol ID must be 0 for Modbus TCP.
    return read_be16(pending.data() + 2) == 0;
}

std::vector<uint8_t> exception_response(const uint8_t* req, size_t /*len*/, uint8_t code) {
    std::vector<uint8_t> resp;
    resp.insert(resp.end(), req, req + 4);  // txn + protocol
    write_be16(resp, 3);                    // unit + exception PDU
    resp.push_back(req[6]);                 // unit id
    resp.push_back(static_cast<uint8_t>(req[7] | 0x80));
    resp.push_back(code);
    return resp;
}

std::vector<uint8_t> handle_modbus_pdu(const uint8_t* data, size_t len) {
    if (len < 8) {
        return {};
    }

    const uint8_t unit = data[6];
    const uint8_t fn = data[7];
    std::vector<uint8_t> pdu;

    switch (fn) {
        case 0x01:  // Read Coils
        case 0x02:  // Read Discrete Inputs
            if (len < 12) {
                return exception_response(data, len, 0x03);  // illegal data value
            }
            {
                const uint16_t quantity = read_be16(data + 10);
                if (quantity < 1 || quantity > 2000) {
                    return exception_response(data, len, 0x03);
                }
                const uint8_t byte_count = static_cast<uint8_t>((quantity + 7) / 8);
                pdu = {fn, byte_count};
                pdu.insert(pdu.end(), byte_count, 0x00);
            }
            break;

        case 0x03:  // Read Holding Registers
        case 0x04:  // Read Input Registers
            if (len < 12) {
                return exception_response(data, len, 0x03);
            }
            {
                const uint16_t quantity = read_be16(data + 10);
                if (quantity < 1 || quantity > 125) {
                    return exception_response(data, len, 0x03);
                }
                const uint8_t byte_count = static_cast<uint8_t>(quantity * 2);
                pdu = {fn, byte_count};
                pdu.insert(pdu.end(), byte_count, 0x00);
            }
            break;

        case 0x05:  // Write Single Coil
        case 0x06:  // Write Single Register
            if (len < 12) {
                return exception_response(data, len, 0x03);
            }
            // Echo address + value (standard success response).
            pdu.assign(data + 7, data + 12);
            break;

        case 0x0F:  // Write Multiple Coils
        case 0x10:  // Write Multiple Registers
            if (len < 13) {
                return exception_response(data, len, 0x03);
            }
            // Echo address + quantity.
            pdu = {fn, data[8], data[9], data[10], data[11]};
            break;

        default:
            return exception_response(data, len, 0x01);  // illegal function
    }

    std::vector<uint8_t> resp;
    resp.insert(resp.end(), data, data + 4);  // txn + protocol
    write_be16(resp, static_cast<uint16_t>(1 + pdu.size()));
    resp.push_back(unit);
    resp.insert(resp.end(), pdu.begin(), pdu.end());
    return resp;
}

class ModbusTcpProtocol final : public ProtocolHandler {
public:
    const char* name() const override { return "Modbus TCP"; }

    FrameStatus try_frame(const std::vector<uint8_t>& pending, size_t& frame_len) const override {
        if (pending.size() < 6) {
            return FrameStatus::NeedMore;
        }
        if (!looks_like_modbus(pending)) {
            return FrameStatus::NotThisProtocol;
        }
        const uint16_t length = read_be16(pending.data() + 4);
        if (length < 2) {
            return FrameStatus::NotThisProtocol;
        }
        frame_len = static_cast<size_t>(6) + length;
        if (frame_len > 260) {
            return FrameStatus::NotThisProtocol;
        }
        if (pending.size() < frame_len) {
            return FrameStatus::NeedMore;
        }
        return FrameStatus::Complete;
    }

    std::vector<uint8_t> handle(const uint8_t* data, size_t len) const override {
        return handle_modbus_pdu(data, len);
    }
};

}  // namespace

std::shared_ptr<ProtocolHandler> make_modbus_tcp_protocol() {
    return std::make_shared<ModbusTcpProtocol>();
}

}  // namespace honeypot
