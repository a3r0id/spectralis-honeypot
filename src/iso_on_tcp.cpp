#include "honeypot/iso_on_tcp.hpp"

namespace honeypot {

bool is_tpkt(const uint8_t* data, size_t len) {
    return len >= 4 && data[0] == 0x03 && data[1] == 0x00;
}

uint16_t tpkt_length(const uint8_t* data) {
    return static_cast<uint16_t>((data[2] << 8) | data[3]);
}

uint8_t cotp_pdu_type(const uint8_t* data, size_t len) {
    if (len < 6) {
        return 0;
    }
    return data[5] & 0xF0;
}

std::vector<uint8_t> build_cotp_cc(const uint8_t* cr, size_t len) {
    if (len < 11) {
        return {};
    }
    std::vector<uint8_t> cc(cr, cr + len);
    cc[5] = 0xD0;  // Connection Confirm
    cc[6] = cr[8];  // dest-ref = client's src-ref
    cc[7] = cr[9];
    cc[8] = 0x00;  // our src-ref
    cc[9] = 0x01;
    return cc;
}

std::vector<uint8_t> build_s7_setup_ack(const uint8_t* s7, size_t s7_len) {
    if (s7_len < 18 || s7[0] != 0x32) {
        return {};
    }

    const uint8_t pdu_ref_hi = s7[4];
    const uint8_t pdu_ref_lo = s7[5];
    const uint8_t* params = s7 + 10;

    std::vector<uint8_t> resp = {
        0x03, 0x00, 0x00, 0x1B,  // TPKT
        0x02, 0xF0, 0x80,        // COTP DT
        0x32, 0x03, 0x00, 0x00,  // S7 Ack_Data
        pdu_ref_hi, pdu_ref_lo,
        0x00, 0x08,  // param length
        0x00, 0x00,  // data length
        0x00, 0x00   // error class / code
    };
    resp.insert(resp.end(), params, params + 8);
    return resp;
}

std::vector<uint8_t> handle_iso_on_tcp(const uint8_t* data, size_t len) {
    if (!is_tpkt(data, len) || tpkt_length(data) != len) {
        return {};
    }

    const uint8_t pdu = cotp_pdu_type(data, len);
    if (pdu == 0xE0) {
        return build_cotp_cc(data, len);
    }

    // COTP Data Transfer: optional S7 setup-communication job (function 0xF0)
    if (pdu == 0xF0 && len >= 18) {
        const uint8_t* s7 = data + 7;
        const size_t s7_len = len - 7;
        if (s7[0] == 0x32 && s7[1] == 0x01 && s7_len >= 18 && s7[10] == 0xF0) {
            return build_s7_setup_ack(s7, s7_len);
        }
    }

    return {};
}

}  // namespace honeypot
