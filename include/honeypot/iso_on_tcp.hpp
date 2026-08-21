#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace honeypot {

// Minimal ISO-on-TCP (RFC 1006 / COTP) + S7 setup-communication replies.
// Enough for a scanner or S7 client to complete a handshake against this honeypot.

bool is_tpkt(const uint8_t* data, size_t len);
uint16_t tpkt_length(const uint8_t* data);
uint8_t cotp_pdu_type(const uint8_t* data, size_t len);
std::vector<uint8_t> build_cotp_cc(const uint8_t* cr, size_t len);
std::vector<uint8_t> build_s7_setup_ack(const uint8_t* s7, size_t s7_len);

// Returns an empty vector when the packet should be logged but not answered.
std::vector<uint8_t> handle_iso_on_tcp(const uint8_t* data, size_t len);

}
