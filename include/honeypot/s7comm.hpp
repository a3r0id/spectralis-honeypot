#pragma once

#include <memory>

#include "honeypot/protocol.hpp"

namespace honeypot {

// Siemens S7comm over ISO-on-TCP (RFC 1006 / TPKT + COTP).
std::shared_ptr<ProtocolHandler> make_s7comm_protocol();

}
