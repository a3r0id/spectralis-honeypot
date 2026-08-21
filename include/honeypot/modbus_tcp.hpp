#pragma once

#include <memory>

#include "honeypot/protocol.hpp"

namespace honeypot {

// Modbus TCP (MBAP). Used by Modicon PLCs such as M221.
std::shared_ptr<ProtocolHandler> make_modbus_tcp_protocol();

}
