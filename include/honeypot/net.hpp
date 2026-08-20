#pragma once

#include <netinet/in.h>
#include <string>

namespace honeypot {

bool resolve_bind_address(const std::string& spec, in_addr& out);

}  // namespace honeypot
