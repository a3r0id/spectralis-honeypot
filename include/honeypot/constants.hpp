#pragma once

#include <string>
#include <vector>

namespace honeypot {

// Public internet scanner prefixes used for connection tagging.
const std::vector<std::string>& scanner_ip_ranges();

}  // namespace honeypot
