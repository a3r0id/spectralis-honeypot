#include "honeypot/ip_utils.hpp"

#include <sstream>
#include <string>

#include "honeypot/constants.hpp"

namespace honeypot {

std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream token_stream(s);
    while (std::getline(token_stream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

uint32_t ip_to_uint32(const std::string& ip_str) {
    const std::vector<std::string> bytes = split(ip_str, '.');
    if (bytes.size() != 4) {
        return 0;
    }

    uint32_t ip = 0;
    for (int i = 0; i < 4; ++i) {
        try {
            const unsigned long octet = std::stoul(bytes[static_cast<size_t>(i)]);
            if (octet > 255) {
                return 0;
            }
            ip |= static_cast<uint32_t>(octet) << (24 - (8 * i));
        } catch (...) {
            return 0;
        }
    }
    return ip;
}

std::string uint32_to_ip(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

int mask_to_cidr_prefix(uint32_t mask) {
    int prefix = 0;
    while (mask & (1U << 31)) {
        prefix++;
        mask <<= 1;
    }
    return prefix;
}

std::string ip_and_mask_to_cidr(const std::string& ip_str, const std::string& mask_str) {
    const uint32_t ip = ip_to_uint32(ip_str);
    const uint32_t mask = ip_to_uint32(mask_str);
    const uint32_t network_address = ip & mask;
    const int prefix = mask_to_cidr_prefix(mask);
    return uint32_to_ip(network_address) + "/" + std::to_string(prefix);
}

bool ip_in_cidr(const std::string& ip_str, const std::string& cidr) {
    const auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        return ip_str == cidr;
    }

    int prefix = 0;
    try {
        prefix = std::stoi(cidr.substr(slash + 1));
    } catch (...) {
        return false;
    }
    if (prefix < 0 || prefix > 32) {
        return false;
    }

    const uint32_t ip = ip_to_uint32(ip_str);
    const uint32_t network = ip_to_uint32(cidr.substr(0, slash));
    const uint32_t mask = (prefix == 0) ? 0U : (~0U << (32 - prefix));
    return (ip & mask) == (network & mask);
}

bool is_scanner_ip(const std::string& ip_str) {
    for (const auto& cidr : scanner_ip_ranges()) {
        if (ip_in_cidr(ip_str, cidr)) {
            return true;
        }
    }
    return false;
}

}  // namespace honeypot
