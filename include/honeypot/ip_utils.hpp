#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace honeypot {

std::vector<std::string> split(const std::string& s, char delimiter);
uint32_t ip_to_uint32(const std::string& ip_str);
std::string uint32_to_ip(uint32_t ip);
int mask_to_cidr_prefix(uint32_t mask);
std::string ip_and_mask_to_cidr(const std::string& ip_str, const std::string& mask_str);
bool ip_in_cidr(const std::string& ip_str, const std::string& cidr);
bool is_scanner_ip(const std::string& ip_str);

}  // namespace honeypot
