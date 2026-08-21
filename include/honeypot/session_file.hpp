#pragma once

#include <cstdint>
#include <ctime>
#include <netinet/in.h>
#include <string>

namespace honeypot {

struct SessionHeader {
    time_t timestamp;
    in_addr ip;
    in_port_t port;
    uint16_t protocol;
};

struct SessionEntry {
    time_t timestamp;
    in_addr ip;
    uint16_t length;
    const uint8_t* payload;
};

void create_session_file(const std::string& filepath, const SessionHeader& header);
void write_session_entry(const std::string& filepath, const SessionEntry& entry);

}
