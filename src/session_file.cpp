#include "honeypot/session_file.hpp"

#include <fstream>
#include <stdexcept>

namespace honeypot {

void create_session_file(const std::string& filepath, const SessionHeader& header) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to create session file: " + filepath);
    }

    file.write(reinterpret_cast<const char*>(&header), sizeof(SessionHeader));
    file.close();
}

void write_session_entry(const std::string& filepath, const SessionEntry& entry) {
    std::ofstream file(filepath, std::ios::binary | std::ios::app);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to write session entry: " + filepath);
    }
    file.write(reinterpret_cast<const char*>(&entry.timestamp), sizeof(entry.timestamp));
    file.write(reinterpret_cast<const char*>(&entry.ip), sizeof(entry.ip));
    file.write(reinterpret_cast<const char*>(&entry.length), sizeof(entry.length));
    if (entry.payload != nullptr && entry.length > 0) {
        file.write(reinterpret_cast<const char*>(entry.payload), entry.length);
    }
    file.close();
}

}  // namespace honeypot
