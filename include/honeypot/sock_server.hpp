#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "honeypot/protocol.hpp"
#include "honeypot/unique_socket.hpp"

namespace honeypot {

constexpr int kBufferSize = 4096;
constexpr int kBacklog = 10;

std::string to_hex(const uint8_t* data, size_t len);
bool send_all(int fd, const uint8_t* data, size_t len);
void handle_client(std::unique_ptr<UniqueSocket> client_sock,
                   std::string client_ip,
                   int client_port,
                   std::string device_id,
                   std::shared_ptr<ProtocolHandler> protocol,
                   const std::string& session_file);

}  // namespace honeypot
