#include "honeypot/sock_server.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <vector>

#include "honeypot/session_file.hpp"

namespace honeypot {
namespace {

void log_payload(const std::string& session_file,
                 const std::string& client_ip,
                 const uint8_t* data,
                 size_t len) {
    in_addr addr{};
    if (inet_pton(AF_INET, client_ip.c_str(), &addr) != 1) {
        return;
    }
    const uint16_t length = static_cast<uint16_t>(std::min(len, static_cast<size_t>(UINT16_MAX)));
    write_session_entry(session_file, SessionEntry{
        time(nullptr),
        addr,
        length,
        data,
    });
}

}

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        if (i > 0) {
            oss << ' ';
        }
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

bool send_all(int fd, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        const ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) {
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

void handle_client(std::unique_ptr<UniqueSocket> client_sock,
                   std::string client_ip,
                   int client_port,
                   std::string device_id,
                   std::shared_ptr<ProtocolHandler> protocol,
                   const std::string& session_file) {
    std::cout << "[INFO] Thread handling " << client_ip << ":" << client_port
              << " as " << device_id << " (" << protocol->name() << ")" << std::endl;

    std::vector<uint8_t> pending;
    uint8_t chunk[kBufferSize];

    while (true) {
        const ssize_t n = recv(client_sock->get(), chunk, sizeof(chunk), 0);
        if (n < 0) {
            std::cerr << "[ERROR] Read failed from " << client_ip << ":" << client_port << std::endl;
            break;
        }
        if (n == 0) {
            std::cout << "[INFO] Client " << client_ip << ":" << client_port
                      << " disconnected." << std::endl;
            break;
        }

        pending.insert(pending.end(), chunk, chunk + n);

        while (!pending.empty()) {
            size_t frame_len = 0;
            const auto status = protocol->try_frame(pending, frame_len);

            if (status == ProtocolHandler::FrameStatus::NeedMore) {
                break;
            }

            if (status == ProtocolHandler::FrameStatus::Complete) {
                std::vector<uint8_t> pkt(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(frame_len));
                pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(frame_len));

                std::cout << "[" << client_ip << ":" << client_port << "] "
                          << protocol->name() << " " << frame_len << " bytes: "
                          << to_hex(pkt.data(), pkt.size()) << std::endl;

                log_payload(session_file, client_ip, pkt.data(), pkt.size());

                const std::vector<uint8_t> response = protocol->handle(pkt.data(), pkt.size());
                if (!response.empty()) {
                    if (!send_all(client_sock->get(), response.data(), response.size())) {
                        std::cerr << "[ERROR] Send failed to " << client_ip << std::endl;
                        return;
                    }
                    std::cout << "[" << client_ip << ":" << client_port << "] replied "
                              << response.size() << " bytes" << std::endl;
                }
                continue;
            }

            // Not framed for this device protocol — log as raw and drop the buffer.
            std::cout << "[" << client_ip << ":" << client_port << "] raw "
                      << pending.size() << " bytes: "
                      << to_hex(pending.data(), pending.size()) << std::endl;

            log_payload(session_file, client_ip, pending.data(), pending.size());
            pending.clear();
            break;
        }
    }
}

}
