#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <exception>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>

#include "honeypot/cli.hpp"
#include "honeypot/device_registry.hpp"
#include "honeypot/net.hpp"
#include "honeypot/session_file.hpp"
#include "honeypot/sock_server.hpp"
#include "honeypot/unique_socket.hpp"

/**
 * Author: Chad Groom (a3r0id)
 * Licensed under the MIT License.
 * Copyright (c) 2026 Chad Groom
 * https://github.com/a3r0id/spectralis-honeypot
 * Description: Modular industrial PLC honeypot (S7comm, Modbus TCP, …)
 */

int main(int argc, char** argv) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    honeypot::ensure_builtin_devices();

    honeypot::Args args;
    try {
        args = honeypot::parse_args(argc, argv);
    } catch (const std::exception&) {
        honeypot::print_usage();
        return 1;
    }

    if (args.help) {
        honeypot::print_usage();
        return 0;
    }
    if (args.list) {
        honeypot::print_device_list(std::cout);
        return 0;
    }
    if (!args.success) {
        std::cerr << "Invalid arguments." << std::endl;
        honeypot::print_usage();
        return 1;
    }

    const honeypot::DeviceInfo* device = honeypot::DeviceRegistry::instance().find(args.device);
    if (device == nullptr || !device->protocol) {
        std::cerr << "[ERROR] Unknown device '" << args.device << "'. Use --list." << std::endl;
        return 1;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<uint16_t>(args.port));
    if (!honeypot::resolve_bind_address(args.bind_addr, address.sin_addr)) {
        std::cerr << "[ERROR] Could not resolve bind address '" << args.bind_addr << "'" << std::endl;
        return 1;
    }

    char bind_ip[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &address.sin_addr, bind_ip, sizeof(bind_ip));

    std::cout << "Listening on " << bind_ip << ":" << args.port
              << " device=" << device->id
              << " protocol=" << device->protocol->name() << std::endl;

    const int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "[ERROR] Socket creation failed: " << std::strerror(errno) << std::endl;
        return 1;
    }
    honeypot::UniqueSocket listening_socket(server_fd);

    int opt = 1;
    if (setsockopt(listening_socket.get(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "[ERROR] setsockopt(SO_REUSEADDR) failed: " << std::strerror(errno) << std::endl;
        return 1;
    }

    if (bind(listening_socket.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        std::cerr << "[ERROR] Bind failed on " << bind_ip << ":" << args.port
                  << ": " << std::strerror(errno) << std::endl;
        return 1;
    }

    if (listen(listening_socket.get(), honeypot::kBacklog) < 0) {
        std::cerr << "[ERROR] Listen failed: " << std::strerror(errno) << std::endl;
        return 1;
    }

    std::cout << "[SUCCESS] Server is listening on " << bind_ip << ":" << args.port << std::endl;

    const std::string session_id = std::to_string(time(nullptr));
    const std::string session_file = session_id + ".spectralis.session.bin";
    honeypot::create_session_file(session_file, honeypot::SessionHeader{
        time(nullptr),
        address.sin_addr,
        static_cast<in_port_t>(ntohs(address.sin_port)),
        IPPROTO_TCP,
    });

    while (true) {
        sockaddr_in client_address{};
        socklen_t client_addr_len = sizeof(client_address);
        const int client_fd = accept(listening_socket.get(),
                                     reinterpret_cast<sockaddr*>(&client_address),
                                     &client_addr_len);
        if (client_fd < 0) {
            std::cerr << "[ERROR] Accept failed: " << std::strerror(errno) << std::endl;
            continue;
        }

        char client_ip[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &client_address.sin_addr, client_ip, sizeof(client_ip));
        const int client_port = ntohs(client_address.sin_port);
        std::cout << "[CONNECTION] " << client_ip << ":" << client_port << std::endl;

        auto client_sock = std::make_unique<honeypot::UniqueSocket>(client_fd);
        std::thread t(honeypot::handle_client,
                      std::move(client_sock),
                      std::string(client_ip),
                      client_port,
                      device->id,
                      device->protocol,
                      session_file);
        t.detach();
    }
}
