#include "honeypot/cli.hpp"

#include <cstdlib>
#include <iostream>

#include "honeypot/device_registry.hpp"

namespace honeypot {
namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* value = std::getenv(key);
    if (value == nullptr || value[0] == '\0') {
        return fallback;
    }
    return value;
}

std::string default_device_from_env() {
    const char* device = std::getenv("HONEYPOT_DEVICE");
    if (device != nullptr && device[0] != '\0') {
        return device;
    }
    // Back-compat with older deployments.
    return env_or("HONEYPOT_PLC_TYPE", "S7-200");
}

}

void print_usage() {
    std::cerr
        << "Usage: spectralis-honeypot [port] [bind_addr] [device]\n"
        << "       spectralis-honeypot --list\n"
        << "       spectralis-honeypot -h | --help\n"
        << "\n"
        << "  port       TCP listen port (default: 102, env HONEYPOT_PORT)\n"
        << "  bind_addr  IPv4 address or interface name (default: 0.0.0.0, env HONEYPOT_BIND_ADDR)\n"
        << "  device     Device id to mock (default: S7-200, env HONEYPOT_DEVICE)\n"
        << "  --list     Print available devices and exit\n";
}

Args parse_args(int argc, char** argv) {
    ensure_builtin_devices();

    Args parsed;
    parsed.port = std::stoi(env_or("HONEYPOT_PORT", "102"));
    parsed.bind_addr = env_or("HONEYPOT_BIND_ADDR", "0.0.0.0");
    parsed.device = default_device_from_env();

    if (argc >= 2) {
        const std::string first = argv[1];
        if (first == "-h" || first == "--help") {
            parsed.help = true;
            parsed.success = true;
            return parsed;
        }
        if (first == "--list" || first == "-l") {
            parsed.list = true;
            parsed.success = true;
            return parsed;
        }
        parsed.port = std::stoi(first);
    }
    if (argc >= 3) {
        parsed.bind_addr = argv[2];
    }
    if (argc >= 4) {
        parsed.device = argv[3];
    }

    const DeviceInfo* device = DeviceRegistry::instance().find(parsed.device);
    if (device != nullptr) {
        parsed.device = device->id;  // canonicalize casing
    }

    parsed.success = parsed.port > 0 && parsed.port <= 65535 && device != nullptr;
    return parsed;
}

}
