#pragma once

#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

#include "honeypot/protocol.hpp"

namespace honeypot {

struct DeviceInfo {
    std::string id;           // canonical id, e.g. "S7-200"
    std::string description;  // human-readable blurb for --list
    std::shared_ptr<ProtocolHandler> protocol;
};

// Built-in device catalog. Call ensure_builtin_devices() before use.
class DeviceRegistry {
public:
    static DeviceRegistry& instance();

    void add(DeviceInfo device);
    const std::vector<DeviceInfo>& all() const;
    const DeviceInfo* find(const std::string& id) const;

private:
    std::vector<DeviceInfo> devices_;
};

void ensure_builtin_devices();
void print_device_list(std::ostream& out);

}
