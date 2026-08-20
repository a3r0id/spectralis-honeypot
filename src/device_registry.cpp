#include "honeypot/device_registry.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>

#include "honeypot/modbus_tcp.hpp"
#include "honeypot/s7comm.hpp"

namespace honeypot {
namespace {

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

}  // namespace

DeviceRegistry& DeviceRegistry::instance() {
    static DeviceRegistry registry;
    return registry;
}

void DeviceRegistry::add(DeviceInfo device) {
    devices_.push_back(std::move(device));
}

const std::vector<DeviceInfo>& DeviceRegistry::all() const {
    return devices_;
}

const DeviceInfo* DeviceRegistry::find(const std::string& id) const {
    const std::string needle = to_lower(id);
    for (const auto& device : devices_) {
        if (to_lower(device.id) == needle) {
            return &device;
        }
    }
    return nullptr;
}

void ensure_builtin_devices() {
    auto& registry = DeviceRegistry::instance();
    if (!registry.all().empty()) {
        return;
    }

    const auto s7 = make_s7comm_protocol();
    registry.add({"S7-200", "Siemens PLC model series", s7});
    registry.add({"S7-300", "Siemens PLC model", s7});
    registry.add({"S7-400", "Siemens PLC model", s7});
    registry.add({"S7-1200", "Siemens S7-1200 PLC", s7});

    const auto modbus = make_modbus_tcp_protocol();
    registry.add({"M221", "Modicon PLC model", modbus});
    registry.add({"M340", "Modicon M340 PLC", modbus});
}

void print_device_list(std::ostream& out) {
    ensure_builtin_devices();
    const auto& devices = DeviceRegistry::instance().all();
    for (size_t i = 0; i < devices.size(); ++i) {
        out << i << ":  \"" << devices[i].id << "\" - " << devices[i].description << '\n';
    }
}

}  // namespace honeypot
