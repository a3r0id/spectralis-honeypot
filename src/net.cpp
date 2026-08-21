#include "honeypot/net.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>

namespace honeypot {

bool resolve_bind_address(const std::string& spec, in_addr& out) {
    if (spec.empty() || spec == "0.0.0.0" || spec == "*") {
        out.s_addr = INADDR_ANY;
        return true;
    }

    if (inet_pton(AF_INET, spec.c_str(), &out) == 1) {
        return true;
    }

    ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0) {
        return false;
    }

    bool found = false;
    for (ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (spec == ifa->ifa_name) {
            out = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr;
            found = true;
            break;
        }
    }
    freeifaddrs(ifaddr);
    return found;
}

}
