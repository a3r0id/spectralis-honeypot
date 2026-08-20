#include "honeypot/constants.hpp"

namespace honeypot {

const std::vector<std::string>& scanner_ip_ranges() {
    static const std::vector<std::string> ranges = {
        "207.90.244.0/24",  // Shodan
        "66.132.153.0/24",  // Censys
        "66.132.159.0/24",
        "66.132.172.0/24",
        "66.132.186.0/24",
        "66.132.195.0/24",
        "66.234.1.0/24",
        "74.120.14.0/24",
        "162.142.125.0/24",
        "167.94.138.0/24",
        "167.94.145.0/24",
        "167.94.146.0/24",
        "167.248.133.0/24",
        "199.45.154.0/23",
        "206.168.32.0/22",
    };
    return ranges;
}

}  // namespace honeypot
