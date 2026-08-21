#pragma once

#include <string>

namespace honeypot {

struct Args {
    int port = 102;
    std::string bind_addr = "0.0.0.0";
    std::string device = "S7-200";
    bool success = false;
    bool help = false;
    bool list = false;
};

void print_usage();
Args parse_args(int argc, char** argv);

}
