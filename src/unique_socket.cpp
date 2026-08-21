#include "honeypot/unique_socket.hpp"

#include <unistd.h>

namespace honeypot {

UniqueSocket::UniqueSocket(int fd) : fd_(fd) {}

UniqueSocket::~UniqueSocket() {
    if (fd_ >= 0) {
        close(fd_);
    }
}

UniqueSocket::UniqueSocket(UniqueSocket&& other) noexcept : fd_(other.fd_) {
    other.fd_ = -1;
}

UniqueSocket& UniqueSocket::operator=(UniqueSocket&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

int UniqueSocket::get() const {
    return fd_;
}

}
