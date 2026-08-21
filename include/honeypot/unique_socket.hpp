#pragma once

namespace honeypot {

class UniqueSocket {
public:
    explicit UniqueSocket(int fd);
    ~UniqueSocket();

    UniqueSocket(const UniqueSocket&) = delete;
    UniqueSocket& operator=(const UniqueSocket&) = delete;

    UniqueSocket(UniqueSocket&& other) noexcept;
    UniqueSocket& operator=(UniqueSocket&& other) noexcept;

    int get() const;

private:
    int fd_;
};

}
