FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release -DHONEYPOT_BUILD_TESTS=OFF \
    && cmake --build /build -j"$(nproc)"

FROM gcr.io/distroless/cc-debian12:latest

WORKDIR /app
COPY --from=builder /build/spectralis-honeypot /app/spectralis-honeypot

USER 65534:65534

ENV HONEYPOT_PORT=102
ENV HONEYPOT_BIND_ADDR=0.0.0.0
ENV HONEYPOT_DEVICE=S7-200

ENTRYPOINT ["/app/spectralis-honeypot"]
