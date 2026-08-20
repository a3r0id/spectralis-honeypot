# Handshake test: ISO-on-TCP COTP Connection Request -> Connection Confirm
import socket
import sys


COTP_CR = bytes(
    [
        0x03, 0x00, 0x00, 0x16,  # TPKT
        0x11, 0xE0,              # COTP CR
        0x00, 0x00,              # dest ref
        0x00, 0x01,              # src ref
        0x00,                    # class
        0xC1, 0x02, 0x01, 0x00,  # src-tsap
        0xC2, 0x02, 0x01, 0x02,  # dest-tsap
        0xC0, 0x01, 0x0A,        # TPDU size
    ]
)


def connect_to_server(host, port):
    s = socket.create_connection((host, port), timeout=5)
    print(f"Connected to server {host}:{port}")
    return s


def test_cotp_handshake(host, port):
    s = connect_to_server(host, port)
    try:
        s.sendall(COTP_CR)
        print(f"Sent COTP CR ({len(COTP_CR)} bytes)")
        response = s.recv(1024)
        print(f"Received {len(response)} bytes: {response.hex(' ')}")
        if len(response) < 6 or response[0] != 0x03 or (response[5] & 0xF0) != 0xD0:
            raise SystemExit("unexpected COTP response (expected Connection Confirm)")
        print("COTP handshake OK")
    finally:
        s.close()
        print(f"Closed connection to server {host}:{port}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 102
    test_cotp_handshake(host, port)
