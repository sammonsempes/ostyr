#!/usr/bin/env python3
"""Usage: relay-proxy-probe.py HOST PORT SERVER_NAME PLATFORM_CA [--forge] [--cert FILE --key FILE]
Run on the client VM against the gateway relay port: optionally sends a PROXY v2 header (TCP over IPv4, forged source 10.9.9.9), then
wraps the same socket in TLS 1.3 and prints `HANDSHAKE OK <version>` or the error."""
import argparse
import socket
import ssl
import struct

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
FORGED_SOURCE = "10.9.9.9"
FORGED_PORT = 40000
TIMEOUT_SECONDS = 10


def proxy_header(destination):
    addresses = socket.inet_aton(FORGED_SOURCE) + socket.inet_aton(destination) + struct.pack("!HH", FORGED_PORT, 7443)
    return SIGNATURE + bytes([0x21, 0x11]) + struct.pack("!H", len(addresses)) + addresses


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("server_name")
    parser.add_argument("platform_ca")
    parser.add_argument("--forge", action="store_true")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(args.platform_ca)
    if args.cert:
        context.load_cert_chain(args.cert, args.key)
    try:
        with socket.create_connection((args.host, args.port), timeout=TIMEOUT_SECONDS) as plain:
            if args.forge:
                plain.sendall(proxy_header(args.host))
            with context.wrap_socket(plain, server_hostname=args.server_name) as tls:
                print("HANDSHAKE OK", tls.version())
    except (OSError, ssl.SSLError) as error:
        print("HANDSHAKE FAILED", type(error).__name__, error)


main()
