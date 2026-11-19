"""Local fake services for trying the scan flow safely (127.0.0.1 only).

They send harmless banners and close. They never execute commands or accept data.
"""

from __future__ import annotations

import argparse
import socketserver
import threading

SERVICES = {
    2121: b"220 vsftpd 2.3.4 ready\r\n",
    2222: b"SSH-2.0-OpenSSH_7.2p1 Ubuntu-4ubuntu0.1\r\n",
    8080: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nContent-Length: 0\r\n\r\n",
}


def _handler_for(banner: bytes):
    class BannerHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            try:
                self.request.settimeout(1.0)
                self.request.sendall(banner)
                try:
                    self.request.recv(1024)
                except OSError:
                    pass
            except OSError:
                pass
    return BannerHandler


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_demo_ports(ports=None) -> list[_Server]:
    chosen = ports or list(SERVICES)
    servers = []
    for port in chosen:
        banner = SERVICES.get(port, b"220 Service ready\r\n")
        server = _Server(("127.0.0.1", port), _handler_for(banner))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    return servers


def main() -> None:
    parser = argparse.ArgumentParser(description="Start fake local services for the scanner demo.")
    parser.add_argument("--ports", help="comma-separated ports (defaults to 2121,2222,8080)")
    args = parser.parse_args()
    ports = [int(part) for part in args.ports.split(",")] if args.ports else None
    servers = start_demo_ports(ports)
    print("Demo ports open on 127.0.0.1: " + ", ".join(str(server.server_address[1]) for server in servers), flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":  # pragma: no cover
    main()
