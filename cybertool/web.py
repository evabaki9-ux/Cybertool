"""Local web UI and JSON API for the port scan / vulnerability lookup flow."""

from __future__ import annotations

import argparse
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__, cve_lookup, playbook, scanner, verify, vulns

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY_BYTES = 64 * 1024
CONTENT_TYPES = {
    "index.html": "text/html; charset=utf-8",
    "styles.css": "text/css; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
}


class CybertoolHandler(BaseHTTPRequestHandler):
    server_version = "Cybertool/%s" % __version__

    def _send(self, body: bytes, status: int, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, value: dict, status: int = HTTPStatus.OK) -> None:
        self._send(json.dumps(value, indent=2).encode("utf-8"), status, "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("Request body is too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must be valid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object")
        return value

    def do_HEAD(self) -> None:  # pragma: no cover - browsers may probe this
        self.do_GET()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            name = "index.html"
        elif path.lstrip("/") in CONTENT_TYPES:
            name = path.lstrip("/")
        elif path == "/api/health":
            self._send_json({"status": "ok", "service": "cybertool"})
            return
        elif path == "/api/status":
            self._send_json({"nmap_available": scanner.nmap_available(), "version": __version__})
            return
        else:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        target = STATIC_DIR / name
        if not target.is_file():
            self._send_json({"error": "Static asset missing"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send(target.read_bytes(), HTTPStatus.OK, CONTENT_TYPES[name])

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in ("/api/scan", "/api/vulns", "/api/verify", "/api/guide", "/api/cve"):
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        try:
            payload = self._read_json()
            if path == "/api/scan":
                if not payload.get("authorized"):
                    raise ValueError("Confirm that you are authorized to scan this target")
                if not str(payload.get("target", "")).strip():
                    raise ValueError("Enter a target to scan")
                result = scanner.scan_target(
                    payload["target"],
                    authorized=True,
                    profile=str(payload.get("profile", "top")),
                    ports=payload.get("ports"),
                    timeout=float(payload.get("timeout", 60)),
                )
            elif path == "/api/guide":
                result = playbook.guide_for(str(payload.get("finding_id", "")))
            elif path == "/api/cve":
                result = cve_lookup.lookup(
                    payload.get("product", ""), payload.get("version", ""),
                    timeout=float(payload.get("timeout", 8)),
                )
            elif path == "/api/vulns":
                report = scanner.SCANS.get(str(payload.get("scan_id", "")))
                if report is None:
                    raise ValueError("Scan not found or expired; run a new scan")
                requested = payload.get("ports")
                if not isinstance(requested, list) or not requested:
                    raise ValueError("Select at least one open port")
                wanted = {int(item) for item in requested}
                selected = [port for port in report["ports"] if port["port"] in wanted]
                if not selected:
                    raise ValueError("None of the selected ports belong to that scan")
                result = vulns.lookup(selected)
                result["scan_id"] = payload["scan_id"]
                result["target"] = report["target"]
            else:
                report = scanner.SCANS.get(str(payload.get("scan_id", "")))
                if report is None:
                    raise ValueError("Scan not found or expired; run a new scan")
                finding_id = str(payload.get("finding_id", ""))
                port_number = int(payload.get("port", 0))
                port_info = next((item for item in report["ports"] if item["port"] == port_number), None)
                if port_info is None:
                    raise ValueError("That port is not part of this scan")
                finding = verify.finding_for(port_info, finding_id)
                if finding is None:
                    raise ValueError("That finding is not part of this scan")
                result = verify.verify_finding(
                    finding, port_info, report["target"],
                    timeout=float(payload.get("timeout", 5)),
                )
        except (ValueError, TypeError, KeyError) as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        except Exception:
            self._send_json({"error": "The request could not be completed"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._send_json(result)

    def log_message(self, format: str, *args: object) -> None:
        print("%s - %s" % (self.address_string(), format % args), flush=True)


def run(host: str = "0.0.0.0", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), CybertoolHandler)
    print("Cybertool running at http://%s:%d/" % (host, port), flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Cybertool.", flush=True)
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cybertool-web", description="Launch the Cybertool web interface.")
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")),
                        help="listening port (default: PORT env var or 8000)")
    args = parser.parse_args(argv)
    run(args.host, args.port)


if __name__ == "__main__":  # pragma: no cover
    main()
