"""Port scanning with nmap, plus a dependency-free fallback for local use.

Only the target's publicly reachable TCP ports are examined. No exploitation,
credential guessing or vulnerability verification is performed here.
"""

from __future__ import annotations

import re
import secrets
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

TOP_PORTS = sorted({
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 512, 513,
    514, 587, 593, 636, 873, 993, 995, 1080, 1099, 1433, 1434, 1521, 1720,
    1723, 1883, 2049, 2121, 2181, 2222, 2375, 2483, 27017, 3128, 3306, 3389,
    3690, 4369, 4443, 4444, 4500, 5000, 5060, 5061, 5432, 5601, 5900, 6000,
    6379, 6443, 6666, 7001, 7070, 8000, 8008, 8080, 8081, 8088, 8090, 8443,
    8500, 8545, 8888, 9000, 9001, 9042, 9090, 9092, 9200, 9300, 9418, 10000,
    11211, 50000,
})

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1099: "java-rmi", 1433: "mssql", 1434: "mssql-monitor", 1521: "oracle",
    1883: "mqtt", 2049: "nfs", 2121: "ftp", 2181: "zookeeper", 2222: "ssh",
    2375: "docker", 27017: "mongodb", 3128: "proxy", 3306: "mysql",
    3389: "ms-wbt-server", 3690: "svn", 4444: "metasploit", 5000: "http",
    5060: "sip", 5061: "sips", 5432: "postgresql", 5601: "kibana",
    5900: "vnc", 6379: "redis", 7001: "weblogic", 8000: "http", 8008: "http",
    8080: "http", 8081: "http", 8088: "http", 8090: "http", 8443: "https",
    8500: "consul", 8545: "ethereum-json-rpc", 8888: "http", 9000: "http",
    9001: "http", 9042: "cassandra", 9090: "http", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
    10000: "webmin", 11211: "memcached", 50000: "unknown",
}

MAX_STORED_SCANS = 20
SCANS: dict[str, dict] = {}


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def validate_target(target: str) -> str:
    value = str(target).strip()
    if not value or value.startswith("-"):
        raise ValueError("Enter a hostname, IP address or CIDR range")
    if len(value) > 255 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-:\[\]/]*", value):
        raise ValueError("Target contains unsupported characters")
    return value


def resolve_ports(profile: str = "top", ports=None):
    """Return a port list, or ``None`` meaning all ports (nmap only)."""
    if ports:
        try:
            parsed = sorted({int(p) for p in ports})
        except (TypeError, ValueError) as exc:
            raise ValueError("Ports must be integers") from exc
        if not parsed or any(p < 1 or p > 65535 for p in parsed):
            raise ValueError("Ports must be between 1 and 65535")
        if len(parsed) > 500:
            raise ValueError("At most 500 ports can be requested at once")
        return parsed
    if profile == "full":
        return None
    if profile == "top":
        return TOP_PORTS
    raise ValueError("Profile must be 'top' or 'full'")


def parse_nmap_xml(xml_text: str, target: str) -> tuple[list[dict], str]:
    """Extract open ports from nmap's ``-oX -`` output."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError("nmap returned output that could not be parsed") from exc
    ports = []
    for element in root.findall(".//port"):
        state = element.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = element.find("service")
        attributes = service.attrib if service is not None else {}
        try:
            number = int(element.get("portid", "0"))
        except ValueError:
            continue
        ports.append({
            "port": number,
            "protocol": element.get("protocol", "tcp"),
            "state": "open",
            "service": attributes.get("name") or SERVICE_NAMES.get(number, "unknown"),
            "product": attributes.get("product", ""),
            "version": attributes.get("version", ""),
            "extrainfo": attributes.get("extrainfo", ""),
            "method": attributes.get("method", "probed"),
        })
    ports.sort(key=lambda item: item["port"])
    status = root.find(".//host/status")
    address = root.find(".//host/address")
    host = address.get("addr", "") if address is not None else ""
    for item in ports:
        item["host"] = host
    return ports, (status.get("state", "unknown") if status is not None else "unknown")


def classify_banner(port: int, banner: str) -> dict:
    """Turn a short service banner into product/version hints."""
    text = banner.strip()
    lower = text.lower()
    result: dict[str, str] = {}
    if text.startswith("SSH-"):
        result["service"] = "ssh"
        match = re.search(r"OpenSSH[_-]?([0-9][0-9A-Za-z.]*)", text, re.I)
        result["product"] = "OpenSSH" if match else "SSH"
        if match:
            result["version"] = match.group(1)
    elif "vsftpd" in lower:
        result.update(service="ftp", product="vsftpd")
        match = re.search(r"vsftpd\s+([0-9][0-9.]*)", text, re.I)
        if match:
            result["version"] = match.group(1)
    elif "apache" in lower:
        result.update(service="http", product="Apache httpd")
        match = re.search(r"Apache/([0-9][0-9.]*)", text, re.I)
        if match:
            result["version"] = match.group(1)
    elif "nginx" in lower:
        result.update(service="http", product="nginx")
        match = re.search(r"nginx/([0-9][0-9.]*)", text, re.I)
        if match:
            result["version"] = match.group(1)
    elif text.startswith("HTTP/"):
        result["service"] = "https" if port in (443, 8443) else "http"
        match = re.search(r"Server:\s*([^\r\n]+)", text, re.I)
        if match:
            server = match.group(1).strip()
            parts = server.split("/", 1)
            result["product"] = parts[0]
            if len(parts) == 2:
                result["version"] = parts[1].strip()
    return result


def scan_with_connect(target: str, ports: list[int], timeout: float) -> tuple[list[dict], str]:
    """Fallback TCP connect scan with a short banner read."""
    if "/" in target:
        raise ValueError("CIDR ranges require nmap; use a single host for the fallback scan")
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Could not resolve target: %s" % exc) from exc
    host = infos[0][4][0]
    connect_timeout = min(max(timeout / 10, 0.2), 1.5)

    def probe(port: int):
        try:
            with socket.create_connection((host, port), timeout=connect_timeout) as sock:
                sock.settimeout(0.5)
                if SERVICE_NAMES.get(port) in ("http", "https"):
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    except OSError:
                        pass
                try:
                    banner = sock.recv(512).decode("utf-8", "replace").strip()
                except (socket.timeout, OSError):
                    banner = ""
                info = {
                    "port": port, "protocol": "tcp", "state": "open",
                    "service": SERVICE_NAMES.get(port, "unknown"),
                    "product": "", "version": "", "extrainfo": "",
                    "method": "connect", "banner": banner[:200], "host": host,
                }
                info.update(classify_banner(port, banner))
                return info
        except (OSError, socket.timeout):
            return None

    with ThreadPoolExecutor(max_workers=64) as pool:
        results = list(pool.map(probe, ports))
    return sorted((item for item in results if item), key=lambda item: item["port"]), "up"


def scan_with_nmap(target: str, ports, timeout: float) -> tuple[list[dict], str]:
    command = ["nmap", "-sV", "--open", "-T4", "-oX", "-"]
    command += ["-p-"] if ports is None else ["-p", ",".join(str(port) for port in ports)]
    command.append(target)
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("nmap timed out; try a shorter port list or a longer timeout") from exc
    except FileNotFoundError as exc:
        raise ValueError("nmap is not installed") from exc
    if not completed.stdout.strip():
        detail = completed.stderr.strip()[:200] or "no output"
        raise ValueError("nmap failed: " + detail)
    return parse_nmap_xml(completed.stdout, target)


def store_scan(report: dict) -> str:
    key = secrets.token_urlsafe(9)
    SCANS[key] = report
    while len(SCANS) > MAX_STORED_SCANS:
        SCANS.pop(next(iter(SCANS)))
    return key


def scan_target(
    target: str,
    authorized: bool = False,
    profile: str = "top",
    ports=None,
    timeout: float = 60,
) -> dict:
    """Run a port scan and return a report with an in-memory ``scan_id``."""
    if not authorized:
        raise ValueError("Confirm that you are authorized to scan this target")
    value = validate_target(target)
    selected = resolve_ports(profile, ports)
    timeout = max(5.0, min(float(timeout), 300.0))
    started = datetime.now(timezone.utc)
    using_nmap = nmap_available()
    error = None
    try:
        if using_nmap:
            open_ports, host_state = scan_with_nmap(value, selected, timeout)
            note = "Scanned with nmap -sV (XML output). Version detection depends on service banners."
        else:
            fallback_ports = TOP_PORTS if selected is None else selected
            open_ports, host_state = scan_with_connect(value, fallback_ports, timeout)
            note = "nmap is not installed here; used a TCP connect scan with banner grabbing on %d ports." % len(fallback_ports)
    except ValueError as exc:
        open_ports, host_state, note = [], "unknown", ""
        error = str(exc)

    report = {
        "target": value,
        "error": error,
        "scanned_at": started.isoformat(timespec="seconds"),
        "duration_ms": int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
        "engine": "nmap" if using_nmap else "connect",
        "host_state": host_state,
        "port_count": len(open_ports),
        "note": note or (error or ""),
        "ports": open_ports,
    }
    report["scan_id"] = store_scan(report)
    return report
