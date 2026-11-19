import json
import socket
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

from cybertool import scanner, vulns
from cybertool.demo_ports import start_demo_ports
from cybertool.web import CybertoolHandler

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="echo-reply"/>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="7.2p1" method="probed"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="Apache httpd" version="2.4.49" method="probed"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/></port>
</ports></host></nmaprun>"""


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ScannerTests(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(ValueError):
            scanner.scan_target("127.0.0.1", authorized=False)
        with self.assertRaises(ValueError):
            scanner.validate_target("-sS 127.0.0.1")
        with self.assertRaises(ValueError):
            scanner.validate_target("bad target!")
        with self.assertRaises(ValueError):
            scanner.resolve_ports("top", [70000])

    def test_nmap_xml_parsing(self):
        ports, state = scanner.parse_nmap_xml(NMAP_XML, "127.0.0.1")
        self.assertEqual(state, "up")
        self.assertEqual([item["port"] for item in ports], [22, 80])
        self.assertEqual(ports[0]["product"], "OpenSSH")
        self.assertEqual(ports[1]["version"], "2.4.49")

    def test_banner_classification(self):
        self.assertEqual(scanner.classify_banner(22, "SSH-2.0-OpenSSH_7.2p1")["version"], "7.2p1")
        ftp = scanner.classify_banner(2121, "220 vsftpd 2.3.4 ready")
        self.assertEqual((ftp["product"], ftp["version"]), ("vsftpd", "2.3.4"))

    def test_connect_fallback_finds_open_port(self):
        port = free_port()
        servers = start_demo_ports([port])
        try:
            report = scanner.scan_target("127.0.0.1", authorized=True, ports=[port], timeout=5)
            self.assertEqual(report["port_count"], 1)
            self.assertEqual(report["ports"][0]["port"], port)
            self.assertEqual(report["ports"][0]["state"], "open")
            self.assertTrue(report["scan_id"])
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()

    def test_unresolvable_target(self):
        report = scanner.scan_target("no-such-host.invalid", authorized=True, ports=[80], timeout=5)
        self.assertEqual(report["port_count"], 0)


class VulnerabilityTests(unittest.TestCase):
    def test_known_matches(self):
        ftp = vulns.find_for_port({"port": 21, "service": "ftp", "product": "vsftpd", "version": "2.3.4"})
        self.assertIn("vsftpd-234-backdoor", {item["id"] for item in ftp})
        ssh = vulns.find_for_port({"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.2p1"})
        self.assertIn("CVE-2016-6210", ssh[0]["cve"])
        apache = vulns.find_for_port({"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49"})
        self.assertIn("apache-path-traversal", {item["id"] for item in apache})

    def test_non_matching_version(self):
        result = vulns.find_for_port({"port": 21, "service": "ftp", "product": "vsftpd", "version": "3.0.5"})
        self.assertNotIn("vsftpd-234-backdoor", {item["id"] for item in result})

    def test_lookup_reports_checked_ports(self):
        result = vulns.lookup([
            {"port": 21, "service": "ftp", "product": "vsftpd", "version": "2.3.4"},
            {"port": 9999, "service": "unknown", "product": "", "version": ""},
        ])
        self.assertEqual(len(result["checked_ports"]), 2)
        self.assertEqual(result["finding_count"], 2)
        self.assertTrue(result["notes"])
        self.assertEqual(result["counts"]["critical"], 1)


class WebTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.servers = start_demo_ports([cls.port])
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CybertoolHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        for server in cls.servers:
            server.shutdown()
            server.server_close()

    def _post(self, path, payload):
        request = Request(self.base + path, data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json"})
        return urlopen(request)

    def test_health_status_and_page(self):
        with urlopen(self.base + "/api/health") as response:
            self.assertEqual(json.load(response)["status"], "ok")
        with urlopen(self.base + "/api/status") as response:
            self.assertIn("nmap_available", json.load(response))
        with urlopen(self.base + "/") as response:
            self.assertIn(b"CYBERTOOL", response.read())

    def test_scan_then_lookup(self):
        with self._post("/api/scan", {
            "target": "127.0.0.1", "authorized": True, "ports": [self.port], "timeout": 5,
        }) as response:
            scan = json.load(response)
        self.assertEqual(scan["port_count"], 1)

        with self._post("/api/vulns", {"scan_id": scan["scan_id"], "ports": [self.port]}) as response:
            result = json.load(response)
        self.assertEqual(result["checked_ports"][0]["port"], self.port)
        self.assertIn("findings", result)

    def test_authorization_required(self):
        with self.assertRaises(Exception) as context:
            self._post("/api/scan", {"target": "127.0.0.1", "authorized": False})
        self.assertEqual(getattr(context.exception, "code", None), 400)


if __name__ == "__main__":
    unittest.main()
