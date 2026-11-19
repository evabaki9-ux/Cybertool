"""Read-only verification of signature matches.

Verification re-probes the service banner on the selected port. It never sends
exploit payloads, attempts authentication, reads files or executes commands.
For version-based signatures this confirms the *version* only, not exploitability.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from . import scanner, vulns

VERSION_RULES = {
    "vsftpd-234-backdoor": {"product": "vsftpd", "equals": ("2.3.4",)},
    "openssh-user-enumeration": {"product": "openssh", "max": "7.3"},
    "apache-path-traversal": {"product": "apache", "equals": ("2.4.49", "2.4.50")},
    "tomcat-ghostcat": {"product": "tomcat", "min": "7.0", "max": "9.0.30"},
}

PATCH_LEVEL_RULES = {"smb-ms17010", "rdp-bluekeep"}

SAFETY_NOTE = "No exploit payloads, login attempts, file reads or commands were used."


def _version_tuple(value: str):
    numbers = re.findall(r"\d+", str(value or ""))
    return tuple(int(number) for number in numbers[:4]) if numbers else None


def _version_matches(spec: dict, version: str) -> bool:
    actual = _version_tuple(version)
    if actual is None:
        return False
    if spec.get("equals"):
        expected = [_version_tuple(item) for item in spec["equals"]]
        return any(actual[:len(item)] == item for item in expected if item)
    if spec.get("min"):
        minimum = _version_tuple(spec["min"])
        if minimum is None or actual < minimum:
            return False
    if spec.get("max"):
        maximum = _version_tuple(spec["max"])
        if maximum is None or actual > maximum:
            return False
    return True


def _service_matches(rule: dict, live: dict) -> bool:
    service = str(live.get("service") or "").lower()
    product = str(live.get("product") or "").lower()
    services = rule.get("services") or set()
    service_ok = service in services or any(name in product for name in services)
    product_ok = not rule.get("product_contains") or rule["product_contains"] in product
    return service_ok and product_ok


def finding_for(port_info: dict, finding_id: str):
    """Find a signature result for one port by its id."""
    return next((item for item in vulns.find_for_port(port_info) if item["id"] == finding_id), None)


def verify_finding(finding: dict, port_info: dict, target: str, timeout: float = 5) -> dict:
    """Run a safe live check for one finding."""
    rule_id = str(finding.get("id") or "")
    rule = next((item for item in vulns.RULES if item["id"] == rule_id), None)
    port = int(port_info.get("port", 0))
    host = port_info.get("host") or target
    check_name = "TCP connect + banner read"

    def result(status: str, evidence: str, detail: str) -> dict:
        return {
            "finding_id": rule_id,
            "title": finding.get("title", rule_id),
            "port": port,
            "status": status,
            "evidence": evidence,
            "detail": detail,
            "check": check_name,
            "safe": True,
            "safety_note": SAFETY_NOTE,
            "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    if rule is None or not port:
        return result("inconclusive", "No matching signature rule", "This finding has no verifier.")

    probes = []
    using_nmap = scanner.nmap_available()
    if using_nmap:
        try:
            probes, _ = scanner.scan_with_nmap(str(host), [port], max(timeout, 10.0))
            check_name = "nmap -sV single-port version detection"
        except (ValueError, TypeError):
            using_nmap = False
    if not using_nmap:
        check_name = "TCP connect + banner read"
        try:
            probes, _ = scanner.scan_with_connect(str(host), [port], timeout)
        except (ValueError, TypeError) as exc:
            return result("inconclusive", "Probe could not run", str(exc))
    live = probes[0] if probes else None
    if live is None:
        return result("not_confirmed", "Re-probe of %s:%d failed" % (host, port),
                      "The port is no longer reachable from this host, so the signature could not be confirmed.")

    evidence = "%s:%d → service=%s" % (host, port, live.get("service") or "unknown")
    if live.get("product"):
        evidence += ", product=" + str(live["product"])
    if live.get("version"):
        evidence += ", version=" + str(live["version"])

    if rule_id in VERSION_RULES:
        spec = VERSION_RULES[rule_id]
        product_ok = spec["product"] in str(live.get("product") or "").lower()
        if product_ok and _version_matches(spec, live.get("version", "")):
            return result("confirmed", evidence,
                          "Live version check matches the affected signature. This confirms the version, not exploitability.")
        if live.get("product") or live.get("version"):
            return result("not_confirmed", evidence,
                          "The live version check reports a different product or version than the affected signature.")
        return result("inconclusive", evidence,
                      "The service answered but did not reveal a usable version.")

    if rule_id in PATCH_LEVEL_RULES:
        if _service_matches(rule, live) or _service_matches(rule, port_info):
            return result("inconclusive", evidence,
                          "The service is present, but its patch level cannot be read anonymously. "
                          "An authenticated scan is required. " + SAFETY_NOTE)
        return result("not_confirmed", evidence, "The expected service was not present on re-probe.")

    if _service_matches(rule, live):
        return result("confirmed", evidence,
                      "The live probe confirms the service that triggered this signature. "
                      "No further exposure testing was performed. " + SAFETY_NOTE)
    return result("not_confirmed", evidence, "The expected service was not present on re-probe.")
