"""Small offline signature list for services found by a port scan.

Matches are *possible* issues inferred from service name, product and version.
Nothing is verified against the target and no exploit is executed.
"""

from __future__ import annotations

import re

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

RULES = [
    {
        "id": "vsftpd-234-backdoor",
        "title": "vsftpd 2.3.4 backdoor",
        "severity": "critical", "kind": "CVE", "cve": "CVE-2011-2523",
        "services": {"ftp"}, "product_contains": "vsftpd", "version_equals": {"2.3.4"},
        "description": "The vsftpd 2.3.4 source tree contained a backdoor that allows a remote shell after a crafted login sequence.",
        "remediation": "Upgrade vsftpd immediately and restrict FTP access to trusted networks.",
        "references": ["CVE-2011-2523"], "confidence": "Product and version match",
    },
    {
        "id": "openssh-user-enumeration",
        "title": "Older OpenSSH may allow user enumeration",
        "severity": "medium", "kind": "CVE", "cve": "CVE-2016-6210",
        "services": {"ssh"}, "product_contains": "openssh", "version_max": "7.3",
        "description": "OpenSSH versions up to 7.3 can leak valid usernames through timing differences in password authentication.",
        "remediation": "Upgrade OpenSSH and disable password authentication in favour of keys.",
        "references": ["CVE-2016-6210"], "confidence": "Version-based match",
    },
    {
        "id": "apache-path-traversal",
        "title": "Apache HTTP Server path traversal",
        "severity": "critical", "kind": "CVE", "cve": "CVE-2021-41773 / CVE-2021-42013",
        "services": {"http", "https"}, "product_contains": "apache",
        "version_equals": {"2.4.49", "2.4.50"},
        "description": "Apache 2.4.49 and 2.4.50 contain a path traversal flaw that can expose files outside the web root when mod_cgi is enabled.",
        "remediation": "Upgrade to 2.4.51 or later and review Alias and CGI configuration.",
        "references": ["CVE-2021-41773", "CVE-2021-42013"], "confidence": "Product and version match",
    },
    {
        "id": "tomcat-ghostcat",
        "title": "Apache Tomcat AJP exposure (Ghostcat)",
        "severity": "high", "kind": "CVE", "cve": "CVE-2020-1938",
        "services": {"http", "https"}, "product_contains": "tomcat",
        "version_min": "7.0", "version_max": "9.0.30",
        "description": "Tomcat versions before the 2020 fixes can expose files through the AJP connector when port 8009 is reachable.",
        "remediation": "Upgrade Tomcat, disable AJP if unused, or set a required secret on the connector.",
        "references": ["CVE-2020-1938"], "confidence": "Version-based match; confirm patch level",
    },
    {
        "id": "smb-ms17010",
        "title": "SMB service exposed — check MS17-010",
        "severity": "critical", "kind": "CVE", "cve": "CVE-2017-0144",
        "services": {"microsoft-ds", "netbios-ssn"},
        "description": "Unpatched Windows SMBv1 systems are affected by EternalBlue (MS17-010), which enables remote code execution.",
        "remediation": "Apply MS17-010, disable SMBv1 and restrict port 445 at the network boundary.",
        "references": ["MS17-010", "CVE-2017-0144"], "confidence": "Service present; patch level not verified",
    },
    {
        "id": "rdp-bluekeep",
        "title": "RDP exposed — check BlueKeep",
        "severity": "high", "kind": "CVE", "cve": "CVE-2019-0708",
        "services": {"ms-wbt-server"},
        "description": "Older Windows Remote Desktop versions are affected by BlueKeep, a wormable pre-authentication remote code execution flaw.",
        "remediation": "Apply CVE-2019-0708 patches, enable NLA and restrict RDP to trusted IPs.",
        "references": ["CVE-2019-0708"], "confidence": "Service present; OS version not verified",
    },
    {
        "id": "redis-open",
        "title": "Redis service exposed",
        "severity": "high", "kind": "Configuration", "cve": None,
        "services": {"redis"},
        "description": "Redis without authentication or protected-mode allows anyone to read, write or overwrite files on the host.",
        "remediation": "Enable AUTH and protected-mode, bind to localhost and firewall the port.",
        "references": ["CWE-306"], "confidence": "Service identified",
    },
    {
        "id": "mongodb-open",
        "title": "MongoDB service exposed",
        "severity": "high", "kind": "Configuration", "cve": None,
        "services": {"mongodb"},
        "description": "MongoDB instances with authentication disabled expose all databases to anyone who can reach the port.",
        "remediation": "Enable authentication, bind to a private interface and restrict network access.",
        "references": ["CWE-306"], "confidence": "Service identified",
    },
    {
        "id": "elasticsearch-open",
        "title": "Elasticsearch API exposed",
        "severity": "high", "kind": "Configuration", "cve": None,
        "services": {"elasticsearch"}, "product_contains": "elasticsearch",
        "description": "An unauthenticated Elasticsearch API can leak indexed data and allow cluster manipulation.",
        "remediation": "Enable security features, bind to a private interface and use an authenticated reverse proxy.",
        "references": ["CWE-306"], "confidence": "Service or product identified",
    },
    {
        "id": "docker-daemon-open",
        "title": "Unauthenticated Docker API",
        "severity": "critical", "kind": "Configuration", "cve": None,
        "ports": {2375},
        "description": "A Docker daemon API without TLS authentication effectively grants root-level control of the host.",
        "remediation": "Close port 2375, enable TLS mutual authentication and firewall the daemon socket.",
        "references": ["CWE-306"], "confidence": "Port and service identified",
    },
    {
        "id": "jenkins-open",
        "title": "Jenkins console exposed",
        "severity": "high", "kind": "Configuration", "cve": None,
        "product_contains": "jenkins",
        "description": "An unauthenticated Jenkins console allows anyone to run jobs and execute code on build agents.",
        "remediation": "Enable authentication, disable the CLI over HTTP and restrict access behind a VPN or proxy.",
        "references": ["CWE-306"], "confidence": "Product identified",
    },
    {
        "id": "telnet-cleartext",
        "title": "Telnet transmits credentials in cleartext",
        "severity": "high", "kind": "Configuration", "cve": None,
        "services": {"telnet"},
        "description": "Telnet offers no encryption, so credentials and session data can be captured on the network path.",
        "remediation": "Disable Telnet and use SSH instead.",
        "references": ["CWE-319"], "confidence": "Service identified",
    },
    {
        "id": "vnc-cleartext",
        "title": "VNC service exposed",
        "severity": "high", "kind": "Configuration", "cve": None,
        "services": {"vnc"},
        "description": "VNC sessions may be unencrypted and protected only by a short password.",
        "remediation": "Tunnel VNC over SSH or TLS, use strong authentication and firewall the port.",
        "references": ["CWE-319"], "confidence": "Service identified",
    },
    {
        "id": "snmp-default",
        "title": "SNMP service exposed",
        "severity": "medium", "kind": "Configuration", "cve": None,
        "services": {"snmp"},
        "description": "SNMP with default community strings can disclose system, interface and routing information.",
        "remediation": "Use SNMPv3 with authentication and encryption, and restrict source IPs.",
        "references": ["CWE-1188"], "confidence": "Service identified",
    },
    {
        "id": "ftp-cleartext",
        "title": "FTP credentials are not encrypted",
        "severity": "medium", "kind": "Configuration", "cve": None,
        "services": {"ftp"},
        "description": "Plain FTP sends usernames and passwords in cleartext and often allows anonymous access.",
        "remediation": "Use SFTP/FTPS, disable anonymous access where not required, and restrict source IPs.",
        "references": ["CWE-319"], "confidence": "Service identified",
    },
    {
        "id": "memcached-open",
        "title": "Memcached service exposed",
        "severity": "medium", "kind": "Configuration", "cve": None,
        "services": {"memcached"},
        "description": "An exposed Memcached instance can leak cached data and be abused for UDP amplification.",
        "remediation": "Bind to localhost, disable UDP and restrict network access.",
        "references": ["CWE-306"], "confidence": "Service identified",
    },
]


def _version_tuple(value: str):
    numbers = re.findall(r"\d+", str(value or ""))
    return tuple(int(number) for number in numbers[:4]) if numbers else None


def _matches_rule(rule: dict, port_info: dict) -> bool:
    service = str(port_info.get("service") or "").lower()
    product = str(port_info.get("product") or "").lower()
    version = str(port_info.get("version") or "")
    number = int(port_info.get("port", 0))

    if rule.get("ports") and number not in rule["ports"]:
        return False
    services = rule.get("services")
    if services and service not in services and not any(name in product for name in services):
        return False
    if rule.get("product_contains") and rule["product_contains"] not in product:
        return False
    if rule.get("version_equals"):
        expected = {_version_tuple(value) for value in rule["version_equals"]}
        actual = _version_tuple(version)
        if actual is None or not any(actual[:len(item)] == item for item in expected if item):
            return False
    if rule.get("version_min"):
        actual, minimum = _version_tuple(version), _version_tuple(rule["version_min"])
        if actual is None or minimum is None or actual < minimum:
            return False
    if rule.get("version_max"):
        actual, maximum = _version_tuple(version), _version_tuple(rule["version_max"])
        if actual is None or maximum is None or actual > maximum:
            return False
    return True


def find_for_port(port_info: dict) -> list[dict]:
    """Return signature matches for one scanned port."""
    results = []
    for rule in RULES:
        if not _matches_rule(rule, port_info):
            continue
        evidence = "%s/%s open" % (port_info.get("port"), port_info.get("protocol", "tcp"))
        if port_info.get("service"):
            evidence += " · service=" + str(port_info["service"])
        if port_info.get("product"):
            evidence += " · product=" + str(port_info["product"])
        if port_info.get("version"):
            evidence += " · version=" + str(port_info["version"])
        results.append({
            "id": rule["id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "kind": rule["kind"],
            "cve": rule["cve"],
            "port": port_info.get("port"),
            "service": port_info.get("service", "unknown"),
            "product": port_info.get("product", ""),
            "version": port_info.get("version", ""),
            "evidence": evidence,
            "description": rule["description"],
            "remediation": rule["remediation"],
            "references": rule["references"],
            "confidence": rule["confidence"],
        })
    return results


def lookup(ports: list[dict]) -> dict:
    """Check a user-selected subset of open ports against the local signatures."""
    selected = []
    findings: list[dict] = []
    notes: list[str] = []
    for port_info in ports:
        number = port_info.get("port")
        try:
            number = int(number)
        except (TypeError, ValueError):
            continue
        item = {
            "port": number,
            "service": port_info.get("service") or "unknown",
            "product": port_info.get("product", ""),
            "version": port_info.get("version", ""),
        }
        selected.append(item)
        matches = find_for_port({**port_info, "port": number})
        if matches:
            findings.extend(matches)
        else:
            label = item["service"] + (" " + item["version"] if item["version"] else "")
            notes.append("Port %s (%s): no local signature matched. Verify manually." % (number, label.strip()))

    findings.sort(key=lambda finding: SEVERITY_ORDER.get(finding["severity"], 9))
    return {
        "checked_ports": selected,
        "finding_count": len(findings),
        "counts": {name: sum(1 for item in findings if item["severity"] == name)
                   for name in ("critical", "high", "medium", "low", "info")},
        "findings": findings,
        "notes": notes,
        "disclaimer": "Version-based heuristics only. No target was exploited and no CVE was verified.",
    }
