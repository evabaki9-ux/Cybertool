# Cybertool — Port Scan + Vulnerability Lookup

A simple three-step local tool:

1. **Scan** a host's open TCP ports (with `nmap` if installed, otherwise a built-in connect scan).
2. **Select** the open ports you care about.
3. **Check** those services against a small offline list of known CVEs and risky defaults.
4. **Verify safely** a selected finding with a read-only re-probe of the service version.
5. **Open the manual guide** for scoped, step-by-step verification and remediation notes.
6. **CVE lookup** queries public NVD records for the detected product/version.

No exploitation, credential guessing or payloads. Scan only systems you own or have written permission to test.

Built by **evabaki9-ux**.

---

## Web interface

Python 3.10+ is the only requirement; there are no third-party Python packages.

```bash
python -m cybertool serve                 # http://localhost:8000
PORT=9000 python -m cybertool serve
```

Enter a target, tick **I am authorized to scan this target**, choose common ports or all ports,
and run the scan. Open ports appear as a selectable list. Pick the ones to investigate and
click **Check selected ports** to see matching signatures, evidence and fixes.

### Scan engine

- If `nmap` is on `PATH`, Cybertool runs `nmap -sV --open -oX -` and parses its XML output.
  This gives service names, products and versions.
- If `nmap` is not installed, Cybertool falls back to a threaded TCP connect scan with a short
  banner read, so the full flow still works on a normal Python install. Full 65535-port scans
  require nmap.

The UI shows which engine is active on load.

### Local demo

Start fake banners on 127.0.0.1 (ports 2121, 2222 and 8080) to try the whole flow safely:

```bash
python -m cybertool.demo_ports
```

Then click **Use local demo host (127.0.0.1)** in the web UI. The fake services advertise
`vsftpd 2.3.4`, `OpenSSH 7.2p1` and `Apache 2.4.49`, so the lookup step returns real
signature matches without touching anything outside your machine.

## CLI

```bash
python -m cybertool scan 127.0.0.1 --authorized --ports 2121,2222,8080
python -m cybertool scan example.com --authorized --profile full --timeout 120
python -m cybertool vulns --port 21 --service ftp --product vsftpd --version 2.3.4
```

All commands print JSON.

## JSON API

- `GET /api/health` — health check
- `GET /api/status` — reports whether nmap is available
- `POST /api/scan` — `{ "target": "127.0.0.1", "authorized": true, "profile": "top"|"full", "ports": [80], "timeout": 60 }`
- `POST /api/vulns` — `{ "scan_id": "...", "ports": [21, 22] }`
- `POST /api/verify` — `{ "scan_id": "...", "finding_id": "openssh-user-enumeration", "port": 22 }`
- `POST /api/guide` — `{ "finding_id": "openssh-user-enumeration" }`
- `POST /api/cve` — `{ "product": "OpenSSH", "version": "7.2p1" }`

`POST /api/scan` returns a `scan_id` plus the open ports. `POST /api/vulns` checks a subset of
that scan against the local signatures and returns findings with severity, CVE/reference IDs,
description, remediation and confidence.

Scans are kept in memory for the life of the server (last 20 only). The server binds to
`0.0.0.0` by default for preview proxies; use `--host 127.0.0.1` to keep it local.

## What the signature list covers

Examples: vsftpd 2.3.4 backdoor, old OpenSSH user enumeration, Apache 2.4.49/50 path traversal,
Tomcat Ghostcat, SMB/MS17-010, RDP/BlueKeep, exposed Redis/MongoDB/Elasticsearch/Docker/Jenkins,
Telnet/VNC/SNMP/FTP cleartext or default-configuration risks, and exposed Memcached.

### Manual guide

Every finding can open a guide with: what the signature means, safe verification steps,
remediation steps, reference IDs and an authorization reminder. The guides intentionally
contain **no** exploit payloads, credential-attack commands or instructions for executing
commands on a target. They are meant to document an authorized engagement, not perform one.

### Online CVE lookup

The **CVE lookup** button on each finding sends only the detected product and version to the
public NVD API (`services.nvd.nist.gov`) and lists matching CVE candidates with CVSS scores and
links. No target address, scan result or credential is sent. Keyword matches can be noisy —
confirm applicability yourself. Set `NVD_API_KEY` in your environment to use an NVD API key.
When outbound internet is unavailable, the UI shows a clean "unavailable" state and the local
signature list still works.

### Safe verification

`POST /api/verify` and the **Verify safely** button re-check the selected port. When nmap is
installed it runs `nmap -sV` on that single port; otherwise it connects and reads the service
banner (sending only an HTTP `HEAD` for web ports). Version-based signatures are
confirmed only when the live banner still matches; patch-level findings such as SMB/RDP stay
**inconclusive** because they cannot be checked anonymously. No exploit payload, login attempt,
file read or command is ever sent. A confirmation means "this version/signature is present",
not "this host is definitely exploitable".

Matches are heuristics based on what the scan reported. A match is **not** proof of
vulnerability, and no match does not mean the service is safe. Verify manually.

## No open ports locally?

The vulnerable versions in this repo are **fake demo banners**, not real software installed on
your machine. Start them before clicking the demo button:

```bash
python -m cybertool.demo_ports
```

Then scan `127.0.0.1`. Using `localhost` may resolve to IPv6 (`::1`) first on some systems;
the scanner now tries every resolved address, but `127.0.0.1` is the most reliable target.

If you scan a real authorized website, its services are probably patched, so the small local
signature list may find nothing. Use **CVE lookup** for the detected versions, and remember a
version match is only a hint — not proof of vulnerability.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests use local fake listeners and sample nmap XML; they make no external requests.

## Layout

```
cybertool/
  scanner.py      nmap XML parsing + connect fallback
  vulns.py        offline signature list and matching
  verify.py       read-only banner re-probe for findings
  playbook.py     manual verification and remediation guides
  cve_lookup.py   optional public NVD lookup by product/version
  web.py          web UI and JSON API
  __main__.py     CLI
  demo_ports.py   local fake banners for the demo
  static/         dashboard
tests/            scanner, matching and endpoint tests
```
