"""Optional online CVE lookup by product/version using the public NVD API.

This is a read-only public lookup. It never sends target addresses, scan results
or credentials. If outbound internet is blocked, it returns a clean unavailable
state and the local signatures keep working.
"""

from __future__ import annotations

import json
import os
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "Cybertool/0.3 (local version lookup)"
UNAVAILABLE_NOTE = (
    "External lookup is unavailable here. Install/run Cybertool on a machine with internet "
    "access, or use the local signature matches and manual guide."
)


def _clean_query(product: str, version: str) -> str:
    text = re.sub(r"[^A-Za-z0-9.\- ]+", " ", "%s %s" % (product, version))
    return re.sub(r"\s+", " ", text).strip()[:120]


def _score_and_severity(cve: dict):
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = entries[0]
        cvss = entry.get("cvssData") or {}
        score = cvss.get("baseScore", entry.get("baseScore"))
        severity = cvss.get("baseSeverity") or entry.get("baseSeverity") or ""
        return score, severity
    return None, ""


def lookup(product: str, version: str = "", timeout: float = 8, limit: int = 10) -> dict:
    """Look up public CVEs for a product/version string."""
    query = _clean_query(str(product or ""), str(version or ""))
    if not query:
        raise ValueError("A product or version is required for lookup")

    params = urlencode({"keywordSearch": query, "resultsPerPage": max(1, min(int(limit), 20))})
    url = NVD_ENDPOINT + "?" + params
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        request = Request(url, headers=headers)
        with urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, ssl.SSLError, ValueError, json.JSONDecodeError) as exc:
        reason = getattr(exc, "reason", exc)
        return {
            "source": "NVD",
            "query": query,
            "available": False,
            "error": str(reason),
            "note": UNAVAILABLE_NOTE,
            "results": [],
        }

    results = []
    for entry in payload.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        description = next(
            (item.get("value", "") for item in cve.get("descriptions", []) if item.get("lang") == "en"),
            "",
        )
        score, severity = _score_and_severity(cve)
        results.append({
            "id": cve_id,
            "score": score,
            "severity": severity,
            "description": description[:400],
            "published": str(cve.get("published", ""))[:10],
            "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
        })

    results.sort(key=lambda item: (item["score"] if item["score"] is not None else -1), reverse=True)
    return {
        "source": "NVD",
        "query": query,
        "available": True,
        "result_count": len(results),
        "results": results[:limit],
        "note": "Public CVE candidates matched by keyword. Confirm applicability yourself; keyword matches can be noisy.",
    }
