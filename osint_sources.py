"""Read-only enrichment from public Shodan InternetDB and urlscan records."""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


USER_AGENT = "Authorized-Exposure-Triage/0.4"


def unique_values(values, limit: int) -> list[str]:
    """Deduplicate without changing the public source's observation order."""
    result = []
    for value in values:
        text = str(value)
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _json_get(url: str, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if getattr(response, "status", response.getcode()) != 200:
            return {}
        payload = json.load(response)
    return payload if isinstance(payload, dict) else {}


def query_shodan_internetdb(addresses: list[str], timeout: int, limit: int = 2) -> list[dict[str, Any]]:
    """Look up a bounded number of current public IPv4 DNS answers in InternetDB."""
    findings: list[dict[str, Any]] = []
    for address in addresses:
        if len(findings) >= limit:
            break
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.version != 4 or not ip.is_global:
            continue
        try:
            payload = _json_get(f"https://internetdb.shodan.io/{ip}", timeout)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            continue
        if not payload:
            continue
        findings.append({
            "ip": str(ip),
            "ports": sorted({int(port) for port in payload.get("ports", []) if isinstance(port, int)})[:50],
            "hostnames": unique_values((str(value).lower().rstrip(".") for value in payload.get("hostnames", [])), 20),
            "cpes": unique_values(payload.get("cpes", []), 20),
            "vulns": unique_values(payload.get("vulns", []), 30),
            "tags": unique_values(payload.get("tags", []), 20),
            "source": f"https://internetdb.shodan.io/{ip}",
        })
    return findings


def query_urlscan(hostname: str, timeout: int, limit: int = 10) -> list[dict[str, str]]:
    """Search existing public urlscan records; this never submits a new scan."""
    host = hostname.lower().rstrip(".")
    query = urllib.parse.urlencode({"q": f"domain:{host}", "size": str(min(max(limit, 1), 20))})
    try:
        payload = _json_get(f"https://urlscan.io/api/v1/search/?{query}", timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return []
    findings: list[dict[str, str]] = []
    for item in payload.get("results", []):
        if not isinstance(item, dict):
            continue
        page = item.get("page") if isinstance(item.get("page"), dict) else {}
        task = item.get("task") if isinstance(item.get("task"), dict) else {}
        domain = str(page.get("domain") or task.get("domain") or "").lower().rstrip(".")
        if domain != host:
            continue
        uuid = str(item.get("_id") or task.get("uuid") or "")
        findings.append({
            "domain": domain,
            "url": str(page.get("url") or task.get("url") or ""),
            "ip": str(page.get("ip") or ""),
            "server": str(page.get("server") or ""),
            "time": str(task.get("time") or ""),
            "source": f"https://urlscan.io/result/{uuid}/" if uuid else "https://urlscan.io/",
        })
        if len(findings) >= limit:
            break
    return findings


def collect_public_osint(hostname: str, addresses: dict[str, list[str]], timeout: int) -> dict[str, Any]:
    return {
        "shodan_internetdb": query_shodan_internetdb(addresses.get("ipv4", []), timeout),
        "urlscan": query_urlscan(hostname, timeout),
    }
