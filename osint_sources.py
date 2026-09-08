"""Passive, read-only enrichment from third-party Internet indexes.

No provider is asked to rescan a target. Secrets returned by credential-intel
providers are discarded in memory and are never included in the result.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from asset_attribution import assess_asset_attribution, build_product_evidence


USER_AGENT = "Authorized-Exposure-Triage/0.5"
PRIVILEGED_NAMES = {
    "admin", "administrator", "root", "sysadmin", "system", "superuser",
    "webmaster", "owner", "security", "itadmin", "manager",
}


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


def _request(url: str, timeout: int, headers: dict[str, str] | None = None) -> tuple[Any, str]:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(2_000_000)
        content_type = response.headers.get("Content-Type", "")
    text = raw.decode("utf-8-sig", errors="replace")
    if "json" in content_type.lower() or text.lstrip().startswith(("{", "[")):
        return json.loads(text), content_type
    return text, content_type


def _json_get(url: str, timeout: int, headers: dict[str, str] | None = None) -> dict[str, Any]:
    payload, _ = _request(url, timeout, headers)
    return payload if isinstance(payload, dict) else {}


def _usable_ips(addresses: list[str], limit: int = 2) -> list[str]:
    result = []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.version == 4 and ip.is_global:
            result.append(str(ip))
        if len(result) >= limit:
            break
    return result


def query_shodan_internetdb(addresses: list[str], timeout: int, limit: int = 2) -> list[dict[str, Any]]:
    """Look up current DNS answers in Shodan InternetDB; no active scan is submitted."""
    findings: list[dict[str, Any]] = []
    for address in _usable_ips(addresses, limit):
        try:
            payload = _json_get(f"https://internetdb.shodan.io/{address}", timeout)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            continue
        if payload:
            findings.append({
                "provider": "shodan", "ip": address,
                "ports": sorted({int(port) for port in payload.get("ports", []) if isinstance(port, int)})[:50],
                "hostnames": unique_values((str(value).lower().rstrip(".") for value in payload.get("hostnames", [])), 20),
                "products": unique_values(payload.get("cpes", []), 20),
                "cpes": unique_values(payload.get("cpes", []), 20),
                "vulns": unique_values(payload.get("vulns", []), 30),
                "observed_at": "", "source": f"https://internetdb.shodan.io/{address}",
            })
    return findings


def _walk_key(payload: Any, key: str):
    if isinstance(payload, dict):
        for name, value in payload.items():
            if name.lower() == key:
                yield value
            yield from _walk_key(value, key)
    elif isinstance(payload, list):
        for value in payload:
            yield from _walk_key(value, key)


def query_censys(addresses: list[str], timeout: int, token: str, limit: int = 2) -> list[dict[str, Any]]:
    """Use Censys Platform's passive host lookup endpoint."""
    findings = []
    for address in _usable_ips(addresses, limit):
        url = f"https://api.platform.censys.io/v3/global/asset/host/{address}"
        payload = _json_get(url, timeout, {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        })
        resource = payload.get("result", {}).get("resource", payload.get("result", payload))
        ports = set()
        products = []
        for services in _walk_key(resource, "services"):
            if not isinstance(services, list):
                continue
            for service in services:
                if not isinstance(service, dict):
                    continue
                port = service.get("port")
                if isinstance(port, int) or str(port).isdigit():
                    ports.add(int(port))
                for field in ("service_name", "extended_service_name", "product", "software"):
                    value = service.get(field)
                    if isinstance(value, str):
                        products.append(value)
                    elif isinstance(value, dict):
                        products.extend(str(v) for k, v in value.items()
                                        if k in {"product", "vendor", "version"} and isinstance(v, (str, int)))
        names = []
        for key in ("names", "hostnames", "dns_names"):
            for value in _walk_key(resource, key):
                if isinstance(value, list):
                    names.extend(str(item).lower().rstrip(".") for item in value if isinstance(item, str))
        observed = next((str(value) for key in ("last_updated_at", "observed_at")
                         for value in _walk_key(resource, key) if value), "")
        findings.append({
            "provider": "censys", "ip": address, "ports": sorted(ports)[:50],
            "hostnames": unique_values(names, 20), "products": unique_values(products, 20),
            "vulns": [], "observed_at": observed, "source": url,
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
    findings = []
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
            "domain": domain, "url": str(page.get("url") or task.get("url") or ""),
            "ip": str(page.get("ip") or ""), "server": str(page.get("server") or ""),
            "time": str(task.get("time") or ""),
            "source": f"https://urlscan.io/result/{uuid}/" if uuid else "https://urlscan.io/",
        })
        if len(findings) >= limit:
            break
    return findings


def query_urlscan_cohosts(addresses: list[str], timeout: int, limit: int = 20) -> list[dict[str, str]]:
    """Return historical domains indexed on the IP; no scan is submitted."""
    findings = []
    for address in _usable_ips(addresses, 2):
        query = urllib.parse.urlencode({"q": f"ip:{address}", "size": str(min(max(limit, 1), 50))})
        payload = _json_get(f"https://urlscan.io/api/v1/search/?{query}", timeout)
        for item in payload.get("results", []):
            if not isinstance(item, dict):
                continue
            page = item.get("page") if isinstance(item.get("page"), dict) else {}
            task = item.get("task") if isinstance(item.get("task"), dict) else {}
            domain = str(page.get("domain") or task.get("domain") or "").lower().rstrip(".")
            if not domain or str(page.get("ip") or "") != address:
                continue
            row = {"provider": "urlscan", "ip": address, "domain": domain,
                   "url": str(page.get("url") or task.get("url") or ""),
                   "observed_at": str(task.get("time") or ""), "source": "https://urlscan.io/"}
            if not any(old["ip"] == address and old["domain"] == domain for old in findings):
                findings.append(row)
            if len(findings) >= limit:
                return findings
    return findings


def _mask_account(value: str) -> str:
    value = value.strip()
    if "@" in value:
        local, domain = value.rsplit("@", 1)
        return (local[:1] + "***" if local else "***") + "@" + domain.lower()
    return value[:1] + "***" if value else "***"


def _is_privileged(value: str) -> bool:
    local = value.rsplit("@", 1)[0].lower()
    normalized = re.sub(r"[^a-z0-9]", "", local)
    return normalized in PRIVILEGED_NAMES or any(normalized.startswith(name) for name in PRIVILEGED_NAMES)


def _row_suggests_privileged(account: str, row: dict[str, Any]) -> bool:
    if _is_privileged(account):
        return True
    context = " ".join(str(value) for key, value in row.items()
                       if any(word in str(key).lower() for word in ("url", "host", "service")))
    return bool(re.search(r"(?:^|[/._-])(?:admin|administrator|sysadmin|controlpanel|cpanel)(?:$|[/._?&=-])",
                          context, re.IGNORECASE))


def _account_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("accounts", "records", "results", "data", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
        return [payload]
    if isinstance(payload, str):
        return [dict(row) for row in csv.DictReader(io.StringIO(payload))]
    return []


def query_intelx_accounts(hostname: str, timeout: int, api_key: str, api_base: str) -> dict[str, Any]:
    """Summarize leaked accounts without retaining passwords, tokens, or raw rows."""
    host = hostname.lower().rstrip(".")
    params = urllib.parse.urlencode({"selector": host, "timeout": str(min(max(timeout, 1), 30)), "limit": "100"})
    url = api_base.rstrip("/") + "/accounts/1?" + params
    payload, _ = _request(url, timeout + 5, {"X-Key": api_key, "Accept": "application/json,text/csv"})
    rows = _account_records(payload)
    accounts = []
    account_hashes = set()
    privileged = []
    privileged_hashes = set()
    discarded_secret_fields = 0
    for row in rows:
        lowered = {str(key).lower(): value for key, value in row.items()}
        discarded_secret_fields += sum(1 for key, value in lowered.items()
                                       if any(word in key for word in ("password", "passwd", "pwd", "token", "secret")) and value)
        account = next((str(lowered[key]) for key in ("email", "account", "username", "user", "login")
                        if key in lowered and lowered[key]), "")
        if not account:
            account = next((str(value) for value in lowered.values()
                            if isinstance(value, str) and re.fullmatch(r"[^@\s]+@[^@\s]+", value)), "")
        if not account:
            continue
        masked = _mask_account(account)
        accounts.append(masked)
        account_hash = hashlib.sha256(account.strip().lower().encode()).digest()
        account_hashes.add(account_hash)
        if _row_suggests_privileged(account, lowered):
            privileged.append(masked)
            privileged_hashes.add(account_hash)
    unique = unique_values(accounts, 100)
    return {
        "status": "collected", "provider": "Intelligence X", "records_seen": len(rows),
        "unique_accounts": len(account_hashes), "masked_accounts": unique[:20],
        "privileged_count": len(privileged_hashes), "privileged_candidates": unique_values(privileged, 20),
        "secret_fields_discarded": discarded_secret_fields,
        "source": f"{api_base.rstrip('/')}/",
        "notice": "원문 비밀번호·토큰·비밀값은 메모리에서 폐기했으며 보고서에 저장하지 않음",
    }


def build_cross_validation(data: dict[str, Any], current_ips: set[str]) -> list[dict[str, Any]]:
    by_ip: dict[str, dict[str, Any]] = {}
    for key in ("shodan_internetdb", "censys"):
        for row in data.get(key, []):
            ip = str(row.get("ip", ""))
            if not ip:
                continue
            item = by_ip.setdefault(ip, {"ip": ip, "providers": [], "ports_by_provider": {}})
            provider = str(row.get("provider") or key)
            if provider not in item["providers"]:
                item["providers"].append(provider)
            ports = set(item["ports_by_provider"].get(provider, []))
            ports.update(port for port in row.get("ports", []) if isinstance(port, int))
            item["ports_by_provider"][provider] = sorted(ports)
    results = []
    for item in by_ip.values():
        count = len(item["providers"])
        item["agreement"] = "3개 출처 일치" if count == 3 else "2개 출처 일치" if count == 2 else "단일 출처 관측"
        item["current_dns_match"] = item["ip"] in current_ips
        results.append(item)
    return sorted(results, key=lambda row: (-len(row["providers"]), row["ip"]))


def collect_public_osint(hostname: str, addresses: dict[str, list[str]], timeout: int,
                         credential_intel: bool = False) -> dict[str, Any]:
    """Collect passive indexes. Provider failures are isolated and summarized."""
    data: dict[str, Any] = {"collection_status": {}, "collection_evidence": {}}

    def error_label(error: Exception) -> str:
        if isinstance(error, urllib.error.HTTPError):
            return f"HTTP {error.code}"
        return type(error).__name__

    def normalized_error(error: Exception) -> str:
        if isinstance(error, urllib.error.HTTPError) and error.code in {401, 403}:
            return "접근 거부"
        if isinstance(error, (TimeoutError,)):
            return "시간 초과"
        if isinstance(error, urllib.error.URLError) and isinstance(error.reason, TimeoutError):
            return "시간 초과"
        if isinstance(error, (urllib.error.URLError, OSError)):
            return "연결 실패"
        if isinstance(error, (ValueError, json.JSONDecodeError)):
            return "파서 오류"
        return "연결 실패"

    providers = [
        ("shodan_internetdb", lambda: query_shodan_internetdb(addresses.get("ipv4", []), timeout), True),
        ("censys", lambda: query_censys(addresses.get("ipv4", []), timeout, os.getenv("CENSYS_API_TOKEN", "")), bool(os.getenv("CENSYS_API_TOKEN"))),
        ("urlscan", lambda: query_urlscan(hostname, timeout), True),
        ("urlscan_cohosts", lambda: query_urlscan_cohosts(addresses.get("ipv4", []), timeout), True),
    ]
    for name, operation, configured in providers:
        if not configured:
            data[name] = []
            data["collection_status"][name] = "미설정(API 키 필요)"
            data["collection_evidence"][name] = {"state": "미설정", "attempts": 0}
            continue
        try:
            data[name] = operation()
            state = "수집 성공" if data[name] else "결과 없음"
            data["collection_status"][name] = f"{state}({len(data[name])}건)"
            data["collection_evidence"][name] = {
                "state": state, "attempts": 1,
                "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "raw_evidence": f"응답 파싱 완료; 결과 {len(data[name])}건", "error": "",
            }
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
            data[name] = []
            state = normalized_error(error)
            data["collection_status"][name] = f"{state}({error_label(error)})"
            data["collection_evidence"][name] = {
                "state": state, "attempts": 1,
                "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "raw_evidence": "응답 본문 미저장(비밀값 보호)", "error": error_label(error),
            }
    if credential_intel:
        key = os.getenv("INTELX_API_KEY", "")
        if not key:
            data["credential_exposure"] = {"status": "미설정", "notice": "INTELX_API_KEY 필요"}
        else:
            try:
                data["credential_exposure"] = query_intelx_accounts(
                    hostname, timeout, key, os.getenv("INTELX_API_BASE", "https://free.intelx.io")
                )
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
                data["credential_exposure"] = {"status": "수집 실패", "notice": error_label(error)}
    current_ips = set(addresses.get("ipv4", [])) | set(addresses.get("ipv6", []))
    data["cross_validation"] = build_cross_validation(data, current_ips)
    data["asset_attribution"] = assess_asset_attribution(hostname, current_ips, data)
    data["product_evidence"] = build_product_evidence(data, data["asset_attribution"])
    return data
