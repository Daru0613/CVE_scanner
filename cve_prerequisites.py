"""Non-executing CVE/PoC prerequisite review.

Only public text is downloaded.  PoC code is never imported, evaluated,
compiled, or invoked, and a match is never reported as proof of vulnerability.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TEXT_LIMIT = 300_000
USER_AGENT = "Authorized-Exposure-Triage/0.6 (non-executing prerequisite review)"
PATH_RE = re.compile(r"(?<![\w])/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/?){1,8}")
AUTH_RE = re.compile(r"\b(?:auth(?:entication|orization)?|login|session|admin(?:istrator)?)\b", re.I)
CONFIG_RE = re.compile(r"\b(?:module|plugin|extension|feature|setting|configuration|enabled?)\b", re.I)
OS_RE = re.compile(r"\b(?:windows|linux|unix|android|ios|macos|ubuntu|debian|red hat|centos)\b", re.I)


def _get_text(url: str, timeout: int, accept: str = "application/json,text/plain,text/html") -> tuple[str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept}, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(TEXT_LIMIT + 1)
        content_type = response.headers.get("Content-Type", "")
    return raw[:TEXT_LIMIT].decode("utf-8", errors="replace"), content_type


def _raw_github_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.hostname == "github.com" and "/blob/" in parsed.path:
        owner_repo, path = parsed.path.lstrip("/").split("/blob/", 1)
        return f"https://raw.githubusercontent.com/{owner_repo}/{path}"
    return url


def _walk_nodes(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_nodes(child)


def _affected_cpes(cve: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for node in _walk_nodes(cve.get("configurations", [])):
        for match in node.get("cpeMatch", []) if isinstance(node.get("cpeMatch"), list) else []:
            if match.get("vulnerable"):
                rows.append({key: match.get(key, "") for key in (
                    "criteria", "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding",
                )})
    return rows


def _version_tuple(value: str) -> tuple[Any, ...]:
    return tuple(int(part) if part.isdigit() else part.lower()
                 for part in re.findall(r"\d+|[A-Za-z]+", value))


def version_in_range(version: str, affected: dict[str, Any]) -> bool:
    """Conservative comparison for ordinary dotted/alphanumeric versions."""
    if not version:
        return False
    current = _version_tuple(version)
    checks = (
        ("versionStartIncluding", lambda a, b: a >= b),
        ("versionStartExcluding", lambda a, b: a > b),
        ("versionEndIncluding", lambda a, b: a <= b),
        ("versionEndExcluding", lambda a, b: a < b),
    )
    for key, operation in checks:
        boundary = affected.get(key)
        if boundary and not operation(current, _version_tuple(str(boundary))):
            return False
    criteria = str(affected.get("criteria", ""))
    parts = criteria.split(":")
    listed = parts[5] if len(parts) > 5 else ""
    return listed in {"", "*", "-", version} or not any(affected.get(key) for key, _ in checks)


def _cpe_product(cpe: str) -> tuple[str, str, str]:
    parts = cpe.split(":")
    if cpe.startswith("cpe:2.3:") and len(parts) > 5:
        return parts[2], parts[3], parts[4]
    if cpe.startswith("cpe:/") and len(parts) > 4:
        return parts[1].removeprefix("/"), parts[2], parts[3]
    return "", "", ""


def extract_poc_conditions(text: str) -> dict[str, Any]:
    """Extract indicators for analyst comparison, not executable steps."""
    paths = []
    for value in PATH_RE.findall(text):
        if value not in paths and not value.startswith(("//", "/usr/", "/bin/", "/dev/")):
            paths.append(value)
    return {
        "paths": paths[:15],
        "authentication_mentioned": bool(AUTH_RE.search(text)),
        "module_or_configuration_mentioned": bool(CONFIG_RE.search(text)),
        "os_mentions": sorted({match.group(0).lower() for match in OS_RE.finditer(text)})[:10],
    }


def review_candidate(cve_id: str, product: dict[str, Any], timeout: int = 8) -> dict[str, Any]:
    """Compare exact product evidence with NVD and public PoC prerequisites."""
    observed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    base = {
        "cve_id": cve_id, "ip": product.get("ip", ""), "cpe": product.get("cpe", ""),
        "version": product.get("exact_version", ""), "observed_at": observed_at,
        "source": NVD_API, "status": "검증 불가", "confidence": "낮음",
        "poc_references": [], "conditions": {}, "evidence": [],
        "notice": "PoC 미실행; 조건 일치는 실제 취약 또는 악용의 증거가 아님",
    }
    if product.get("attribution") != "대상 전용 추정" or not product.get("cpe") or not product.get("exact_version"):
        base["evidence"].append("대상 전용 귀속·정확한 버전·CPE 조건 미충족")
        return base
    try:
        query = urllib.parse.urlencode({"cveId": cve_id})
        text, _ = _get_text(f"{NVD_API}?{query}", timeout)
        payload = json.loads(text)
        cve = payload.get("vulnerabilities", [{}])[0].get("cve", {})
    except (IndexError, KeyError, ValueError, json.JSONDecodeError, urllib.error.URLError, OSError, TimeoutError) as error:
        base["evidence"].append(f"NVD 수집 실패: {type(error).__name__}")
        return base
    affected = _affected_cpes(cve)
    observed_identity = _cpe_product(str(product.get("cpe", "")))
    matching = [row for row in affected
                if _cpe_product(str(row.get("criteria", ""))) == observed_identity
                and version_in_range(str(product.get("exact_version", "")), row)]
    base["evidence"].append(f"NVD 영향 CPE 범위 {len(affected)}건, 버전 범위 일치 {len(matching)}건")
    refs = [ref.get("url", "") for ref in cve.get("references", [])
            if isinstance(ref, dict) and "Exploit" in ref.get("tags", []) and ref.get("url")]
    base["poc_references"] = refs[:10]
    condition_sets = []
    for url in refs[:3]:
        try:
            poc_text, _ = _get_text(_raw_github_url(url), timeout)
            condition_sets.append(extract_poc_conditions(poc_text))
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            continue
    if condition_sets:
        base["conditions"] = {
            "paths": sorted({path for row in condition_sets for path in row["paths"]})[:15],
            "authentication_mentioned": any(row["authentication_mentioned"] for row in condition_sets),
            "module_or_configuration_mentioned": any(row["module_or_configuration_mentioned"] for row in condition_sets),
            "os_mentions": sorted({value for row in condition_sets for value in row["os_mentions"]})[:10],
        }
    if matching:
        base["status"] = "버전 일치"
        base["confidence"] = "중간"
        if condition_sets:
            base["status"] = "전제조건 일부 일치"
            base["evidence"].append("공개 PoC 텍스트에서 전제조건 단서를 추출했으나 대상 충족 여부는 별도 관찰 필요")
    else:
        base["evidence"].append("관측 버전이 NVD 영향 범위에 포함된다는 근거 없음")
    return base


def review_external_candidates(data: dict[str, Any], timeout: int = 8, limit: int = 10) -> list[dict[str, Any]]:
    products = data.get("product_evidence", [])
    by_ip = {}
    for product in products:
        if product.get("decision") == "CVE 후보 생성 가능":
            by_ip.setdefault(product.get("ip"), []).append(product)
    results = []
    for source in data.get("shodan_internetdb", []):
        for cve_id in source.get("vulns", []):
            for product in by_ip.get(source.get("ip"), []):
                results.append(review_candidate(str(cve_id), product, timeout))
                if len(results) >= limit:
                    return results
    return results
