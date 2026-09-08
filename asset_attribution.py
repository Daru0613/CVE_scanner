"""Conservative, domain-first attribution for passive Internet observations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _same_domain(name: str, hostname: str) -> bool:
    name = name.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    return name == hostname or name.endswith("." + hostname)


def assess_asset_attribution(hostname: str, current_ips: set[str], data: dict[str, Any]) -> list[dict[str, Any]]:
    """Score only evidence already returned by passive providers.

    An IP is never treated as the primary asset.  The score describes how well
    the provider record can be tied back to the requested domain at this time.
    """
    rows: dict[str, dict[str, Any]] = {}
    for key in ("shodan_internetdb", "censys"):
        for source in data.get(key, []):
            ip = str(source.get("ip", ""))
            if not ip:
                continue
            item = rows.setdefault(ip, {"ip": ip, "providers": [], "hostnames": []})
            provider = str(source.get("provider") or key)
            if provider not in item["providers"]:
                item["providers"].append(provider)
            item["hostnames"].extend(str(v).lower().rstrip(".") for v in source.get("hostnames", []) if v)

    results = []
    for ip, item in rows.items():
        names = sorted(set(item["hostnames"]))
        matching = [name for name in names if _same_domain(name, hostname)]
        unrelated = [name for name in names if not _same_domain(name, hostname)]
        score = 0
        evidence = []
        if ip in current_ips:
            score += 45
            evidence.append("현재 DNS A/AAAA 일치")
        if matching:
            score += 30
            evidence.append("외부 색인 호스트명 일치")
        if len(item["providers"]) >= 2:
            score += 10
            evidence.append("Shodan·Censys 동일 IP 관측")
        if unrelated:
            score -= min(35, 10 + len(unrelated) * 5)
            evidence.append(f"무관 호스트명 {len(unrelated)}개 관측")

        # Passive public evidence cannot prove exclusive ownership.  Therefore
        # "dedicated" is explicitly an estimate and requires both DNS and name evidence.
        if unrelated:
            state = "공유호스팅 추정"
        elif ip in current_ips and matching and score >= 70:
            state = "대상 전용 추정"
        else:
            state = "귀속 불명"
        confidence = "높음" if score >= 70 else "보통" if score >= 45 else "낮음"
        results.append({
            "ip": ip, "asset": hostname, "state": state,
            "score": max(0, min(100, score)), "confidence": confidence,
            "evidence": evidence or ["도메인 귀속 근거 없음"],
            "matching_hostnames": matching, "unrelated_hostnames": unrelated[:10],
            "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        })
    return sorted(results, key=lambda row: (-row["score"], row["ip"]))


def build_product_evidence(data: dict[str, Any], attributions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    attribution = {row["ip"]: row for row in attributions}
    results = []
    for key in ("shodan_internetdb", "censys"):
        for row in data.get(key, []):
            ip = str(row.get("ip", ""))
            ownership = attribution.get(ip, {})
            for value in row.get("cpes", []) or row.get("products", []):
                text = str(value)
                # A CPE with a non-wildcard version is the only exact-version
                # evidence accepted automatically. Free-form banners stay unverified.
                parts = text.split(":")
                exact_version = parts[5] if text.startswith("cpe:2.3:") and len(parts) > 5 and parts[5] not in {"", "*", "-"} else ""
                results.append({
                    "ip": ip, "provider": str(row.get("provider") or key), "raw_evidence": text,
                    "exact_version": exact_version, "cpe": text if text.startswith("cpe:") else "",
                    "attribution": ownership.get("state", "귀속 불명"),
                    "decision": "CVE 후보 생성 가능" if exact_version and ownership.get("state") == "대상 전용 추정" else "CVE 매핑 보류",
                })
    return results
