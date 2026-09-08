#!/usr/bin/env python3
"""Defensive breach-source triage scanner.

This tool performs non-invasive HTTP metadata collection and compares it with
the shape of a supplied, sanitized data sample. It does not authenticate,
submit credentials, exploit vulnerabilities, or download breach content.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from summary_report import report_path, write_report
from sample_input import rows_from_csv
from asm_inventory import build_inventory, connection_error
from manual_review import collect_review
from env_config import load_local_env
from passive_asm import (analyze_cookies, analyze_security_headers, automatic_assessment,
                         resolve_addresses)
from osint_sources import collect_public_osint
from historical_asm import collect_historical, probe_live_status
from cve_prerequisites import review_external_candidates


FIELD_RULES: dict[str, tuple[str, ...]] = {
    "identity": ("email", "username", "user", "login", "account"),
    "credential": ("password", "passwd", "pwd", "password_hash", "hash", "salt"),
    "session": ("session", "cookie", "token", "jwt", "refresh"),
    "network": ("ip", "user_agent", "ua", "referer", "host"),
    "personal": ("name", "phone", "mobile", "address", "birth", "ssn"),
    "business": ("order", "invoice", "payment", "customer", "account_id"),
    "cloud_secret": ("api_key", "apikey", "access_key", "secret_key", "bucket"),
    "audit": ("created", "updated", "last_login", "timestamp", "logged_at"),
}

SENSITIVE_CATEGORIES = {"credential", "session", "cloud_secret"}
TECH_PATTERNS = {
    "wordpress": re.compile(r"wordpress|wp-content|wp-includes", re.I),
    "nginx": re.compile(r"nginx(?:/([\d.]+))?", re.I),
    "apache": re.compile(r"apache(?:/([\d.]+))?", re.I),
    "iis": re.compile(r"microsoft-iis(?:/([\d.]+))?", re.I),
    "php": re.compile(r"php(?:/([\d.]+))?", re.I),
    "express": re.compile(r"express", re.I),
    "jquery": re.compile(r"jquery(?:-|\.)([\d.]+)(?:\.min)?\.js", re.I),
}


@dataclass
class SiteObservation:
    url: str
    final_url: str = ""
    status: str = "not_checked"
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    surface_results: list[dict[str, str]] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    inventory: list[dict[str, str]] = field(default_factory=list)
    manual_review: dict[str, Any] | None = None
    security_headers: list[dict[str, str]] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    addresses: dict[str, list[str]] = field(default_factory=lambda: {"ipv4": [], "ipv6": []})
    automatic: dict[str, Any] | None = None
    claim: dict[str, str] = field(default_factory=dict)
    linked_pages: list[dict[str, str]] = field(default_factory=list)
    external_osint: dict[str, Any] = field(default_factory=dict)
    historical_asm: dict[str, Any] = field(default_factory=dict)
    live_status: dict[str, Any] = field(default_factory=dict)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rows_from_json(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for key in ("rows", "data", "records", "results", "items"):
            if isinstance(payload.get(key), list):
                rows = payload[key]
                break
        else:
            rows = [payload]
    else:
        raise ValueError("JSON root must be an object or an array")

    if not rows or not all(isinstance(row, dict) for row in rows):
        raise ValueError("JSON must contain one or more object records")
    return rows


def load_sample(path: Path, encoding: str = "utf-8-sig") -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding=encoding)
    except UnicodeDecodeError:
        raise ValueError("Cannot decode sample; for Korean legacy CSV try --encoding cp949") from None
    if text.lstrip().startswith(("{", "[")) or path.suffix.lower() == ".json":
        return rows_from_json(json.loads(text))
    return rows_from_csv(text)


def classify_field(field_name: str) -> str:
    leaf = field_name.rsplit(".", 1)[-1].replace("[]", "")
    leaf = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", leaf)
    normalized = re.sub(r"[^a-z0-9]", "_", leaf.lower()).strip("_")
    member_fields = {
        "mb_no": "identity", "mb_id": "identity", "mb_nick": "identity",
        "mb_hp": "personal", "mb_tel": "personal", "mb_jumin": "personal",
        "mb_sex": "personal", "mb_zip1": "personal", "mb_zip2": "personal",
        "mb_addr1": "personal", "mb_addr2": "personal", "mb_addr3": "personal",
        "mb_addr_jibeon": "personal", "mb_lost_certify": "credential",
        "mb_addr": "personal", "mb_zip": "personal", "mb_buseo": "business",
    }
    if normalized in member_fields:
        return member_fields[normalized]
    # Exact compound names take priority over generic tokens such as 'user'.
    for category, keywords in FIELD_RULES.items():
        if normalized in keywords:
            return category
    tokens = set(normalized.split("_"))
    for category in ("cloud_secret", "credential", "session", "network", "audit", "business", "identity", "personal"):
        if any(set(keyword.split("_")).issubset(tokens) for keyword in FIELD_RULES[category]):
            return category
    return "other"


def flatten_record(row: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in row.items():
        # Escape separators so literal dotted keys cannot overwrite nested fields.
        name = str(name).replace("~", "~0").replace(".", "~1")
        path = f"{prefix}.{name}" if prefix else name
        if isinstance(value, dict) and value:
            result.update(flatten_record(value, path))
        else:
            result[path] = value
    return result


def value_type(value: Any) -> str:
    return type(value).__name__


def infer_schema(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [flatten_record(row) for row in rows]
    result = []
    for name in sorted({name for row in rows for name in row}):
        values = [row[name] for row in rows if name in row and row[name] not in (None, "")]
        result.append({
            "field": name,
            "category": classify_field(name),
            "present_in_rows": sum(name in row for row in rows),
            "nonempty_in_rows": len(values),
            "sample_types": sorted({value_type(value) for value in values}),
        })
    return result


def validate_site(url: str) -> str:
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("site must be an http(s) URL or hostname")
    if parsed.username or parsed.password:
        raise ValueError("site URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("site URL must not contain query parameters or fragments")
    _ = parsed.port
    return urllib.parse.urlunparse(parsed)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def collect_response(observation: SiteObservation, response: Any) -> None:
    observation.final_url = response.geturl()
    observation.status = str(response.code)
    observation.security_headers = analyze_security_headers(response.headers, urllib.parse.urlsplit(observation.final_url).scheme)
    observation.cookies = analyze_cookies(response.headers)
    allowed = {"server", "x-powered-by", "content-type", "strict-transport-security", "via", "cache-control"}
    observation.headers = {key.lower(): value for key, value in response.headers.items() if key.lower() in allowed}
    body = response.read(250_000).decode("utf-8", errors="ignore")
    # Product banners are hints, not evidence of the origin server or vulnerability.
    detect_technologies(observation, "\n".join(observation.headers.values()) + "\n" + body)
    # Endpoint enumeration is outside scope. Only the explicitly supplied root
    # page is read for passive product hints and HTTP security metadata.
    if re.search(r"(?:src|href)=[\"'][^\"']*/wp-(?:content|includes)/", body, re.I):
        observation.technologies.append("wordpress")
    if 300 <= response.code < 400:
        observation.notes.append("redirect not followed; inspect the destination separately if in scope")


def fetch_site(url: str, timeout: int) -> SiteObservation:
    normalized_url = validate_site(url)
    observation = SiteObservation(url=normalized_url)
    request = urllib.request.Request(
        normalized_url,
        headers={"User-Agent": "Authorized-Exposure-Triage/0.1"},
        method="GET",
    )
    try:
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        with opener.open(request, timeout=timeout) as response:
            collect_response(observation, response)
    except urllib.error.HTTPError as response:
        with response:
            collect_response(observation, response)
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as error:
        observation.status = "error"
        observation.notes.append(connection_error(error))
    return observation


def check_https(site: str, timeout: int) -> dict[str, str]:
    parsed = urllib.parse.urlsplit(site)
    # Do not invent a TLS port for explicitly scoped nonstandard ports.
    if parsed.port not in (None, 80):
        return {"url": "HTTPS", "state": "미점검", "evidence": "사용자 지정 포트; HTTPS 주소 미지정", "action": "담당자에게 HTTPS 주소 확인"}
    host = f'[{parsed.hostname}]' if ':' in parsed.hostname else parsed.hostname
    url = urllib.parse.urlunsplit(('https', host, parsed.path or '/', '', ''))
    request = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'Authorized-Exposure-Triage/0.3'})
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return {"url": url, "state": "관찰됨", "evidence": f"인증서 검증 통과; HEAD HTTP {response.code}", "action": "실제 서비스와 리다이렉트 정책 확인"}
    except (urllib.error.URLError, OSError) as error:
        return {"url": url, "state": "추가 확인", "evidence": connection_error(error), "action": "인증서·DNS·연결 설정 확인"}


def sample_paths(args) -> list[Path]:
    if args.sample:
        return [args.sample]
    if not args.sample_dir.is_dir():
        raise ValueError('자료 폴더가 없습니다')
    paths = sorted((path for path in args.sample_dir.iterdir() if path.is_file() and path.suffix.lower() == '.txt'), key=lambda path: path.name.casefold())
    if not paths:
        raise ValueError('자료 폴더에 TXT 파일이 없습니다')
    return paths


def load_samples(paths, encoding):
    rows, sources = [], []
    for path in paths:
        try:
            current = load_sample(path, encoding)
        except (ValueError, OSError) as error:
            raise ValueError(f'{path.name}: {error}') from None
        schema = infer_schema(current)
        sources.append({'name': path.name, 'records': len(current), 'schema': schema})
        rows.extend(current)
    return rows, sources


def detect_technologies(observation: SiteObservation, text: str) -> None:
    for technology, pattern in TECH_PATTERNS.items():
        match = pattern.search(text)
        if match:
            version = match.group(1) if match.lastindex else None
            value = f"{technology} {version}" if version else technology
            if value not in observation.technologies:
                observation.technologies.append(value)


def build_findings(
    schema: list[dict[str, Any]],
    observation: SiteObservation,
    cve_candidates: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    categories = {item["category"] for item in schema}
    findings: list[dict[str, str]] = []

    def add(vector: str, evidence: str, confidence: str, next_check: str) -> None:
        findings.append(
            {
                "site": observation.final_url or observation.url,
                "http_status": observation.status,
                "observation_notes": "; ".join(observation.notes),
                "finding_type": "schema hypothesis; site ownership of sample unverified",
                "data_categories": ", ".join(sorted(categories)),
                "possible_exposure_point": vector,
                "evidence": evidence,
                "confidence": confidence,
                "related_technology": ", ".join(observation.technologies),
                "cve_status": "see CVE candidates section; no causal link established" if cve_candidates else "not queried / no technology identified",
                "recommended_check": next_check,
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            }
        )

    if "credential" in categories:
        add(
            "application database, backup, or admin export",
            "credential-shaped fields detected in supplied sample",
            "low",
            "compare field names and record timestamps with DB audit logs and backup access logs",
        )
    if "session" in categories:
        add(
            "application logs, session store, or support export",
            "session/token-shaped fields detected in supplied sample",
            "low",
            "check log redaction, session-store access, and token revocation history",
        )
    if "cloud_secret" in categories:
        add(
            "source repository, CI/CD secret, or cloud storage configuration",
            "cloud credential-shaped fields detected in supplied sample",
            "low",
            "review secret-manager audit events and rotate exposed credentials immediately",
        )
    if {"identity", "personal"}.intersection(categories):
        add(
            "customer/user database or API response",
            "identity or personal-data fields detected in supplied sample",
            "low",
            "compare API access logs, export jobs, and database query audit records",
        )
    if not findings:
        add(
            "unknown; insufficient structural evidence",
            "no recognized sensitive field category",
            "low",
            "obtain a sanitized schema and the suspected exposure time window",
        )
    return findings


def markdown_text(value: Any) -> str:
    text = "".join(f"&#{ord(character)};" if character in "\\`*_{}[]()#+-.!|" else html.escape(character, quote=True)
                   for character in str(value))
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")


def write_schema(path: Path, schema: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(schema, handle, ensure_ascii=True, indent=2)
        handle.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authorized breach-source triage scanner")
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--sample", type=Path, help="sanitized JSON, CSV, or pasted CSV text")
    inputs.add_argument("--sample-dir", type=Path, help="combine all TXT files directly inside this site's folder")
    inputs.add_argument("--site-only", action="store_true",
                        help="run non-invasive site/ASM checks without a supplied data sample")
    parser.add_argument("--encoding", choices=("utf-8-sig", "cp949", "euc-kr"), default="utf-8-sig", help="sample text encoding")
    parser.add_argument("--site", required=True, help="authorized site URL or hostname")
    parser.add_argument("--output", type=Path, help="Markdown report path (default: site-named file in report folder)")
    parser.add_argument("--schema-output", type=Path, help="default: alongside report as .schema.json")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--offline", action="store_true", help="analyze schema only; no network requests")
    parser.add_argument("--surface-checks", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--asm", action="store_true", help="run passive site metadata, external-index and historical ASM checks")
    parser.add_argument("--mode", choices=("live", "historical", "full"), default="full",
                        help="ASM mode (default: full; unreachable live targets automatically use historical)")
    parser.add_argument("--no-osint", action="store_true", help="disable Shodan, Censys, urlscan and credential-intel lookups")
    parser.add_argument("--credential-intel", action="store_true",
                        help="query Intelligence X for leaked accounts; masks accounts and discards all secret values")
    parser.add_argument("--manual-review", action="store_true", help="after scanning, answer six manual verification missions")
    parser.add_argument("--claim-date", default="", help="claimed post date/time for report context")
    parser.add_argument("--claim-source", default="", help="forum or source name for report context")
    parser.add_argument("--claim-url", default="", help="public reference URL for the claim (recorded only; not requested)")
    parser.add_argument("--claim-summary", default="", help="short description of the claimed leak")
    parser.add_argument("--company", default="", help="company or service name shown in the report")
    parser.add_argument("--confirmed-leak", dest="confirmed_leak", action="store_true", default=True,
                        help="mark supplied data as shared leaked data (default)")
    parser.add_argument("--unverified-claim", dest="confirmed_leak", action="store_false",
                        help="treat the supplied material as an unverified claim")
    parser.add_argument(
        "--nvd",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--cve-review", action="store_true",
        help="non-executing NVD/public-PoC prerequisite review for exactly versioned, dedicated assets",
    )
    return parser.parse_args()


def main() -> int:
    # Keep Korean mission prompts readable in Windows Terminal and redirected logs.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if reconfigure:
            reconfigure(encoding='utf-8')
    load_local_env()
    args = parse_args()
    try:
        if args.timeout <= 0:
            raise ValueError("timeout must be positive")
        if args.surface_checks:
            raise ValueError("--surface-checks is disabled: endpoint scanning is outside the approved scope")
        if args.nvd:
            raise ValueError("--nvd is disabled: vulnerability verification is outside the approved scope")
        if args.cve_review and (args.offline or args.no_osint or not args.asm):
            raise ValueError("--cve-review requires --asm and cannot be combined with --offline or --no-osint")
        if args.credential_intel and (args.offline or args.no_osint or not args.asm):
            raise ValueError("--credential-intel requires --asm and cannot be combined with --offline or --no-osint")
        site = validate_site(args.site)
        inputs = [] if args.site_only else sample_paths(args)
        # Keep every target's artifacts together, regardless of whether its
        # sanitized input arrived as one file or a folder of TXT files.
        name = report_path(site).stem.removeprefix('www.')
        default_output = Path('보고서') / name / f'{name}_통합.md'
        args.output = args.output or default_output
        args.schema_output = args.schema_output or args.output.with_suffix('.schema.json')
        historical_output = args.output.with_suffix('.historical.json')
        paths = [path.resolve() for path in inputs] + [args.output.resolve(), args.schema_output.resolve(), historical_output.resolve()]
        if len(set(paths)) != len(paths):
            raise ValueError("input and output paths must be distinct")
        if args.site_only:
            rows, sources, schema = [], [], []
            print('site-only mode: no sample data loaded')
        else:
            rows, sources = load_samples(inputs, args.encoding)
            schema = infer_schema(rows)
            print(f'loaded {len(sources)} sample files; {len(rows)} records')
        observation = SiteObservation(url=site, status="offline", notes=["no site evidence collected"]) if args.offline else fetch_site(site, args.timeout)
        if not args.offline:
            observation.addresses = resolve_addresses(urllib.parse.urlsplit(site).hostname)
            if args.asm:
                print('checking HTTP and HTTPS live status...')
                observation.live_status = probe_live_status(urllib.parse.urlsplit(site).hostname, args.timeout)
                if observation.status == 'error':
                    live_status = observation.live_status
                    alternate = next((row['url'] for row in observation.live_status.get('protocols', [])
                                      if row.get('status') in {'LIVE', 'REDIRECT'}), '')
                    if alternate and alternate != site:
                        observation = fetch_site(alternate, args.timeout)
                        observation.addresses = resolve_addresses(urllib.parse.urlsplit(site).hostname)
                        observation.live_status = live_status
        observation.sources = sources
        observation.claim = {"company": args.company, "confirmed": args.confirmed_leak,
                             "date": args.claim_date, "source": args.claim_source,
                             "url": args.claim_url, "summary": args.claim_summary}
        live_enabled = args.mode in {'live', 'full'}
        if args.asm and not args.offline and not args.no_osint:
            print('cross-checking Shodan, Censys and urlscan passive records...')
            observation.external_osint = collect_public_osint(
                urllib.parse.urlsplit(site).hostname, observation.addresses, args.timeout,
                credential_intel=args.credential_intel,
            )
        historical_enabled = ((args.asm and args.mode in {'historical', 'full'}) or
                              (args.asm and (observation.status == 'error' or observation.live_status.get('status') in {'DEAD', 'DNS_FAILURE', 'TIMEOUT'})))
        if historical_enabled and not args.offline:
            print('collecting cached public CT, Wayback and Common Crawl history...')
            observation.historical_asm = collect_historical(
                urllib.parse.urlsplit(site).hostname, schema, observation.claim, args.timeout
            )
            historical_output.parent.mkdir(parents=True, exist_ok=True)
            historical_output.write_text(json.dumps(observation.historical_asm, ensure_ascii=False, indent=2), encoding='utf-8')
        tls_check = check_https(site, args.timeout) if args.asm and live_enabled and not args.offline and urllib.parse.urlsplit(site).scheme == 'http' else None
        # This is a non-executing prerequisite comparison. Shared/unknown IPs
        # and observations without an exact CPE version are excluded upstream.
        nvd_enabled = args.cve_review
        cve_candidates = (review_external_candidates(observation.external_osint, args.timeout)
                          if args.cve_review else [])
        if args.cve_review:
            observation.external_osint['cve_prerequisite_reviews'] = cve_candidates
        observation.inventory = build_inventory(observation, schema, cve_candidates, nvd_enabled, tls_check)
        observation.automatic = automatic_assessment(observation, schema, cve_candidates)
        if args.manual_review:
            observation.manual_review = collect_review()
        findings = build_findings(schema, observation, cve_candidates)
        write_schema(args.schema_output, schema)
        verification_output = args.output.with_name(f'{args.output.stem}_검증{args.output.suffix}')
        if verification_output.resolve() in paths:
            raise ValueError("verification report path must be distinct from inputs and other outputs")
        report_generated_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        write_report(args.output, schema, observation, findings, cve_candidates, len(rows), nvd_enabled,
                     include_verification=False, generated_at=report_generated_at)
        write_report(verification_output, schema, observation, findings, cve_candidates, len(rows), nvd_enabled,
                     include_verification=True, generated_at=report_generated_at)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"normalized records: {len(rows)}")
    print(f"recognized fields: {len(schema)}")
    print(f"site status: {observation.status}")
    print(f"technologies: {', '.join(observation.technologies) or 'none detected'}")
    print("endpoint scan: disabled")
    print("vulnerability verification: non-executing prerequisite review" if nvd_enabled else "vulnerability verification: disabled")
    print(f"schema: {args.schema_output}")
    print(f"report: {args.output}")
    print(f"verification report: {verification_output}")
    if observation.historical_asm:
        print(f"historical data: {historical_output}")
    print("Note: findings are hypotheses and do not prove the breach source.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
