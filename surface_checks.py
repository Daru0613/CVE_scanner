"""Bounded public API and client-side secret checks; never validates credentials."""

import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

from passive_asm import javascript_signals


API_PATHS = ("/api", "/api/v1", "/openapi.json", "/swagger.json", "/wp-json/", "/graphql")
EXPOSURE_PATHS = ("/.env", "/.git/config", "/server-status", "/actuator", "/actuator/env", "/metrics", "/debug")
STANDARD_PATHS = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
BODY_LIMIT = 250_000
MAX_SCRIPTS = 8
KEY_ASSIGNMENT = re.compile(
    r'''(?i)["']?\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["']([^"'\s]{16,256})["']'''
)
EXPOSURE_SIGNATURES = {
    "디렉터리 목록": re.compile(r"<title>Index of /|<h1>Index of /", re.I),
    "디버그·스택 추적": re.compile(r"Traceback \(most recent call last\)|Stack trace:|Whoops, looks like something went wrong", re.I),
    "환경설정 파일": re.compile(r"(?m)^(?:APP_KEY|DB_(?:HOST|DATABASE|USERNAME|PASSWORD)|AWS_ACCESS_KEY_ID)=", re.I),
    "Git 저장소 설정": re.compile(r"(?m)^\s*\[(?:core|remote \"origin\")\]", re.I),
    "서버 상태 페이지": re.compile(r"Apache Server Status|Server Version:|Scoreboard Key", re.I),
    "운영 메트릭": re.compile(r"(?m)^# (?:HELP|TYPE) [a-zA-Z_:][a-zA-Z0-9_:]*", re.I),
}


def secret_summary(body: str) -> str:
    count = 0
    for match in KEY_ASSIGNMENT.finditer(body):
        value = match.group(1)
        if any(marker in value.lower() for marker in ("example", "placeholder", "your_", "process.env", "redacted", "${")):
            continue
        if len(set(value)) < 6:
            continue
        count += 1
    return f"키/토큰 할당 패턴 {count}건; 값 미저장·유효성 미검증" if count else "제한된 응답에서 탐지 패턴 없음"


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            for name, value in attrs:
                if name == "src" and value:
                    self.sources.append(value)


def script_urls(url: str, body: str) -> list[str]:
    parser = Scripts()
    parser.feed(body)
    origin = urllib.parse.urlsplit(url)
    result = []
    for source in parser.sources:
        candidate = urllib.parse.urljoin(url, source)
        parsed = urllib.parse.urlsplit(candidate)
        if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
            continue
        if parsed.query or parsed.fragment or parsed.username or not parsed.path.lower().endswith(".js"):
            continue
        if candidate not in result:
            result.append(candidate)
    # Application scripts are more useful than bundled libraries for finding
    # actual API usage. Preserve discovery order within each priority group.
    libraries = re.compile(r"(?:jquery|bootstrap|polyfill|vendor|bundle\.min)", re.I)
    indexed = list(enumerate(result))
    indexed.sort(key=lambda pair: (bool(libraries.search(urllib.parse.urlsplit(pair[1]).path)), pair[0]))
    return [item for _, item in indexed[:MAX_SCRIPTS]]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_public(url: str, timeout: int) -> tuple[str, str, str, bool]:
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"User-Agent": "Authorized-Exposure-Triage/0.2", "Accept-Encoding": "identity"})
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(BODY_LIMIT + 1)
            return str(response.code), response.headers.get("Content-Type", ""), raw[:BODY_LIMIT].decode("utf-8", errors="replace"), len(raw) > BODY_LIMIT
    except (urllib.error.URLError, OSError, ValueError) as error:
        return "error", "", "", False


def json_fields(payload, prefix="", depth=0) -> set[str]:
    if depth > 12:
        return set()
    result = set()
    if isinstance(payload, dict):
        for key, value in payload.items():
            name = str(key).replace("~", "~0").replace(".", "~1")
            path = f"{prefix}.{name}" if prefix else name
            if isinstance(value, (dict, list)):
                result.update(json_fields(value, path, depth + 1))
            else:
                result.add(path)
    elif isinstance(payload, list):
        for value in payload[:20]:
            result.update(json_fields(value, prefix, depth + 1))
    return result


def inspect_response(url, kind, status, content_type, body, truncated, sample_fields):
    overlap = []
    if status == "error":
        assessment = "요청 실패; 접근 여부 미확인"
    elif status in {"401", "403"}:
        assessment = "인증 요구 또는 접근 차단"
    elif status == "429":
        assessment = "요청 제한; 추가 점검 중단"
    elif status.startswith("3"):
        assessment = "리다이렉트; 따라가지 않음"
    elif status.startswith("2"):
        assessment = "공개 응답; API 여부 미확인" if kind == "API 후보" else "표준 공개 파일" if kind == "표준 파일" else "공개 정적 응답"
        try:
            payload = json.loads(body)
        except (ValueError, RecursionError):
            payload = None
        if isinstance(payload, (dict, list)):
            assessment = "공개 JSON 응답; 취약점 확정 아님"
            if isinstance(payload, dict) and ("openapi" in payload or "swagger" in payload) and "paths" in payload:
                assessment = "공개 API 명세; 취약점 확정 아님"
            else:
                observed = json_fields(payload)
                # Compare field names only; wrappers may differ. No value matching.
                overlap = sorted(name for name in sample_fields if name.rsplit(".", 1)[-1] in {key.rsplit(".", 1)[-1] for key in observed})
    else:
        assessment = "해당 경로의 정상 접근 미확인"
    secrets = secret_summary(body) if status != "error" else "미검사"
    exposure_findings = []
    if status.startswith("2"):
        exposure_findings = [label for label, pattern in EXPOSURE_SIGNATURES.items() if pattern.search(body)]
        if re.search(r"(?m)(?://[#@]\s*sourceMappingURL=|/\*[#@]\s*sourceMappingURL=)", body):
            exposure_findings.append("소스맵 위치 공개")
    count = re.search(r'(\d+)건;', secrets)
    return {"url": url, "kind": kind, "status": status, "assessment": assessment,
            "key_hits": int(count.group(1)) if count else 0, "field_matches": overlap,
            "js_signals": javascript_signals(body) if kind == "JavaScript" else [],
            "truncated": truncated, "secrets": secrets,
            "overlap": ", ".join(overlap) or "없음 / 대조 불가", "exposure_findings": exposure_findings,
            "coverage": "앞 250KB만 검사; 응답 잘림" if truncated else "응답 검사 완료" if status != "error" else "응답 없음"}


def scan_surface(url: str, timeout: int, sample_fields: set[str]) -> list[dict[str, str]]:
    parsed = urllib.parse.urlsplit(url)
    origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    pending = ([(url, "페이지")] + [(origin + path, "API 후보") for path in API_PATHS if origin + path != url]
               + [(origin + path, "노출 후보") for path in EXPOSURE_PATHS if origin + path != url]
               + [(origin + path, "표준 파일") for path in STANDARD_PATHS])
    results = []
    for index, (target, kind) in enumerate(pending):
        if index:
            time.sleep(0.5)
        status, content_type, body, truncated = read_public(target, timeout)
        results.append(inspect_response(target, kind, status, content_type, body, truncated, sample_fields))
        if index == 0 and status.startswith("2") and "html" in content_type.lower():
            pending.extend((script, "JavaScript") for script in script_urls(target, body))
        if status in {"error", "429"}:
            for remaining, remaining_kind in pending[index + 1:]:
                results.append({"url": remaining, "kind": remaining_kind, "status": "skipped",
                                "assessment": "앞선 요청 실패/제한으로 미점검", "secrets": "미검사",
                                "key_hits": 0, "field_matches": [], "js_signals": [], "truncated": False,
                                "overlap": "대조 불가", "coverage": "미점검", "exposure_findings": []})
            break
    return results
