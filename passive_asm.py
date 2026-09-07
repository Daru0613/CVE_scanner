"""Passive analysis of data already exposed by a requested public page."""

from __future__ import annotations

import re
import socket
import urllib.parse
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Any


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}


class PublicReferences(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: list[tuple[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        mapping = {"a": "href", "form": "action", "script": "src", "link": "href", "img": "src"}
        name = mapping.get(tag.lower())
        if name and attr.get(name):
            self.references.append((tag.lower(), attr[name] or ""))
        if tag.lower() == "form":
            self._form = {"action": attr.get("action") or "", "method": (attr.get("method") or "GET").upper(), "fields": [], "password_fields": []}
            self.forms.append(self._form)
        elif tag.lower() in {"input", "select", "textarea"} and self._form is not None and attr.get("name"):
            field = attr["name"] or ""
            if field not in self._form["fields"]:
                self._form["fields"].append(field)
            if tag.lower() == "input" and (attr.get("type") or "text").lower() == "password":
                self._form["password_fields"].append(field)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None


def endpoint_category(path: str) -> str:
    lowered = path.lower()
    if any(word in lowered for word in ("login", "signin", "auth")):
        return "authentication"
    if any(word in lowered for word in ("member", "user", "account")):
        return "member"
    if any(word in lowered for word in ("board", "bbs")):
        return "board"
    if "search" in lowered:
        return "search"
    if any(lowered.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico")):
        return "static"
    if any(word in lowered for word in ("download", "upload", "file", "attach")):
        return "file"
    return "unknown"


def extract_endpoints(page_url: str, body: str, limit: int = 100) -> list[dict[str, Any]]:
    parser = PublicReferences()
    parser.feed(body)
    base = urllib.parse.urlsplit(page_url)
    results, seen = [], set()
    for source, reference in parser.references:
        absolute = urllib.parse.urljoin(page_url, reference)
        parsed = urllib.parse.urlsplit(absolute)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != base.hostname or parsed.username:
            continue
        path = parsed.path or "/"
        parameters = sorted(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
        key = (path, tuple(parameters), source)
        if key in seen:
            continue
        seen.add(key)
        results.append({"path": path, "parameters": parameters, "source": source,
                        "category": endpoint_category(path)})
        if len(results) >= limit:
            break
    return results


def extract_forms(page_url: str, body: str, limit: int = 20) -> list[dict[str, Any]]:
    parser = PublicReferences()
    parser.feed(body)
    base = urllib.parse.urlsplit(page_url)
    results = []
    for form in parser.forms[:limit]:
        target = urllib.parse.urljoin(page_url, form["action"])
        parsed = urllib.parse.urlsplit(target)
        if parsed.hostname != base.hostname or parsed.username:
            continue
        results.append({"action": parsed.path or "/", "method": form["method"],
                        "fields": sorted(form["fields"])[:30],
                        "password_fields": sorted(form["password_fields"])[:10]})
    return results


def analyze_security_headers(headers: Any, scheme: str) -> list[dict[str, str]]:
    lowered = {name.lower(): value for name, value in headers.items()}
    results = []
    for name, label in SECURITY_HEADERS.items():
        if name == "strict-transport-security" and scheme != "https":
            state = "NOT_APPLICABLE"
        else:
            state = "PRESENT" if lowered.get(name) else "MISSING"
        results.append({"name": label, "state": state})
    return results


def analyze_cookies(headers: Any) -> list[dict[str, Any]]:
    values = headers.get_all("Set-Cookie", []) if hasattr(headers, "get_all") else []
    results = []
    for value in values:
        jar = SimpleCookie()
        try:
            jar.load(value)
        except Exception:
            continue
        for name, morsel in jar.items():
            results.append({"name": name, "secure": bool(morsel["secure"]),
                            "httponly": bool(morsel["httponly"]),
                            "samesite": morsel["samesite"] or "미지정",
                            "path": morsel["path"] or "미지정"})
    return results


JS_PATTERNS = {
    "fetch": re.compile(r"\bfetch\s*\("),
    "XMLHttpRequest": re.compile(r"\bXMLHttpRequest\b"),
    "jQuery.ajax": re.compile(r"\$\.(?:ajax|get|post)\s*\("),
    "axios": re.compile(r"\baxios\.(?:get|post|put|delete|request)\s*\("),
    "GraphQL": re.compile(r"[\"']/graphql(?:[/?\"'])", re.I),
    "API path": re.compile(r"[\"'](/api(?:/[^\"']*)?)[\"']", re.I),
}


def javascript_signals(body: str) -> list[str]:
    return [name for name, pattern in JS_PATTERNS.items() if pattern.search(body)]


def resolve_addresses(hostname: str) -> dict[str, list[str]]:
    results = {"ipv4": [], "ipv6": []}
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return results
    for family, _, _, _, address in records:
        key = "ipv4" if family == socket.AF_INET else "ipv6" if family == socket.AF_INET6 else None
        value = address[0]
        if key and value not in results[key]:
            results[key].append(value)
    return results


def automatic_assessment(observation: Any, schema: list[dict[str, Any]], cves: list[dict[str, str]]) -> dict[str, Any]:
    confirmed, suspected, informational = [], [], []
    if urllib.parse.urlsplit(observation.url).scheme == "http" and observation.status not in {"error", "offline", "not_checked"}:
        confirmed.append("대상 주소가 암호화되지 않은 HTTP로 제공됨")
    for header in observation.security_headers:
        if header["state"] == "MISSING":
            informational.append(f"{header['name']} 보안 헤더 미관찰")
    for cookie in observation.cookies:
        if not cookie["secure"]:
            suspected.append(f"쿠키 {cookie['name']}: Secure 속성 미관찰")
        if not cookie["httponly"]:
            suspected.append(f"쿠키 {cookie['name']}: HttpOnly 속성 미관찰")
        if cookie["samesite"] == "미지정":
            informational.append(f"쿠키 {cookie['name']}: SameSite 속성 미관찰")
    for result in observation.surface_results:
        if result.get("key_hits"):
            suspected.append(f"{result['url']}: 키·토큰 할당 패턴 {result['key_hits']}건")
        if result.get("field_matches"):
            suspected.append(f"{result['url']}: 유출 자료와 공개 JSON 필드명 일부 일치")
        for finding in result.get("exposure_findings", []):
            suspected.append(f"{result['url']}: {finding}")
    sample_fields = {item["field"].rsplit(".", 1)[-1].lower() for item in schema}
    for form in getattr(observation, "forms", []):
        if form.get("password_fields") and form.get("method") == "GET":
            confirmed.append(f"공개 폼 {form['action']}: 비밀번호 필드가 GET 방식으로 전송될 수 있음")
        matches = sorted(field for field in form["fields"] if field.lower() in sample_fields)
        if matches:
            suspected.append(f"공개 폼 {form['action']}: 유출 자료와 입력 필드명 일치 ({', '.join(matches[:6])})")
    if any(row.get("cve_id") for row in cves):
        informational.append("버전이 포함된 기술 식별값으로 CVE 후보 조회됨; 적용 여부 미확인")
    if confirmed or suspected:
        level = "주의 필요"
    elif observation.status == "200":
        level = "검사 범위에서 중대 노출 미관찰"
    else:
        level = "판단 보류"
    leak_confirmed = bool(getattr(observation, "claim", {}).get("confirmed"))
    breach = ("외부 포럼 공유는 확인됨; 원 시스템에서 빠져나온 기술적 경로는 자동 근거로 별도 판정"
              if leak_confirmed else "외부 관찰만으로 유출 원인 확정 불가")
    return {"level": level, "confirmed": confirmed, "suspected": suspected,
            "informational": informational,
            "breach": breach}
