"""Bounded, read-only historical ASM using public CT and web archive indexes."""

from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

USER_AGENT = "Authorized-Exposure-Triage/0.5"
CACHE_TTL = 86400


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe_live_status(hostname: str, timeout: int, attempts: int = 2) -> dict[str, Any]:
    """Classify HTTP and HTTPS with bounded HEAD retries and no redirect following."""
    protocols = []
    for scheme in ('https', 'http'):
        state, reason = 'UNKNOWN', ''
        for attempt in range(attempts):
            request = urllib.request.Request(f'{scheme}://{hostname}/', method='HEAD', headers={'User-Agent': USER_AGENT})
            try:
                opener = urllib.request.build_opener(_NoRedirect())
                with opener.open(request, timeout=timeout) as response:
                    code = response.status
                state = 'REDIRECT' if 300 <= code < 400 else 'LIVE'
                reason = f'HTTP {code}'
                break
            except urllib.error.HTTPError as error:
                state, reason = ('REDIRECT' if 300 <= error.code < 400 else 'LIVE'), f'HTTP {error.code}'
                break
            except urllib.error.URLError as error:
                inner = getattr(error, 'reason', error)
                if isinstance(inner, ssl.SSLError):
                    state, reason = 'TLS_ERROR', 'TLS certificate or handshake failure'
                elif isinstance(inner, socket.gaierror):
                    state, reason = 'DNS_FAILURE', 'DNS resolution failure'
                elif isinstance(inner, (TimeoutError, socket.timeout)):
                    state, reason = 'TIMEOUT', 'connection timeout'
                else:
                    state, reason = 'HTTP_ERROR', type(inner).__name__
            except (TimeoutError, socket.timeout):
                state, reason = 'TIMEOUT', 'connection timeout'
            except OSError as error:
                state, reason = 'HTTP_ERROR', type(error).__name__
            if attempt + 1 < attempts:
                time.sleep(1)
        protocols.append({'url': f'{scheme}://{hostname}/', 'status': state, 'reason': reason})
    live = next((row['status'] for row in protocols if row['status'] in {'LIVE', 'REDIRECT'}), None)
    final = live or ('DNS_FAILURE' if all(row['status'] == 'DNS_FAILURE' for row in protocols) else
                     'TIMEOUT' if all(row['status'] == 'TIMEOUT' for row in protocols) else 'DEAD')
    return {'status': final, 'protocols': protocols}


def registrable_hint(hostname: str) -> str:
    labels = hostname.lower().strip('.').split('.')
    if len(labels) >= 3 and '.'.join(labels[-2:]) in {'co.kr', 'or.kr', 'go.kr', 'ac.kr'}:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:]) if len(labels) >= 2 else hostname


def _get_json(url: str, timeout: int) -> Any:
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)


def _safe_host(value: str, root: str) -> str | None:
    host = value.lower().strip().strip('.').removeprefix('*.')
    if re.fullmatch(r'[a-z0-9.-]+', host) and (host == root or host.endswith('.' + root)):
        return host
    return None


def query_ct(root: str, timeout: int, limit: int = 300) -> list[dict[str, str]]:
    url = 'https://crt.sh/?' + urllib.parse.urlencode({'q': '%.' + root, 'output': 'json'})
    try:
        payload = _get_json(url, timeout)
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        return []
    found: dict[str, dict[str, str]] = {}
    for cert in payload if isinstance(payload, list) else []:
        for raw in str(cert.get('name_value', '')).splitlines():
            host = _safe_host(raw, root)
            if not host:
                continue
            row = found.setdefault(host, {'hostname': host, 'source': 'ct_log', 'historical_asset': True,
                                          'first_seen': '', 'last_seen': '', 'wildcard_observed': False})
            row['wildcard_observed'] = row['wildcard_observed'] or raw.strip().startswith('*.')
            before, after = str(cert.get('not_before', '')), str(cert.get('not_after', ''))
            row['first_seen'] = min(filter(None, (row['first_seen'], before)), default='')
            row['last_seen'] = max(filter(None, (row['last_seen'], after)), default='')
            if len(found) >= limit:
                break
    return sorted(found.values(), key=lambda row: row['hostname'])


def normalize_archived_url(value: str, root: str) -> tuple[str, list[str]] | None:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return None
    host = _safe_host(parsed.hostname or '', root)
    if parsed.scheme not in {'http', 'https'} or not host or parsed.username:
        return None
    path = re.sub(r'/+', '/', parsed.path or '/')
    parameters = sorted(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))[:30]
    return urllib.parse.urlunsplit((parsed.scheme.lower(), host, path, '', '')), parameters


def endpoint_category(path: str) -> str:
    value = path.lower()
    for category, words in (
        ('authentication', ('login', 'signin', 'auth')), ('member', ('member', 'user', 'account')),
        ('api', ('/api/', '/graphql')), ('admin', ('admin', 'manage')), ('upload', ('upload',)),
        ('download', ('download', 'attach')), ('file', ('file', '.pdf', '.xls', '.csv')),
        ('board', ('board', '/bbs/')), ('static', ('.js', '.css', '.png', '.jpg')),
    ):
        if any(word in value for word in words):
            return category
    return 'unknown'


def query_wayback(root: str, timeout: int, limit: int = 200) -> list[dict[str, Any]]:
    params = [('url', root + '/*'), ('output', 'json'), ('fl', 'timestamp,original,statuscode,mimetype,digest'),
              ('filter', 'statuscode:200'), ('collapse', 'urlkey'), ('limit', str(limit))]
    source_url = 'https://web.archive.org/cdx/search/cdx?' + urllib.parse.urlencode(params)
    try:
        payload = _get_json(source_url, timeout)
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        return []
    rows = []
    for values in payload[1:] if isinstance(payload, list) and payload else []:
        if not isinstance(values, list) or len(values) < 5:
            continue
        normalized = normalize_archived_url(str(values[1]), root)
        if normalized:
            url, parameters = normalized
            rows.append({'url': url, 'path': urllib.parse.urlsplit(url).path, 'parameters': parameters,
                         'timestamp': str(values[0]), 'status': str(values[2]), 'mime': str(values[3]),
                         'digest': str(values[4]), 'source': 'wayback', 'source_url': source_url,
                         'historical_asset': True, 'category': endpoint_category(urllib.parse.urlsplit(url).path)})
    return rows


def query_commoncrawl(root: str, timeout: int, limit: int = 100) -> list[dict[str, Any]]:
    try:
        indexes = _get_json('https://index.commoncrawl.org/collinfo.json', timeout)
        index_id = indexes[0]['id']
        query = urllib.parse.urlencode({'url': root + '/*', 'output': 'json', 'filter': 'status:200',
                                        'collapse': 'urlkey', 'pageSize': str(limit)})
        req = urllib.request.Request(f'https://index.commoncrawl.org/{index_id}-index?{query}',
                                     headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            lines = response.read(1_000_000).decode('utf-8', errors='ignore').splitlines()
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError, KeyError, IndexError):
        return []
    rows = []
    for line in lines[:limit]:
        try:
            item = json.loads(line)
            normalized = normalize_archived_url(str(item.get('url', '')), root)
        except (ValueError, json.JSONDecodeError):
            continue
        if normalized:
            url, parameters = normalized
            rows.append({'url': url, 'path': urllib.parse.urlsplit(url).path, 'parameters': parameters,
                         'timestamp': str(item.get('timestamp', '')), 'status': str(item.get('status', '')),
                         'mime': str(item.get('mime', '')), 'digest': str(item.get('digest', '')),
                         'source': 'common_crawl', 'source_url': f'https://index.commoncrawl.org/{index_id}-index',
                         'historical_asset': True, 'category': endpoint_category(urllib.parse.urlsplit(url).path)})
    return rows


def deduplicate_urls(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row['url'], ','.join(row.get('parameters', [])))
        previous = result.get(key)
        if not previous or row.get('timestamp', '') > previous.get('timestamp', ''):
            result[key] = row
    return sorted(result.values(), key=lambda row: (row.get('timestamp', ''), row['url']))


def build_timeline(subdomains: list[dict[str, Any]], urls: list[dict[str, Any]], claim: dict[str, str]) -> list[dict[str, str]]:
    events = []
    for row in subdomains:
        if row.get('first_seen'):
            events.append({'timestamp': row['first_seen'], 'event': f"CT 로그 서브도메인: {row['hostname']}", 'source': 'ct_log'})
    for row in urls:
        if row.get('timestamp'):
            events.append({'timestamp': row['timestamp'], 'event': f"과거 {row['category']} 경로: {row['path']}", 'source': row['source']})
    if claim.get('date'):
        events.append({'timestamp': claim['date'], 'event': '외부 포럼 게시', 'source': claim.get('source', 'user')})
    return sorted(events, key=lambda row: row['timestamp'])[:300]


def check_residual_assets(subdomains: list[dict[str, Any]], timeout: int, limit: int = 10) -> list[dict[str, Any]]:
    """Check only CT-observed hosts, once each, with DNS and a single HTTPS HEAD."""
    results = []
    for row in subdomains[:limit]:
        host = row['hostname']
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
        except socket.gaierror:
            results.append({'hostname': host, 'current_status': 'INACTIVE', 'current_ip': [],
                            'historical_source': 'ct_log', 'last_seen': row.get('last_seen', ''),
                            'residual_asset': False})
            continue
        status = 'DNS_ONLY'
        request = urllib.request.Request(f'https://{host}/', method='HEAD', headers={'User-Agent': USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
                status = 'ACTIVE' if 100 <= response.status < 500 else 'HTTP_ERROR'
        except urllib.error.HTTPError:
            status = 'ACTIVE'
        except (urllib.error.URLError, TimeoutError, OSError):
            status = 'DNS_ONLY'
        results.append({'hostname': host, 'current_status': status, 'current_ip': addresses,
                        'historical_source': 'ct_log', 'last_seen': row.get('last_seen', ''),
                        'residual_asset': status in {'ACTIVE', 'DNS_ONLY'},
                        'risk_note': '과거 CT 자산의 현재 잔존 여부만 확인; 취약점 판정 아님'})
    return results


def snapshot_diff(previous: dict[str, Any], current: dict[str, Any]) -> list[dict[str, str]]:
    old_hosts = {row['hostname'] for row in previous.get('subdomains', [])}
    new_hosts = {row['hostname'] for row in current.get('subdomains', [])}
    old_urls = {row['url'] for row in previous.get('urls', [])}
    new_urls = {row['url'] for row in current.get('urls', [])}
    rows = ([{'state': 'NEW', 'asset': value} for value in sorted((new_hosts - old_hosts) | (new_urls - old_urls))] +
            [{'state': 'REMOVED', 'asset': value} for value in sorted((old_hosts - new_hosts) | (old_urls - new_urls))])
    return rows[:200]


def collect_historical(hostname: str, schema: list[dict[str, Any]], claim: dict[str, str], timeout: int,
                       cache_dir: Path = Path('.cache/historical')) -> dict[str, Any]:
    root = registrable_hint(hostname)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / (hashlib.sha256(root.encode()).hexdigest()[:20] + '.json')
    previous: dict[str, Any] = {}
    if cache_file.exists():
        try:
            previous = json.loads(cache_file.read_text(encoding='utf-8'))
        except (OSError, ValueError, json.JSONDecodeError):
            previous = {}
    if cache_file.exists() and time.time() - cache_file.stat().st_mtime < CACHE_TTL:
        if previous:
            previous['cache_hit'] = True
            return previous
    subdomains = query_ct(root, timeout)
    urls = deduplicate_urls(query_wayback(root, timeout) + query_commoncrawl(root, timeout))
    categories = sorted({row['category'] for row in urls if row['category'] != 'unknown'})
    sample_categories = {row['category'] for row in schema}
    correlation = []
    if sample_categories & {'identity', 'credential', 'personal'} and set(categories) & {'member', 'authentication'}:
        correlation.append({'type': 'member_system_related', 'confidence': 'LOW',
                            'evidence': '회원 형태 샘플과 과거 회원·로그인 경로가 함께 관찰됨'})
    residual = check_residual_assets(subdomains, timeout)
    result = {'domain': root, 'historical_asset': True, 'collected_at': datetime.now(timezone.utc).isoformat(),
              'subdomains': subdomains, 'urls': urls, 'categories': categories,
              'residual_assets': residual, 'correlation': correlation,
              'timeline': build_timeline(subdomains, urls, claim), 'cache_hit': False}
    result['snapshot_diff'] = snapshot_diff(previous, result) if previous else []
    cache_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return result
