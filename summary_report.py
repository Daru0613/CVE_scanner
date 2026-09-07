"""Concise reports focused on evidence-backed likely leak routes."""

import html
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit


def report_path(url):
    host = urlsplit(url).hostname or "site"
    name = re.sub(r'[^\w.-]', '_', host).strip('. ')[:180] or "site"
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if name.split('.')[0].upper() in reserved:
        name = "site_" + name
    return Path("보고서") / f"{name}.md"


def escape(value):
    return ''.join(f"&#{ord(c)};" if c in "\\`*_{}[]()#+!|" else html.escape(c, quote=True)
                   for c in str(value)).replace('\r', '').replace('\n', ' ')


def important_fields(schema, limit=8):
    order = {'credential': 0, 'cloud_secret': 1, 'session': 2, 'identity': 3,
             'personal': 4, 'network': 5, 'business': 6, 'audit': 7, 'other': 8}
    fields = sorted(schema, key=lambda item: (order.get(item['category'], 9), item['field']))
    text = ', '.join(item['field'] for item in fields[:limit]) or '없음'
    return text + (f' 외 {len(fields) - limit}개' if len(fields) > limit else '')


def source_interpretation(schema):
    categories = {item['category'] for item in schema}
    notes = []
    if 'credential' in categories:
        notes.append('회원 인증 DB·백업·관리자 내보내기 형태')
    if categories & {'identity', 'personal'}:
        notes.append('회원 명부·회원정보 저장 구조')
    if 'session' in categories:
        notes.append('로그·세션 저장소 형태')
    if 'cloud_secret' in categories:
        notes.append('배포 설정·소스 저장소 형태')
    return ' / '.join(notes) or '자료 용도 판단 근거 부족'


def evidence_matches(schema, observation):
    sample = {item['field'].rsplit('.', 1)[-1].lower() for item in schema}
    forms = []
    for form in observation.forms:
        matched = sorted(field for field in form['fields'] if field.lower() in sample)
        if matched:
            forms.append((form, matched))
    json_rows = [(row, row.get('field_matches', [])) for row in observation.surface_results
                 if row.get('field_matches')]
    keys = [row for row in observation.surface_results if row.get('key_hits', 0)]
    return forms, json_rows, keys


def likely_routes(schema, observation, cve_candidates):
    categories = {item['category'] for item in schema}
    forms, json_rows, keys = evidence_matches(schema, observation)
    routes = []
    credential_forms = [(form, matches) for form, matches in forms
                        if any(re.search(r'(?:id|login|user|pass|pw)', name, re.I) for name in matches)]
    if 'credential' in categories and credential_forms:
        form, matches = credential_forms[0]
        routes.append({
            'route': '회원 인증 시스템과 연결된 DB·관리자 내보내기·백업',
            'confidence': '중간',
            'evidence': f"유출 자료에 인증 컬럼이 있고 공개 폼 {form['action']}의 입력 필드와 일치: {', '.join(matches[:6])}",
            'next': '폼 처리 서버가 사용하는 회원 테이블, 관리자 다운로드 기록, 백업 접근 로그를 시간순으로 대조',
        })
    elif 'credential' in categories:
        routes.append({
            'route': '회원 DB·백업·관리자 내보내기', 'confidence': '낮음',
            'evidence': '유출 자료에 아이디·비밀번호 등 인증정보 형태의 컬럼이 포함됨',
            'next': '내부 회원 스키마와 내보내기·백업 파일 구조를 대조',
        })
    for row, matches in json_rows:
        routes.append({
            'route': f"공개 회원정보 API ({row['url']})", 'confidence': '높음',
            'evidence': f"인증 없는 공개 JSON 응답과 유출 자료의 필드명 일치: {', '.join(matches[:6])}",
            'next': '공개 의도·응답 데이터 범위와 해당 시점의 API 접근 로그를 확인',
        })
    for row in keys:
        routes.append({
            'route': f"공개 코드의 키·토큰 경로 ({row['url']})", 'confidence': '중간',
            'evidence': f"공개 응답에서 키·토큰 할당 패턴 {row['key_hits']}건 탐지",
            'next': '키 종류·권한·사용 이력을 관리 콘솔에서 확인하고 비밀 키면 폐기·교체',
        })
    if 'session' in categories:
        routes.append({
            'route': '로그·세션 저장소', 'confidence': '낮음',
            'evidence': '유출 자료에 세션·토큰 형태의 컬럼이 포함됨',
            'next': '세션 저장소 접근 기록과 로그 마스킹·내보내기 이력을 확인',
        })
    if 'cloud_secret' in categories and not keys:
        routes.append({
            'route': '소스 코드·배포 설정·비밀 저장소', 'confidence': '낮음',
            'evidence': '유출 자료에 API 키·비밀정보 형태의 컬럼이 포함됨',
            'next': '소스·CI/CD·비밀관리 시스템의 접근 및 변경 이력을 확인',
        })
    applicable = {row['cve_id'] for row in cve_candidates if row.get('cve_id') and 'applicability unverified' not in row.get('status', '')}
    if applicable:
        routes.append({
            'route': '확인된 영향 버전의 취약점', 'confidence': '중간',
            'evidence': f"적용 가능한 CVE {len(applicable)}개 확인",
            'next': '공격 시점의 웹 로그와 취약 경로 요청을 대조',
        })
    rank = {'높음': 0, '중간': 1, '낮음': 2}
    return sorted(routes, key=lambda item: rank[item['confidence']])


def site_structure_summary(observation):
    technologies = observation.technologies
    server = [item for item in technologies if item.split()[0] in {'nginx', 'apache', 'iis'}]
    backend = [item for item in technologies if item.split()[0] in {'php', 'express', 'wordpress'}]
    frontend = [item for item in technologies if item.split()[0] == 'jquery']
    paths = [item['path'].lower() for item in observation.endpoints]
    if any('/bbs/' in path or path.startswith('/bbs') for path in paths):
        structure = 'PHP 계열 게시판 경로(`/bbs/`)가 관찰됨'
    elif any('/member' in path for path in paths):
        structure = '회원 관련 경로(`/member`)가 관찰됨'
    else:
        structure = '특정 애플리케이션 구조 미식별'
    categories = Counter(item['category'] for item in observation.endpoints)
    relevant = [(name, count) for name, count in categories.most_common()
                if name in {'authentication', 'member', 'board', 'file'}]
    js_signals = sorted({signal for row in observation.surface_results for signal in row.get('js_signals', [])})
    return {
        'server': ', '.join(server) or '미식별', 'backend': ', '.join(backend) or '미식별',
        'frontend': ', '.join(frontend) or '미식별', 'structure': structure,
        'paths': ', '.join(f'{name} {count}개' for name, count in relevant) or '유출 관련 경로 유형 미식별',
        'forms': f'{len(observation.forms)}개 공개 폼 관찰' if observation.forms else '공개 폼 미관찰',
        'api': ', '.join(js_signals) + ' 사용 흔적' if js_signals else 'API 호출 흔적 미관찰',
    }


def osint_evidence(observation):
    data = getattr(observation, 'external_osint', {}) or {}
    shodan = [row for row in data.get('shodan_internetdb', [])
              if row.get('ports') or row.get('cpes') or row.get('vulns')]
    urlscan = [row for row in data.get('urlscan', []) if row.get('domain')]
    return shodan, urlscan


def write_report(path, schema, observation, findings, cve_candidates, record_count, nvd_enabled,
                 include_verification=False):
    host = urlsplit(observation.url).hostname or observation.url
    claim, sources = observation.claim, observation.sources
    routes = likely_routes(schema, observation, cve_candidates)
    forms, json_rows, keys = evidence_matches(schema, observation)
    strongest = routes[0]['confidence'] if routes else '근거 부족'
    purpose = "검증용" if include_verification else "노션 기록용"
    lines = [f"# {escape(host)} — 유출 경로 ASM 보고서 ({purpose})", "", "## 조사 개요", "",
             f"- 대상 사이트: {escape(observation.url)}",
             f"- 조사 시각: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
             f"- 분석 자료: {len(sources)}개 파일, {record_count}개 레코드, {len(schema)}개 필드"]
    if claim.get('company'):
        lines.append(f"- 기업·서비스명: {escape(claim['company'])}")
    if claim.get('confirmed'):
        lines.append("- 유출·공유 상태: **외부 포럼 공유 확인** (사용자 제공 정보 기준)")
    if claim.get('date') or claim.get('source'):
        lines.append(f"- 게시일·게시처: {escape(' / '.join(v for v in (claim.get('date'), claim.get('source')) if v))}")
    if claim.get('summary'):
        lines.append(f"- 유출 내용: {escape(claim['summary'])}")
    if claim.get('url'):
        lines.append(f"- 참고 게시물: {escape(claim['url'])} (기록만 하며 자동 접속하지 않음)")
    if include_verification:
        lines += ["", "**[사이트 접속 확인 사진]**", "",
                  f"1. Chrome 또는 Edge 주소창에 `{escape(observation.url)}`를 입력해 접속합니다.",
                  "2. `F12`를 누르고 **Network** 탭을 엽니다. 목록이 비어 있으면 `Ctrl+R`로 한 번 새로고침합니다.",
                  "3. Network 목록에서 Type이 `document`인 첫 요청을 누르고 **Headers → General**의 Request URL·Status Code를 펼칩니다.",
                  "4. 주소창, 사이트 첫 화면, Request URL, Status Code가 함께 보이게 캡처합니다.",
                  "5. Windows 작업표시줄의 날짜·시각도 포함하고, 로그인 입력·버튼 클릭·폼 제출은 하지 않습니다.",
                  "6. 사진 아래에 `확인 시각 / 입력 URL / 최종 Request URL / Status Code`를 기록합니다."]
    access = ('오프라인 · 사이트 미점검' if observation.status == 'offline' else
              '미확인' if observation.status == 'error' else 'HTTP ' + observation.status)
    conclusion = ((routes[0]['route'] + ' 경로를 우선 조사해야 합니다.')
                  if routes else '현재 자동 근거만으로 우선 조사할 유출 경로를 만들지 못했습니다.')
    lines += ["", "## 핵심 판단", "",
              f"- 사이트 접근: {access}",
              f"- HTTP·HTTPS 종합 상태: {escape(observation.live_status.get('status', '미분류'))}",
              f"- 가장 유력한 경로의 신뢰도: **{strongest}**",
              f"- 결론: {conclusion}"]
    if sources:
        lines += ["", "## 샘플 데이터 분석", "",
                  "자료 값은 기록하지 않고 유출 경로 판단에 영향을 주는 컬럼 구조만 표시합니다.", "",
                  "| 자료 | 레코드 | 주요 컬럼 | 구조 해석 |", "| --- | ---: | --- | --- |"]
        for source in sources:
            lines.append(f"| {escape(source['name'])} | {source['records']} | {escape(important_fields(source['schema']))} | {escape(source_interpretation(source['schema']))} |")
        if len(sources) > 1:
            common = set.intersection(*({item['field'] for item in source['schema']} for source in sources))
            lines += ["", f"공통 컬럼 {len(common)}개: {escape(', '.join(sorted(common)[:8]) or '없음')}. 동일 인물 연결과 중복 제거는 수행하지 않았습니다."]
        if include_verification:
            lines += ["", "**[자료 구조 확인 사진]**", "",
                      "1. TXT 파일을 메모장 또는 코드 편집기로 엽니다.",
                      "2. 첫 행의 컬럼명과 파일명이 보이도록 캡처합니다.",
                      "3. 실제 이름·이메일·전화번호·주소·비밀번호 값은 검은색 상자로 완전히 가립니다.",
                      "4. 자료가 여러 개면 파일별로 한 장씩 캡처하고 `자료명 / 행 수 / 컬럼 수`를 적습니다."]
    lines += ["", "## ASM 의심 항목 — 유력 유출 경로", "",
              "미탐지 항목과 유출 판단에 직접 영향을 주지 않는 일반 설정은 제외했습니다.", ""]
    if routes:
        if include_verification:
            lines += ["| 우선순위 | 유력 경로 | 신뢰도 | 연결 근거 | 다음 확인 |", "| ---: | --- | --- | --- | --- |"]
            for index, item in enumerate(routes, 1):
                lines.append(f"| {index} | {escape(item['route'])} | {item['confidence']} | {escape(item['evidence'])} | {escape(item['next'])} |")
        else:
            lines += ["| 우선순위 | 유력 경로 | 신뢰도 | 연결 근거 |", "| ---: | --- | --- | --- |"]
            for index, item in enumerate(routes, 1):
                lines.append(f"| {index} | {escape(item['route'])} | {item['confidence']} | {escape(item['evidence'])} |")
    else:
        lines.append("자료와 사이트 사이에 자동으로 연결된 유력 경로가 없습니다.")
    if include_verification:
        login_path = forms[0][0]['action'] if forms else '/로그인-경로'
        login_url = urljoin(observation.url, login_path)
        lines += ["", "**[유력 유출 경로 검증 사진]**", "",
                  "1. 위 표의 1순위 경로부터 확인합니다.",
                  f"2. Chrome 또는 Edge에서 `{escape(login_url)}`를 엽니다. 실제 아이디·비밀번호는 입력하지 않습니다.",
                  "3. `F12` → **Elements**를 열고 `Ctrl+F`를 눌러 `<form`을 검색합니다.",
                  "4. 해당 form을 펼쳐 `<input name=...>` 부분을 찾습니다. 샘플과 일치한 `name` 속성과 주소창이 함께 보이게 캡처합니다.",
                  "5. 이어서 `F12` → **Network** → `Ctrl+R` → Type `document` 요청 → **Headers**를 열고 Request URL·Status Code를 캡처합니다.",
                  "6. 관리자·DB·백업 기록은 운영 담당자가 사용하는 관리 콘솔에서 조사 기간을 설정한 뒤 시각·작업 종류·마스킹된 계정·대상 파일명만 보이게 캡처합니다.",
                  "7. 사진 아래에 `일치한 필드 / 내부 기록 유무 / 현재 판정`을 기록합니다."]
    if forms or json_rows or keys:
        lines += ["", "## 사이트와 유출 자료의 연결 근거", ""]
        for form, matches in forms:
            lines.append(f"- 공개 폼 `{escape(form['action'])}`의 입력 필드와 일치: {escape(', '.join(matches))}")
        for row, matches in json_rows:
            lines.append(f"- 공개 JSON `{escape(row['url'])}`의 필드와 일치: {escape(', '.join(matches[:8]))}")
        for row in keys:
            lines.append(f"- 공개 응답 `{escape(row['url'])}`에서 키·토큰 패턴 {row['key_hits']}건 탐지 (값 미저장)")
        if include_verification:
            evidence_url = (json_rows[0][0]['url'] if json_rows else
                            keys[0]['url'] if keys else
                            urljoin(observation.url, forms[0][0]['action']))
            lines += ["", "**[사이트·유출 자료 연결 확인 사진]**", "",
                      f"1. 로그아웃 상태의 Chrome 또는 Edge에서 `{escape(evidence_url)}`를 엽니다.",
                      "2. `F12` → **Network** → `Ctrl+R` 후 해당 요청을 선택합니다.",
                      "3. **Headers**에서 Request URL·Status Code·Response Headers의 Content-Type이 보이게 캡처합니다.",
                      "4. JSON이면 **Response** 탭에서 일치한 필드명만 보이게 캡처하고 값은 모두 가립니다. HTML 폼이면 **Elements**에서 일치한 input `name`을 캡처합니다.",
                      "5. API 키 패턴이 나온 파일은 Network 검색창에 파일명만 입력해 응답을 연 뒤, 값 전체를 가리고 변수명·파일 URL만 남깁니다.",
                      "6. 사진 아래에 `일치 필드 / 로그인 필요 여부 / Content-Type / 공개 의도 확인 결과`를 기록합니다."]
    shodan_rows, urlscan_rows = osint_evidence(observation)
    if shodan_rows or urlscan_rows:
        lines += ["", "## 외부 ASM 교차검증", "",
                  "Shodan InternetDB와 urlscan의 공개·과거 관측값입니다. 현재 상태나 유출 원인을 단독으로 확정하는 근거는 아닙니다.", ""]
        if shodan_rows:
            lines += ["| 출처 | 대상 IP | 공개 포트 관측 | CPE 단서 | CVE 관측 |", "| --- | --- | --- | --- | --- |"]
            for row in shodan_rows:
                ports = ', '.join(map(str, row.get('ports', []))) or '없음'
                cpes = ', '.join(row.get('cpes', [])[:5]) or '없음'
                vulns = ', '.join(row.get('vulns', [])[:8]) or '없음'
                lines.append(f"| Shodan InternetDB | {escape(row['ip'])} | {escape(ports)} | {escape(cpes)} | {escape(vulns)} |")
        if urlscan_rows:
            current_ips = set(observation.addresses.get('ipv4', [])) | set(observation.addresses.get('ipv6', []))
            same_ip = sum(1 for row in urlscan_rows if row.get('ip') in current_ips)
            paths = []
            for row in urlscan_rows:
                path_value = urlsplit(row.get('url', '')).path or '/'
                if path_value not in paths:
                    paths.append(path_value)
            lines += ["", f"- urlscan 공개 기록: 동일 호스트 {len(urlscan_rows)}건, 현재 DNS IP 일치 {same_ip}건",
                      f"- 과거 관찰 경로: {escape(', '.join(paths[:8]))}"]
        if include_verification:
            shodan_ip = shodan_rows[0]['ip'] if shodan_rows else '대상-IP'
            shodan_url = f"https://internetdb.shodan.io/{shodan_ip}"
            urlscan_url = f"https://urlscan.io/search/#{quote('domain:' + host)}"
            lines += ["", "**[Shodan·urlscan 교차검증 사진]**", "",
                      f"1. 브라우저에서 `{escape(shodan_url)}`를 엽니다. JSON 화면의 `ip`, `ports`, `cpes`, `vulns`와 주소창이 보이게 캡처합니다.",
                      f"2. 새 탭에서 `{escape(urlscan_url)}`를 열고 검색 결과 중 도메인이 정확히 `{escape(host)}`인 항목만 확인합니다.",
                      "3. urlscan 결과 한 건을 열어 Summary의 URL·Domain·IP·Scan date가 함께 보이게 캡처합니다. 새 URL 스캔은 제출하지 않습니다.",
                      f"4. PowerShell에서 `Resolve-DnsName {escape(host)} -Type A`를 실행하고 Name·IPAddress가 보이게 캡처합니다.",
                      "5. DNS IP와 Shodan·urlscan IP가 같은지 비교하고 사진 아래에 `외부 관측 시각 / 현재 DNS IP / 동일 여부`를 기록합니다."]
    history = getattr(observation, 'historical_asm', {}) or {}
    if history:
        subdomains = history.get('subdomains', [])
        historical_urls = history.get('urls', [])
        residual = [row for row in history.get('residual_assets', []) if row.get('residual_asset')]
        correlations = history.get('correlation', [])
        lines += ["", "## Historical ASM", "",
                  f"- 기준 루트 도메인: {escape(history.get('domain', host))}",
                  f"- CT 로그 과거 서브도메인: {len(subdomains)}개",
                  f"- Wayback·Common Crawl 과거 URL: {len(historical_urls)}개",
                  f"- 현재 잔존 자산 후보: {len(residual)}개",
                  f"- 과거 경로 유형: {escape(', '.join(history.get('categories', [])) or '관련 유형 미발견')}",
                  f"- 유출 자료 구조 연관성: {escape(correlations[0]['type'] + ' (' + correlations[0]['confidence'] + ')' if correlations else '자동 연관성 미발견')}"]
        if subdomains:
            lines += ["", "과거 서브도메인: " + escape(', '.join(row['hostname'] for row in subdomains[:15]))]
        relevant_urls = [row for row in historical_urls if row.get('category') != 'unknown'][:15]
        if relevant_urls:
            lines += ["", "| 과거 관찰 시각 | 출처 | 유형 | 경로 |", "| --- | --- | --- | --- |"]
            for row in relevant_urls:
                lines.append(f"| {escape(row.get('timestamp', ''))} | {escape(row['source'])} | {escape(row['category'])} | {escape(row['path'])} |")
        if residual:
            lines += ["", "잔존 자산 후보: " + escape(', '.join(f"{row['hostname']} ({row['current_status']})" for row in residual[:10]))]
        timeline = history.get('timeline', [])
        if timeline:
            lines += ["", "### 과거 자산 시간축", "", "| 시각 | 관찰 내용 | 출처 |", "| --- | --- | --- |"]
            for row in timeline[-15:]:
                lines.append(f"| {escape(row.get('timestamp', ''))} | {escape(row.get('event', ''))} | {escape(row.get('source', ''))} |")
        changes = history.get('snapshot_diff', [])
        if changes:
            lines += ["", "### 이전 조사 대비 변경", ""]
            for row in changes[:20]:
                lines.append(f"- [{escape(row['state'])}] {escape(row['asset'])}")
        if include_verification:
            root = history.get('domain', host)
            lines += ["", "**[Historical ASM 확인 사진]**", "",
                      f"1. CT 로그는 `https://crt.sh/?q=%25.{escape(root)}`에 접속합니다. 검색 결과의 Common Name·Matching Identities·Not Before가 보이게 캡처합니다.",
                      f"2. Wayback은 `https://web.archive.org/web/*/{escape(root)}/*`에 접속합니다. 연도 막대와 실제 저장된 URL·캡처 시각이 보이게 캡처합니다.",
                      "3. 보고서의 과거 URL 중 로그인·회원·API 경로를 Wayback 결과 목록에서 검색합니다. 보관된 기록에 있는 URL만 열고 현재 사이트 주소로 바꿔 접속하지 않습니다.",
                      "4. Common Crawl 출처는 `https://index.commoncrawl.org/collinfo.json`에서 보고서 JSON의 수집 시점과 사용 색인을 확인해 주소창과 함께 캡처합니다.",
                      "5. 사진 아래에 `출처 / 과거 관찰 시각 / hostname 또는 경로 / 현재 자산과의 연관성`을 기록합니다."]
    if include_verification and observation.manual_review:
        review = observation.manual_review
        lines += ["", "## 수동 미션 판단", "", f"- 종합 위험도: **{escape(review['risk'])}**",
                  f"- 판단: {escape(review['conclusion'])}", f"- 가능 경로: {escape(' / '.join(review['routes']))}", "",
                  "| 미션 | 입력 결과 |", "| --- | --- |"]
        for item in review['answers']:
            lines.append(f"| {escape(item['mission'])} | {escape(item['answer'])} |")
    if include_verification:
        lines += ["", "## 단계별 확인 절차", "",
                  "1. **자료 구조 대조:** 유력 경로에 표시된 내부 회원 테이블의 컬럼명·순서·내보내기 형식을 샘플과 비교합니다.",
                  "2. **시점 설정:** 포럼 게시일과 파일 수정 시각을 기준으로 조사 시간 범위를 정합니다.",
                  "3. **관리 기능 확인:** 해당 시간 범위의 관리자 로그인, 회원 검색, CSV·엑셀 내보내기 기록을 확인합니다.",
                  "4. **DB·백업 확인:** DB 감사 로그, 백업 생성·다운로드, FTP·SSH·스토리지 접근 기록을 같은 시간순으로 맞춥니다.",
                  "5. **공개 경로 확인:** 보고서에 JSON·키·토큰 경로가 나온 경우 익명 접근 범위와 당시 웹 로그를 확인합니다.",
                  "6. **외부 관측 대조:** Shodan의 IP·포트와 urlscan의 호스트·IP·관찰 시각이 조사 당시 자산과 같은지 확인합니다.",
                  "7. **최종 판정:** 계정·IP·시각·대상 파일·전송량이 연결되면 확인된 경로로 기록하고, 연결되지 않으면 미확정으로 남깁니다.",
                  "", "## 수동 검증 기록표", "",
                  "아래 표의 빈칸을 조사하면서 채웁니다. 계정, 비밀번호, 개인정보, API 키 원문은 적지 않습니다.", "",
                  "| 확인 항목 | 조사 결과 | 판정 | 증거 파일·캡처명 | 확인 시각 |", "| --- | --- | --- | --- | --- |",
                  "| 내부 회원 테이블과 샘플 컬럼 일치 | 미기록 | 미확인 |  |  |",
                  "| 관리자 내보내기·다운로드 기록 | 미기록 | 미확인 |  |  |",
                  "| DB·백업·FTP·SSH 접근 기록 | 미기록 | 미확인 |  |  |",
                  "| 공개 API·파일 접근 기록 | 미기록 | 미확인 |  |  |",
                  "| API 키·토큰 종류와 사용 이력 | 미기록 | 미확인 |  |  |",
                  "| Shodan·urlscan 자산 귀속과 시점 | 미기록 | 미확인 |  |  |",
                  "| 최종 유출 경로 | 미기록 | 미확정 |  |  |",
                  "", "**[최종 판정 근거 사진]**", "",
                  "1. 앞 단계에서 경로 판단에 직접 사용한 사진만 골라 번호를 붙입니다.",
                  "2. `01_사이트`, `02_자료구조`, `03_연결근거`, `04_내부로그`, `05_외부ASM` 순서로 배치합니다.",
                  "3. 각 사진 아래에 출처·확인 시각·판정에 사용한 부분을 한 문장으로 적습니다.",
                  "4. 사진이 없으면 해당 표의 증거 파일 칸에 `캡처 없음`과 확인한 방법을 적습니다."]
    lines += ["", "## 검증 한계", "",
              "- 포럼 공유 사실은 사용자 제공 정보 기준으로 확인 처리했습니다.",
              "- 외부 자동 점검은 내부 DB·관리자·백업 접근 로그를 볼 수 없습니다.",
              "- Shodan과 urlscan 결과는 수집 시점이 다른 공개 관측값이므로 현재 자산 상태와 다를 수 있습니다.",
              "- 기술적 유출 경로 확정에는 해당 시점의 내부 기록이 필요합니다.", ""]
    technology = site_structure_summary(observation)
    lines += ["## 사이트 제작 기술·구조 요약", "",
              f"- 웹서버: {escape(technology['server'])}",
              f"- 백엔드·CMS 단서: {escape(technology['backend'])}",
              f"- 프론트엔드 라이브러리: {escape(technology['frontend'])}",
              f"- 사이트 구조: {technology['structure']}",
              f"- 유출 조사 관련 공개 경로: {escape(technology['paths'])}",
              f"- 입력 폼: {escape(technology['forms'])}",
              f"- API 사용 단서: {escape(technology['api'])}", ""]
    if include_verification:
        lines += ["**[사이트 기술·구조 확인 사진]**", "",
                  f"1. `{escape(observation.url)}`에서 `F12` → **Network**를 열고 `Ctrl+R`로 새로고침합니다.",
                  "2. Type이 `document`인 첫 요청 → **Headers** → Response Headers에서 Server·X-Powered-By·Content-Type을 찾습니다.",
                  "3. 주소창, 요청 이름, Status Code와 해당 응답 헤더가 함께 보이게 캡처합니다.",
                  "4. Network 상단의 `JS` 필터를 누르고 jQuery 등 파일명을 선택합니다. **Headers**의 Request URL에서 파일명·버전 단서가 보이게 캡처합니다.",
                  "5. 사이트 경로 구조는 **Elements**에서 `Ctrl+F`로 `/bbs/`, `/member`, `/api`를 각각 검색해 실제 링크가 보이는 부분만 캡처합니다.",
                  "6. Cookie·Authorization·Request Payload·Query String의 개인정보는 가립니다.",
                  "7. 사진 아래에 `확인한 웹서버 / 백엔드 단서 / JavaScript 파일 / 관련 경로`를 기록합니다.", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('\n'.join(lines), encoding='utf-8')
