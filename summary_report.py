"""Concise reports focused on evidence-backed likely leak routes."""

import html
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit


PORT_RISKS = {
    21: "FTP: 평문 인증·파일 노출", 22: "SSH: 계정 공격·관리권한 탈취",
    23: "Telnet: 평문 인증·원격 제어", 25: "SMTP: 스팸 중계·계정 열거",
    53: "DNS: 정보 노출·증폭 악용", 80: "HTTP: 웹 취약점·평문 전송",
    110: "POP3: 평문 메일 인증", 143: "IMAP: 평문 메일 인증",
    443: "HTTPS: 웹 취약점·TLS 설정", 445: "SMB: 파일 노출·원격 실행",
    1433: "MSSQL: DB 노출·계정 공격", 1521: "Oracle DB: DB 노출·계정 공격",
    3306: "MySQL: DB 노출·계정 공격", 3389: "RDP: 계정 공격·원격 제어",
    5432: "PostgreSQL: DB 노출·계정 공격", 6379: "Redis: 데이터 노출·원격 명령",
    8080: "대체 HTTP: 관리·웹 기능 노출", 8443: "대체 HTTPS: 관리·웹 기능 노출",
    9200: "Elasticsearch: 데이터·관리 API 노출", 27017: "MongoDB: 데이터베이스 노출",
}


def port_risk(port):
    return PORT_RISKS.get(port, "서비스 공개: 용도·접근통제 확인")


def cve_risk(cve):
    return "공개 취약점 악용 가능—영향 버전·심각도 확인"


HISTORICAL_RISKS = {
    "admin": "관리 기능 잔존 시 권한 탈취·설정 변경 위험",
    "authentication": "인증 구현 취약점·계정 공격 가능성 확인",
    "member": "회원정보 처리·권한 검증 경로 확인",
    "board": "게시물 입력·조회 기능의 접근통제 확인",
    "download": "파일 직접 다운로드·경로 검증 필요",
    "file": "업로드·첨부파일 접근통제 확인",
    "api": "익명 API 응답 범위·인증 요구 확인",
    "static": "과거 코드·버전 단서 조사; 영향 버전이면 알려진 취약점 가능, 현재 적용 여부 미확인",
    "unknown": "기능 미식별; 현재 잔존 여부 확인",
}


def historical_risk(category, path=""):
    lowered = path.lower()
    if re.search(r'\.(png|jpg|jpeg|gif|ico|woff|css)(?:$|\?)', lowered):
        return '과거 서비스 운영 시점·자산 위치 대조; 이미지·스타일 경로만으로 취약점 확인 불가'
    if any(word in lowered for word in ("backup", "dump", ".sql", ".zip", ".bak")):
        return "백업·덤프 잔존 시 데이터 노출 위험"
    return HISTORICAL_RISKS.get(category, HISTORICAL_RISKS["unknown"])


def history_table(rows, timeline=False):
    """Merge adjacent identical reasons without changing chronological order."""
    prepared = []
    for row in rows:
        event = row.get('event', '')
        match = re.match(r'과거 (\w+) 경로: (.*)', event)
        category = row.get('category', match.group(1) if match else 'unknown')
        path = row.get('path', match.group(2) if match else event)
        reason = historical_risk(category, path)
        stamp = str(row.get('timestamp', ''))
        if len(stamp) == 14 and stamp.isdigit():
            stamp = datetime.strptime(stamp, '%Y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S UTC')
        prepared.append((stamp, row.get('source', ''), path, reason))
    result = ['<table>', '<thead><tr><th>관찰 시각</th><th>출처</th><th>관찰 경로 / 내용</th><th>조사 이유 · 예상 위험 (미확정)</th></tr></thead>', '<tbody>']
    end = 0
    for index, (stamp, source, path, reason) in enumerate(prepared):
        cells = ''.join(f'<td>{escape(value)}</td>' for value in (stamp, source, path))
        if timeline:
            cells += f'<td>{escape(reason)}</td>'
        elif index >= end:
            end = index + 1
            while end < len(prepared) and prepared[end][3] == reason:
                end += 1
            cells += f'<td rowspan="{end-index}">{escape(reason)}</td>'
        result.append('<tr>' + cells + '</tr>')
    return result + ['</tbody>', '</table>']


def simplify_photo_steps(lines):
    """Give each existing evidence task short actions and a visible photo slot."""
    output, active, number, photo = [], False, 0, 0
    for line in lines:
        if line.startswith('**[') and '사진' in line:
            active, number = True, 0
            photo += 1
            output += [line, '', '아래 순서대로 확인하세요. 화면이 없거나 접속이 실패하면 오류 화면을 남기고 “미확인”으로 적습니다.', '']
            continue
        if active and re.match(r'^\d+\. ', line):
            for step in re.split(r'(?<=다\.)\s+', re.sub(r'^\d+\. ', '', line)):
                number += 1
                output.append(f'{number}. {step}')
            continue
        if active and line:
            output += ['', f'> 사진 {photo:02d} 붙이는 곳: Win + Shift + S → 필요한 영역 선택 → 이 위치에 붙여넣기',
                       '> 기록: 확인 시각 / 화면에서 확인한 사실 / 미확인 항목', '']
            active = False
        output.append(line)
    if active:
        output += ['', f'> 사진 {photo:02d} 붙이는 곳: Win + Shift + S → 영역 선택 → 붙여넣기', '> 기록: 확인 시각 / 관찰 사실 / 미확인 항목', '']
    return output


def shodan_html_rows(row):
    """Render one IP as merged HTML cells; Markdown tables cannot rowspan."""
    ports = row.get('ports', [])
    cves = row.get('vulns', [])[:8]
    count = max(len(ports), len(cves), 1)
    cpes = ', '.join(row.get('cpes', [])[:5]) or '없음'
    output = []
    for index in range(count):
        port = ports[index] if index < len(ports) else None
        cve = cves[index] if index < len(cves) else ''
        cells = []
        if index == 0:
            cells += [f'<td rowspan="{count}">Shodan InternetDB</td>',
                      f'<td rowspan="{count}">{escape(row["ip"])}</td>']
        cells += [f'<td>{escape(port if port is not None else "—")}</td>',
                  f'<td>{escape(port_risk(port) if port is not None else "—")}</td>']
        if index == 0:
            cells.append(f'<td rowspan="{count}">{escape(cpes)}</td>')
        cells += [f'<td>{escape(cve or "—")}</td>',
                  f'<td>{escape(cve_risk(cve) if cve else "—")}</td>']
        output.append('<tr>' + ''.join(cells) + '</tr>')
    return output


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
    for row in observation.surface_results:
        for finding in row.get('exposure_findings', []):
            routes.append({
                'route': f"공개 노출 지점 ({row['url']})", 'confidence': '중간',
                'evidence': finding,
                'next': '서비스 담당자가 공개 의도를 확인하고 민감 내용·접근 로그를 대조',
            })
    for form in observation.forms:
        if form.get('password_fields') and form.get('method') == 'GET':
            routes.append({
                'route': f"GET 방식 인증 폼 ({form['action']})", 'confidence': '높음',
                'evidence': '비밀번호 입력값이 URL·브라우저 기록·중간 로그에 남을 수 있는 폼 방식',
                'next': 'POST 방식과 HTTPS로 변경하고 프록시·웹 로그의 기존 노출 여부 확인',
            })
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
    if sources and claim.get('confirmed'):
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
    if include_verification and forms:
        login_path = forms[0][0]['action']
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
            lines += ["<table>",
                      "<thead><tr><th>출처</th><th>대상 IP</th><th>포트</th><th>포트 주요 위험</th><th>CPE 단서</th><th>CVE</th><th>CVE 위험</th></tr></thead>",
                      "<tbody>"]
            for row in shodan_rows:
                lines.extend(shodan_html_rows(row))
            lines += ["</tbody>", "</table>"]
            lines += ["", "CVE는 InternetDB가 반환한 순서대로 최대 8개만 표시합니다. 포트와 CVE는 같은 IP에서의 독립 관측값이며, 같은 행에 있더라도 포트별 CVE 대응을 뜻하지 않습니다."]
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
            lines += ['', '과거 기록은 당시 경로가 존재했다는 근거입니다. 아래 위험은 현재 잔존 여부·공개 의도·접근통제를 확인해야 하는 이유이며 취약점 확정이 아닙니다.', '']
            lines += history_table(relevant_urls)
        if residual:
            lines += ["", "잔존 자산 후보: " + escape(', '.join(f"{row['hostname']} ({row['current_status']})" for row in residual[:10]))]
        timeline = history.get('timeline', [])
        if timeline:
            lines += ["", "### 과거 자산 시간축", "", '시간축은 서비스 변화와 조사 시점의 겹침을 확인하는 자료입니다. 기록이 없는 기간을 서비스 종료로 판단하지 않습니다.', '']
            lines += history_table(timeline[-15:], timeline=True)
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
                      "4. Common Crawl 기록이 있으면 historical.json에서 해당 기록의 source_url을 복사해 브라우저에 붙여넣습니다. 응답에서 대상 URL과 timestamp를 찾습니다. 주소창과 해당 행을 캡처합니다. 기록이 없으면 미수집으로 적습니다.",
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
                  "", "**[최종 판정 근거 사진]**", "",
                  "1. 앞 단계에서 경로 판단에 직접 사용한 사진만 골라 번호를 붙입니다.",
                  "2. `01_사이트`, `02_자료구조`, `03_연결근거`, `04_내부로그`, `05_외부ASM` 순서로 배치합니다.",
                  "3. 각 사진 아래에 출처·확인 시각·판정에 사용한 부분을 한 문장으로 적습니다.",
                  "4. 사진이 없으면 사진 자리 아래에 `캡처 없음`과 확인한 방법을 적습니다."]
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
    if not sources:
        lines = [line for line in lines if '포럼 공유 사실은' not in line]
    if include_verification:
        lines = simplify_photo_steps(lines)
    path.write_text('\n'.join(lines), encoding='utf-8')
