"""Evidence-based ASM inventory. Observed access is not a verified vulnerability."""

import socket
import ssl
import urllib.error
from urllib.parse import urlsplit


def connection_error(error):
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "인증서 검증 실패 (신뢰 체인·호스트명·유효기간 확인)"
    if isinstance(reason, socket.gaierror):
        return "DNS 이름 조회 실패"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "연결 또는 응답 시간 초과"
    if isinstance(reason, ConnectionRefusedError):
        return "서버 연결 거부"
    if isinstance(reason, ssl.SSLError):
        return "TLS 연결 협상 실패"
    return f"연결 실패 ({type(reason).__name__})"


def build_inventory(observation, schema, cves, nvd_enabled, tls_check=None):
    rows = []

    def add(asset, state, evidence, action):
        rows.append(dict(asset=asset, state=state, evidence=evidence, action=action))

    status = observation.status
    if status in {'offline', 'not_checked'}:
        add(observation.url, '미점검', '사이트 접속 미실행', '--offline을 제외하고 점검 실행')
    elif status == 'error':
        add(observation.url, '미점검', '; '.join(observation.notes) or status, '접속 원인을 해결한 뒤 재점검')
    else:
        add(observation.url, '관찰됨', f'HTTP {status}', '서비스 용도와 공개 범위를 담당자에게 확인')
    if urlsplit(observation.url).scheme == 'http':
        add('전송 암호화', '관찰됨', '입력 주소는 암호화되지 않은 HTTP', '로그인·개인정보 처리 구간의 HTTPS 적용 확인')
    if tls_check:
        add(tls_check['url'], tls_check['state'], tls_check['evidence'], tls_check['action'])
    elif urlsplit(observation.url).scheme == 'https' and status not in {'offline', 'not_checked'}:
        add('HTTPS 연결', '추가 확인' if status == 'error' else '관찰됨',
            '; '.join(observation.notes) if status == 'error' else '인증서 검증을 통과한 HTTPS 응답',
            '인증서 및 서버 설정 확인' if status == 'error' else '제품·인증 정책은 별도 확인')

    results = observation.surface_results
    if not results:
        add('엔드포인트 스캔', '미수행', '승인 범위에 따라 엔드포인트 탐색·추가 요청을 수행하지 않음', '필요 시 자산 소유자가 별도 승인 절차로 수행')
    for result in results:
        matches = result.get('field_matches', [])
        if result['status'] in {'error', 'skipped', '429'}:
            state, action = '미점검', '접속 실패 또는 요청 제한 해결 후 재점검'
        elif result.get('key_hits', 0):
            state, action = '노출 의심', '키 종류·권한·공개 의도 확인; 비밀 키면 교체'
        elif result.get('exposure_findings'):
            state, action = '노출 의심', '공개 의도와 실제 민감정보 포함 여부 확인; 불필요하면 즉시 접근 차단'
        elif matches:
            state, action = '추가 확인', '필드명 일치만 확인됨; 내부 스키마·공개 정책과 대조'
        elif result['status'] in {'401', '403'}:
            state, action = '접근 제한', '익명 요청 차단 관찰; 정상 사용자 권한 정책은 별도 검증'
        elif result['status'].startswith('3'):
            state, action = '추가 확인', '이동 목적지가 점검 범위인지 확인 후 별도 점검'
        elif result['status'].startswith('2'):
            state, action = '관찰됨', '공개 의도 확인; HTTP 200만으로 API·취약점 확정 불가'
        elif result['status'] == '404':
            if result['kind'] == 'API 후보':
                state, action = '기본 경로 미발견', '현재 경로에서는 찾지 못함; 실제 API 주소는 서비스 문서·브라우저 통신에서 확인'
            elif result['kind'] == '표준 파일':
                state, action = '파일 미발견', 'robots.txt 또는 sitemap.xml을 운영하는지 담당자에게 확인'
            else:
                state, action = '경로 미발견', '링크 변경 또는 제거 여부 확인'
        else:
            state, action = '추가 확인', '응답 상태와 서버 설정 확인'
        evidence = f"HTTP {result['status']}; {result['assessment']}"
        if result.get('key_hits', 0):
            evidence += f"; 키 패턴 {result['key_hits']}건 (값 미저장)"
        if matches:
            evidence += '; 일치 필드: ' + ', '.join(matches[:6])
            if len(matches) > 6:
                evidence += f' 외 {len(matches) - 6}개'
        if result.get('exposure_findings'):
            evidence += '; 노출 신호: ' + ', '.join(result['exposure_findings'])
        if result.get('truncated'):
            evidence += '; 응답 잘림'
            if state == '관찰됨':
                state = '추가 확인'
        add(result['url'], state, evidence, action)

    categories = {item['category'] for item in schema}
    points = []
    if 'credential' in categories:
        points.append('회원 DB·백업·관리자 내보내기')
    if 'session' in categories:
        points.append('로그·세션 저장소')
    if 'cloud_secret' in categories:
        points.append('배포 설정·소스 코드')
    if categories & {'identity', 'personal'}:
        points.append('회원 명부·API 응답')
    add('자료 기반 확인 지점', '추정', ' / '.join(points) or '분류 근거 부족', '사이트 보유 데이터인지와 유출 시점의 접근 로그 확인')
    ids = {row['cve_id'] for row in cves if row['cve_id']}
    if not nvd_enabled:
        add('취약점 검증', '미수행', '승인 범위에 따라 CVE 조회·적용 여부 검증을 수행하지 않음', '별도 승인과 내부 제품 명세가 있을 때 수행')
    elif not cves:
        add('CVE 전제조건 비교', '후보 없음',
            '대상 전용 귀속·정확한 CPE 버전·외부 CVE 후보를 모두 만족한 항목 없음',
            '공유/귀속 불명 IP의 CVE를 합산하지 말고 내부 자산·버전 자료로 보완')
    elif ids:
        add('CVE 적용 여부', '추가 확인', f'키워드 후보 {len(ids)}개; 영향 버전 미검증', '제조사 공지·실제 버전·패치·필수 설정 조건 대조')
    else:
        failed = any('failed' in row['status'] for row in cves)
        add('CVE 적용 여부', '미점검' if failed else '추가 확인',
            '조회 실패' if failed else '키워드 결과 없음; 안전 판정 아님', '조회 상태 및 제품 식별 정확도 확인')
    return rows
