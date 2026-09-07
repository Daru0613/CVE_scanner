"""Interactive, evidence-labelled manual review missions."""

MISSIONS = (
    ("사이트·HTTPS", "브라우저에서 최종 주소와 자물쇠/인증서 상태를 확인하세요.", (
        ("https_ok", "HTTPS 정상"), ("http_only", "HTTP만 사용"),
        ("cert_error", "인증서 경고"), ("unreachable", "접속 불가"), ("unknown", "확인 못함"))),
    ("실제 API", "F12 → Network → Fetch/XHR에서 로그아웃 상태의 응답을 확인하세요.", (
        ("auth_required", "인증 요구/차단"), ("public_nonsensitive", "공개 JSON이나 API지만 민감정보 없음"),
        ("public_sensitive", "익명 응답에 개인정보·내부정보 있음"), ("none", "API 요청을 찾지 못함"), ("unknown", "판단 못함"))),
    ("API 키", "Sources에서 키 변수 위치를 보고 담당자 콘솔에서 종류와 제한을 확인하세요. 키 값은 입력하지 마세요.", (
        ("none", "키 의심 항목 없음"), ("public_restricted", "공개용이며 출처·권한 제한됨"),
        ("suspected", "키처럼 보이나 종류 미확인"), ("secret_exposed", "비밀 키 공개 확인"), ("unknown", "확인 못함"))),
    ("자료·DB 관계", "자료 필드와 내부 DB/내보내기 양식을 담당자와 비교하세요. 실제 개인정보는 입력하지 마세요.", (
        ("strong", "내부 구조와 대부분 일치"), ("partial", "일부 필드만 일치"),
        ("none", "일치하지 않음"), ("no_access", "내부 자료에 접근할 수 없음"), ("unknown", "판단 못함"))),
    ("CVE 적용 여부", "실제 제품 버전·패치 상태를 제조사 공지와 비교하세요.", (
        ("applicable", "영향 버전이며 미패치"), ("patched", "영향 버전이나 패치됨"),
        ("not_applicable", "제품/버전/조건이 비해당"), ("version_unknown", "버전을 모름"), ("unknown", "확인 못함"))),
    ("로그·유출 흔적", "웹·DB·관리자 내보내기·백업 로그의 시각과 대상을 대조하세요.", (
        ("confirmed", "자료와 연결되는 다운로드/조회 기록 확인"), ("suspicious", "비정상 접근은 있으나 자료와 연결 미확정"),
        ("no_trace", "검사한 기간에 관련 흔적 없음"), ("no_logs", "로그가 없거나 접근할 수 없음"), ("unknown", "확인 못함"))),
)


def collect_review(input_fn=input, output_fn=print):
    answers = []
    output_fn("\n=== ASM 수동 검증 미션 ===")
    output_fn("번호만 입력하세요. 비밀번호, 개인정보, API 키 원문은 입력하지 마세요.\n")
    for number, (title, instruction, choices) in enumerate(MISSIONS, 1):
        output_fn(f"[미션 {number}/6] {title}")
        output_fn(instruction)
        for index, (_, label) in enumerate(choices, 1):
            output_fn(f"  {index}. {label}")
        while True:
            try:
                raw = input_fn("선택 번호: ").strip()
            except (EOFError, KeyboardInterrupt):
                raise ValueError("수동 검증 입력이 중단되었습니다") from None
            if raw.isdigit() and 1 <= int(raw) <= len(choices):
                code, label = choices[int(raw) - 1]
                answers.append({"mission": title, "code": code, "answer": label})
                output_fn(f"기록: {label}\n")
                break
            output_fn(f"1부터 {len(choices)} 사이의 번호를 입력하세요.")
    return evaluate_review(answers)


def evaluate_review(answers):
    values = {item['mission']: item['code'] for item in answers}
    score = 0
    reasons, actions, routes = [], [], []
    rules = (
        ('사이트·HTTPS', 'http_only', 1, 'HTTP만 사용해 전송 구간 보호 확인 필요', '로그인·개인정보 구간에 HTTPS 적용'),
        ('사이트·HTTPS', 'cert_error', 1, '인증서 경고 확인', '인증서 체인·호스트명·유효기간 수정'),
        ('실제 API', 'public_sensitive', 4, '익명 API 응답에서 민감정보 확인', '해당 API 접근 통제 및 응답 최소화'),
        ('API 키', 'suspected', 2, '공개 파일의 키 종류가 미확인', '키 소유자·권한·사용 이력 확인'),
        ('API 키', 'secret_exposed', 4, '비밀 키 공개 확인', '키 폐기·교체 후 사용 이력 조사'),
        ('자료·DB 관계', 'strong', 3, '자료 구조가 내부 DB/내보내기 양식과 대부분 일치', '자료 생성 경로와 접근자 확인'),
        ('자료·DB 관계', 'partial', 1, '자료 구조가 내부 시스템과 일부 일치', '필드 의미·시점·식별 체계 추가 대조'),
        ('CVE 적용 여부', 'applicable', 3, '영향 버전이며 미패치 상태 확인', '제조사 권고에 따라 패치·완화 후 로그 조사'),
        ('로그·유출 흔적', 'suspicious', 3, '비정상 접근 흔적이 있으나 자료와 연결 미확정', '시각·계정·IP·조회 대상을 자료와 대조'),
        ('로그·유출 흔적', 'confirmed', 6, '자료와 연결되는 다운로드 또는 조회 기록 확인', '사고 대응 절차로 증거 보존·차단·영향 범위 산정'),
    )
    for mission, code, points, reason, action in rules:
        if values.get(mission) == code:
            score += points
            reasons.append(reason)
            actions.append(action)
    if values.get('실제 API') == 'public_sensitive':
        routes.append('비인가 공개 API 응답')
    if values.get('API 키') == 'secret_exposed':
        routes.append('공개된 비밀 키를 통한 접근 가능성')
    if values.get('자료·DB 관계') in {'strong', 'partial'}:
        routes.append('회원 DB·관리자 내보내기·백업 경로')
    if values.get('CVE 적용 여부') == 'applicable':
        routes.append('미패치 취약점 경로 (공격 흔적 추가 확인 필요)')
    if values.get('로그·유출 흔적') == 'confirmed':
        level, conclusion = '높음', '유출 관련 기록이 확인되어 즉시 사고 대응과 영향 범위 조사가 필요합니다.'
    elif score >= 7:
        level, conclusion = '높음', '여러 강한 의심 근거가 있으나 유출 경로 확정에는 로그 연결이 필요합니다.'
    elif score >= 3:
        level, conclusion = '중간', '추가 조사가 필요한 의심 근거가 확인됐습니다.'
    elif score:
        level, conclusion = '낮음', '약한 의심 근거만 확인됐습니다.'
    else:
        level, conclusion = '판단 보류', '입력된 수동 확인만으로 의심 근거를 만들기 어렵습니다.'
    return {"answers": answers, "risk": level, "conclusion": conclusion,
            "reasons": reasons or ['확인된 구체적 의심 근거 없음'],
            "routes": routes or ['확정 가능한 경로 없음'],
            "actions": list(dict.fromkeys(actions)) or ['미확인 단계와 내부 로그를 추가 확인']}
