# CVE Scanner 실행 안내

같은 사이트의 TXT 자료를 한 폴더에 넣으면 자료를 합쳐 분석하고 공개 웹 자산을 한 번 점검한 뒤, 같은 결과로 Markdown 보고서 두 개를 만듭니다.

## 권장 실행 명령어

`--asm`의 기본 모드는 `--mode full`입니다. 기존 Live ASM과 Shodan InternetDB·urlscan 교차검증에 더해 CT 로그, Wayback, Common Crawl 공개 색인의 Historical ASM을 수행합니다. 결과는 24시간 캐시하므로 같은 도메인을 반복 조회할 때 전체 색인을 다시 요청하지 않습니다.

```powershell
cd D:\whs_scanner\CVE_scanner

python .\scanner.py `
    --sample-dir ".\자료\kapae.kr" `
    --site "http://www.kapae.kr/" `
    --asm
```

한 줄로 실행해도 됩니다.

```powershell
python .\scanner.py --sample-dir ".\자료\kapae.kr" --site "http://www.kapae.kr/" --asm
```

## 새 사이트 조사 순서

예를 들어 `example.com`을 조사하려면 다음 순서대로 진행합니다.

1. 사이트 이름으로 자료 폴더를 만듭니다.

```powershell
New-Item -ItemType Directory -Path ".\자료\example.com" -Force
```

2. 조사할 TXT 파일을 폴더 바로 아래에 넣습니다.

```text
자료/example.com/회원_001.txt
자료/example.com/회원_002.txt
자료/example.com/추가자료.txt
```

3. 사이트 상태에 맞는 명령어를 실행합니다.

살아 있는지 모르거나 Live와 과거 자산을 모두 조사할 때 권장하는 명령어:

```powershell
python .\scanner.py `
    --sample-dir ".\자료\example.com" `
    --site "https://example.com/" `
    --asm `
    --mode full
```

현재 운영 중인 사이트만 조사할 때:

```powershell
python .\scanner.py `
    --sample-dir ".\자료\example.com" `
    --site "https://example.com/" `
    --asm `
    --mode live
```

폐쇄되었거나 접속 불가인 사이트의 과거 공개 자산을 조사할 때:

```powershell
python .\scanner.py `
    --sample-dir ".\자료\example.com" `
    --site "https://example.com/" `
    --asm `
    --mode historical
```

사이트가 예전에 HTTP만 사용했다면 `--site "http://example.com/"`으로 입력해도 됩니다. ASM 상태 판정에서는 HTTP와 HTTPS를 모두 확인합니다.

생성 결과:

```text
보고서/kapae.kr/kapae.kr_통합.md
보고서/kapae.kr/kapae.kr_통합_검증.md
보고서/kapae.kr/kapae.kr_통합.schema.json
보고서/kapae.kr/kapae.kr_통합.historical.json
```

- `kapae.kr_통합.md`: 확인 절차를 뺀 노션 기록용 보고서
- `kapae.kr_통합_검증.md`: 각 대주제 바로 아래에 사진 자리표시자와 정확한 접속 URL, `F12 → Network/Elements` 이동 순서, 캡처 범위, 기록 항목이 배치된 검증용 보고서

사이트 점검과 외부 API 조회는 한 번만 수행하며, 그 결과를 두 형식으로 나눠 저장합니다.

## 실행 모드 요약

| 모드 | 사용 상황 | 수행 내용 |
| --- | --- | --- |
| `full` | 일반적인 조사, 상태를 모를 때 | Live ASM + Historical ASM + 자료 연관성 분석 |
| `live` | 현재 운영 사이트만 볼 때 | 현재 HTTP·HTTPS·DNS·공개 경로·Shodan·urlscan·CVE 후보 점검 |
| `historical` | 폐쇄 또는 접속 불가 사이트 | CT 로그·Wayback·Common Crawl·잔존 자산·시간축 분석 |

`--mode`를 생략하면 `full`이 사용됩니다. `live` 모드에서도 HTTP와 HTTPS가 모두 접속 불가이면 Historical ASM으로 자동 전환합니다. Historical ASM은 공개 색인에 실제 기록된 URL만 보관하며 경로를 추측해 요청하지 않습니다.

`자료/kapae.kr` 바로 아래의 모든 `.txt` 파일을 합칩니다. 하위 폴더와 다른 확장자는 읽지 않습니다. 행은 단순 합산하며 동일 인물 연결이나 중복 제거는 하지 않습니다. 웹 점검은 한 번만 실행합니다.

## 게시 정보 포함

```powershell
python .\scanner.py `
    --sample-dir ".\자료\kapae.kr" `
    --site "http://www.kapae.kr/" `
    --asm `
    --company "기업 또는 서비스명" `
    --claim-date "2025-12-23 01:20 PM GST" `
    --claim-source "DarkForums" `
    --claim-summary "회원정보 데이터가 외부 포럼에서 공유됨" `
    --claim-url "https://게시물-주소"
```

`--claim-url`은 보고서에 글자로만 기록하며 스캐너가 접속하지 않습니다. 입력 자료는 기본적으로 외부 포럼에 공유된 유출 자료로 표시합니다. 아직 주장 단계라면 `--unverified-claim`을 추가하세요.

## 선택형 수동 미션 포함

```powershell
python .\scanner.py `
    --sample-dir ".\자료\kapae.kr" `
    --site "http://www.kapae.kr/" `
    --asm `
    --manual-review
```

자동 점검 후 6개 질문에 번호로 답하면 결과가 보고서에 추가됩니다. 비밀번호·개인정보·API 키 원문은 입력하지 않습니다. 자동 점검만 필요하면 생략하세요.

## 파일 하나만 분석

```powershell
python .\scanner.py `
    --sample ".\자료\kapae.kr\회원_001.txt" `
    --site "http://www.kapae.kr/" `
    --asm `
    --output ".\보고서\kapae.kr\회원_001.md"
```

`--sample`과 `--sample-dir`은 동시에 사용할 수 없습니다.

## 네트워크 없이 자료만 확인

```powershell
python .\scanner.py `
    --sample-dir ".\자료\kapae.kr" `
    --site "http://www.kapae.kr/" `
    --asm `
    --offline `
    --output ".\보고서\kapae.kr\오프라인_확인.md"
```

`--offline`에서는 HTTP·HTTPS·DNS·API·키·CVE 점검이 실행되지 않습니다.

## CP949 TXT 파일

기본 인코딩은 UTF-8입니다. 한글 인코딩 오류가 발생하면 다음처럼 실행합니다.

```powershell
python .\scanner.py `
    --sample-dir ".\자료\kapae.kr" `
    --encoding cp949 `
    --site "http://www.kapae.kr/" `
    --asm
```

한 폴더의 모든 파일은 같은 인코딩이어야 합니다.

## 출력 경로 직접 지정

```powershell
python .\scanner.py `
    --sample-dir ".\자료\kapae.kr" `
    --site "http://www.kapae.kr/" `
    --asm `
    --output ".\보고서\kapae.kr\최종_통합.md" `
    --schema-output ".\보고서\kapae.kr\최종_통합.schema.json"
```

같은 출력 경로로 재실행하면 기존 요약 보고서와 파일명 뒤에 `_검증`이 붙은 검증 보고서를 덮어씁니다. 검증 보고서의 기록표를 직접 작성했다면 재실행 전에 다른 이름으로 보관하세요.

## TXT 자료 형식

TXT 내용은 CSV 구조여야 합니다. 첫 행은 필드명이고 다음 행부터 데이터입니다.

```text
"mb_no","mb_id","mb_password","mb_email"
"1","sample001","[MASKED]","masked@example.test"
```

붙여넣으며 행이 한 줄로 합쳐진 일부 CSV도 자동 복원합니다. 행의 열 개수가 헤더와 다르면 파일명을 표시하고 웹 점검 전에 중단합니다.

`CSV is empty`가 나오면 TXT가 비어 있거나 저장되지 않은 상태입니다.

```powershell
Get-ChildItem ".\자료\kapae.kr" -Filter "*.txt" -File |
    Select-Object Name, Length
```

## PowerShell 붙여넣기 주의사항

- 코드 블록 안의 명령어만 복사하세요.
- URL을 Markdown 링크로 바꾸지 말고 `"http://www.kapae.kr/"` 그대로 사용하세요.
- 옵션 앞에 `\--site`처럼 역슬래시를 붙이지 마세요.
- PowerShell 줄 연결 문자 `` ` ``는 줄의 마지막 글자여야 합니다. 뒤에 공백을 넣지 마세요.

## 자동 점검 범위

- HTTP 응답과 같은 호스트의 HTTPS 인증서 상태
- DNS IPv4·IPv6 주소
- 보안 헤더와 쿠키 속성(쿠키 값 미저장)
- 기본 API 후보 5개, `robots.txt`, `sitemap.xml`
- 같은 사이트가 실제로 불러온 JavaScript 최대 8개
- HTML에 표시된 동일 호스트 경로와 파라미터 이름
- 실제 링크된 로그인·회원 페이지 최대 5개와 폼 필드
- 공개 JSON 필드와 유출 자료 컬럼의 일치
- API 키·토큰 할당 패턴(값과 유효성 미저장·미검증)
- 정확한 버전이 식별된 기술의 NVD CVE 후보
- 현재 DNS IPv4에 대한 Shodan InternetDB 공개 포트·CPE·CVE 관측값(최대 2개 IP)
- 해당 호스트의 기존 urlscan 공개 기록(최대 10건, 새 스캔 제출 없음)

Shodan InternetDB는 API 키 없이 사용합니다. urlscan API 키도 필요하지 않지만 비인증 조회 한도가 적용될 수 있습니다. 두 결과는 과거 공개 관측값이므로 보고서에서 현재 취약점이나 유출 원인으로 단독 확정하지 않습니다. 외부 OSINT 조회를 빼려면 `--no-osint`를 추가하세요.

리다이렉트, 로그인, 키를 사용한 인증, 비밀번호 검증, 취약점 재현, 임의 경로 생성, 포트 스캔은 수행하지 않습니다. 각 응답은 최대 250KB만 검사합니다.

외부 포럼 공유 사실과 기술적 유출 경로는 구분합니다. 공개 폼 필드와 유출 컬럼의 일치는 시스템 연관성 근거지만, 실제 DB·백업·관리자 내보내기 경로를 확정하려면 해당 시점의 내부 접근 로그가 필요합니다.

## 전체 옵션과 테스트

```powershell
python .\scanner.py --help
python -m unittest -v
```
