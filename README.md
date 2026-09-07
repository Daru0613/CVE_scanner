# Scanner 사용법

승인된 자산의 입력 자료를 로컬에서 분석하고, 지정한 사이트의 공개 메타데이터를 확인한 뒤 Markdown 보고서와 구조화된 결과를 생성합니다. 입력 자료와 생성 결과는 로컬에만 보관해야 합니다.

## 준비

```powershell
cd D:\whs_scanner\CVE_scanner
New-Item -ItemType Directory -Path ".\자료\대상-식별자" -Force
```

`자료\대상-식별자` 바로 아래에 분석할 `.txt` 파일을 넣습니다. 파일은 첫 행이 컬럼명인 CSV 형식이어야 하며, 실제 비밀번호·토큰·키·개인정보 원문 대신 마스킹 값을 사용합니다.

예시 형식:

```text
"record_id","account_name","secret_field"
"1","masked-user","[MASKED]"
```

## 기본 실행

```powershell
python .\scanner.py `
    --sample-dir ".\자료\대상-식별자" `
    --site "https://승인된-호스트.example/" `
    --asm
```

한 줄로 실행할 수도 있습니다.

```powershell
python .\scanner.py --sample-dir ".\자료\대상-식별자" --site "https://승인된-호스트.example/" --asm
```

대상 주소는 반드시 소유하거나 점검 권한을 받은 호스트만 사용합니다.

## 실행 모드

```powershell
python .\scanner.py --sample-dir ".\자료\대상-식별자" --site "https://승인된-호스트.example/" --asm --mode live
python .\scanner.py --sample-dir ".\자료\대상-식별자" --site "https://승인된-호스트.example/" --asm --mode historical
python .\scanner.py --sample-dir ".\자료\대상-식별자" --site "https://승인된-호스트.example/" --asm --offline
```

- `full`: 현재 공개 정보와 과거 공개 기록을 함께 확인합니다.
- `live`: 현재 공개 HTTP·DNS·자산 정보만 확인합니다.
- `historical`: 과거 공개 기록만 확인합니다.
- `offline`: 네트워크를 사용하지 않고 입력 자료만 처리합니다.

## 단일 파일 입력

```powershell
python .\scanner.py `
    --sample ".\자료\대상-식별자\input.txt" `
    --site "https://승인된-호스트.example/" `
    --asm
```

`--sample`과 `--sample-dir`은 함께 사용하지 않습니다.

## 인코딩과 출력

```powershell
python .\scanner.py `
    --sample-dir ".\자료\대상-식별자" `
    --encoding cp949 `
    --site "https://승인된-호스트.example/" `
    --asm `
    --output ".\보고서\대상-식별자\result.md" `
    --schema-output ".\보고서\대상-식별자\result.schema.json"
```

기본 출력은 `보고서/` 아래에 생성됩니다. 결과에는 원문 값 대신 컬럼 구조와 점검 상태만 기록하도록 운영하며, 결과 파일은 Git에 추가하지 않습니다.

## 옵션 확인

```powershell
python .\scanner.py --help
```

## 입력 오류 확인

```powershell
Get-ChildItem ".\자료\대상-식별자" -Filter "*.txt" -File |
    Select-Object Name, Length
```

행의 컬럼 수가 헤더와 다르거나 파일이 비어 있으면 사이트 확인 전에 실행이 중단됩니다.

## Git 보호 규칙

`.gitignore`는 입력 자료, 보고서, CSV·JSON 결과, 캐시, Python 바이트코드를 제외합니다. 이미 한 번 Git에 추가된 파일은 ignore만으로 제거되지 않으므로, 최초 적용 시 다음 명령으로 인덱스에서만 제거합니다. 로컬 파일은 남습니다.

```powershell
git rm -r --cached --ignore-unmatch .\자료 .\보고서 .\.cache .\__pycache__
git rm --cached --ignore-unmatch *.txt *.csv *.json
git add .gitignore README.md
git status --short
```

`git status`에서 입력 자료와 결과 파일이 더 이상 변경 대상으로 보이지 않는지 확인한 뒤 커밋합니다. 이미 원격 저장소에 올라간 민감 자료는 ignore만으로 삭제되지 않으므로 저장소 기록 정리와 자격 증명 교체가 별도로 필요합니다.
