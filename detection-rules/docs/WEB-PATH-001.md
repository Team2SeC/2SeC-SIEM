# WEB-PATH-001: Path Traversal / LFI Detection Rule

## 1. 탐지 룰 개요

- **Rule ID**: WEB-PATH-001
- **공격 유형**: Path Traversal / Local File Inclusion (LFI)
- **공격 분류**: File Access
- **로그 소스**: DVWA Apache access log
- **적용 단계**: Logstash (Classification / Enrichment)

---

## 2. 위협 시나리오 (Threat Scenario)

### 2.1 위협 개요

Path Traversal은 디렉터리 이동 문자를 사용하여 **웹 루트 외부의 파일에 접근**하는 공격이다. 민감한 시스템 파일, 설정 파일, 소스 코드 등을 읽을 수 있다.

본 룰은 다음과 같은 시나리오를 탐지하기 위해 설계되었다.

- **상위 디렉터리 접근**
    - ../../../etc/passwd
    - ..\..\windows\system32\drivers\etc\hosts
- **절대 경로 접근**
    - /etc/passwd
    - C:\boot.ini
- **인코딩 우회**
    - %2e%2e%2f (URL encoding)
    - ..%252f (Double encoding)

### 2.2 보호 대상 자산과 영향

| 자산 | 영향 |
|------|------|
| 시스템 파일 | Information disclosure |
| 설정 파일 | Configuration exposure |
| 소스 코드 | Logic disclosure |
| 데이터베이스 정보 | Credential theft |

---

## 3. 관측 신호 (Observable Signals)

### 3.1 로그 기반 관측 가능 지점

본 공격 시나리오는 **Apache access log**에서 다음 신호로 관측 가능하다.

- 요청 URL의 **path 및 query**
- 디렉터리 이동 패턴
- 시스템 파일명
- URL 인코딩 패턴

### 3.2 주요 관측 필드

| 필드 | 설명 |
|------|------|
| url.path | 요청 경로 |
| url.query | 파일 참조 파라미터 |
| http.request.method | 요청 메서드 |
| http.response.status_code | 응답 코드 |
| source.ip | 공격 주체 IP |

---

## 4. 탐지 근거 (Detection Rationale)

### 4.1 표준 및 권장 사항

#### OWASP

- **A05:2021 – Security Misconfiguration**
- Path Traversal Testing Guide

#### CWE-22

- https://cwe.mitre.org/data/definitions/22.html
- Path Traversal

### 4.2 프로젝트 실험 근거

DVWA File Inclusion 모듈:

```
page=../../../etc/passwd
file=..\..\..\..\windows\system32\drivers\etc\hosts
page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

---

## 5. 탐지 조건 (Detection Conditions)

### 5.1 탐지 패턴

#### Directory Traversal
```
../
..\
%2e%2e%2f
%2e%2e%5c
..%2f
..%5c
```

#### System Files
```
/etc/passwd
/etc/shadow
/etc/hosts
boot.ini
win.ini
```

#### File Parameters
```
file=
page=
path=
include=
dir=
```

---

## 6. 위험도 평가

- **attack_severity**: Medium
- **민감 정보 노출 위험**
- **추가 공격의 전초전**

---

## 7. 대응 전략

### 7.1 초기 대응

- 로그 기록 및 모니터링

### 7.2 2차 대응

- 1분 10회 이상: Alert
- 민감 파일 접근 시도 시 즉시 차단

---

## 8. 예방 조치

- 파일 경로 화이트리스트
- 경로 정규화
- chroot jail
- 최소 권한 원칙

---

## 9. 참고 자료

- **OWASP Path Traversal**: https://owasp.org/www-community/attacks/Path_Traversal
- **CWE-22**: https://cwe.mitre.org/data/definitions/22.html

---

## 10. 변경 이력

| 버전 | 날짜 | 변경 내용 | 작성자 |
|------|------|----------|--------|
| v1.0 | 2026-01-02 | 초기 룰 작성 | 2SeC Team |