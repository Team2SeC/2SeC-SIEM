# WEB-SQLI-001: SQL Injection Detection Rule

## 1. 탐지 룰 개요

- **Rule ID**: WEB-SQLI-001
- **공격 유형**: SQL Injection
- **공격 분류**: Injection
- **로그 소스**: DVWA Apache access log
- **적용 단계**: Logstash (Classification / Enrichment)

---

## 2. 위협 시나리오 (Threat Scenario)

### 2.1 위협 개요

SQL Injection은 웹 애플리케이션의 데이터베이스 쿼리에 악의적인 SQL 구문을 삽입하여 **인가되지 않은 데이터 접근, 수정, 삭제를 수행**하는 공격이다. 이는 OWASP Top 10에서 지속적으로 상위권을 차지하는 가장 위험한 웹 취약점 중 하나이다.

본 룰은 다음과 같은 시나리오를 탐지하기 위해 설계되었다.

- **Union-based SQLi**
    - UNION SELECT를 통한 다른 테이블 데이터 추출
    - 데이터베이스 구조 정보 수집
- **Boolean-based Blind SQLi**
    - `' OR 1=1--` 같은 논리 연산자를 통한 인증 우회
    - 참/거짓 응답을 통한 데이터 추출
- **Time-based Blind SQLi**
    - SLEEP(), WAITFOR DELAY 등을 통한 시간 지연 공격
    - 응답 시간 차이로 데이터 추출
- **Error-based SQLi**
    - 의도적인 SQL 에러 유발을 통한 정보 수집
    - 데이터베이스 버전, 구조 정보 노출
- **Second-Order SQLi**
    - 저장된 데이터를 통한 지연 실행
    - 프로필, 설정 등에 악성 SQL 저장

### 2.2 보호 대상 자산과 영향

| 자산 | 영향 |
|------|------|
| 데이터베이스 | Complete compromise |
| 사용자 데이터 | Confidentiality breach |
| 비즈니스 로직 | Integrity violation |
| 시스템 가용성 | Potential DoS |

---

## 3. 관측 신호 (Observable Signals)

### 3.1 로그 기반 관측 가능 지점

본 공격 시나리오는 **Apache access log**에서 다음 신호로 관측 가능하다.

- 요청 URL의 **query string**
- SQL 예약어 및 함수
- 특수 문자 패턴 (`'`, `"`, `;`, `--`)
- URL 인코딩된 SQL 구문
- 특정 HTTP 메서드(GET, POST)
- 응답 코드 패턴 (200, 500)

### 3.2 주요 관측 필드

| 필드 | 설명 |
|------|------|
| url.query | SQL 페이로드가 포함된 쿼리 파라미터 |
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

SQL Injection은 OWASP Top 10 2021에서 3위를 차지하며, 가장 위험한 웹 취약점 중 하나로 분류된다.

#### CWE-89: SQL Injection

- https://cwe.mitre.org/data/definitions/89.html
- SQL 명령어 삽입 취약점의 표준 분류

#### NIST SP 800-53

- SI-10: Information Input Validation
- 입력값 검증을 통한 SQL Injection 방지 통제

### 4.2 오픈소스 탐지 룰 근거

#### Sigma Rule

```yaml
title: SQL Injection in Web Logs
detection:
    selection:
        url|contains:
            - 'union select'
            - "' or 1=1"
            - 'benchmark('
            - 'sleep('
    condition: selection
```

#### ModSecurity Core Rule Set (CRS)

- Rule 942100-942999: SQL Injection Attack Detected
- 다양한 SQLi 패턴 포함

### 4.3 프로젝트 실험 근거

DVWA SQLi 모듈 실험 결과:

#### Low Security Level
```
id=' or 1=1-- -
id=' UNION SELECT user,password FROM users-- -
```

#### Medium Security Level
```
id=1 UNION SELECT user,password FROM users
id=1 AND SLEEP(5)
```

#### High Security Level
```
id=1' AND 1=1-- -
id=1' UNION SELECT database(),version()-- -
```

**관측된 패턴**:
- `UNION SELECT` 구문 빈번
- 주석 처리 (`--`, `#`) 사용
- 논리 연산자 (`OR`, `AND`) 활용
- 시스템 함수 호출 (`database()`, `version()`)

---

## 5. 탐지 조건 (Detection Conditions)

### 5.1 기본 탐지 조건

| 조건 필드 | 조건 |
|----------|------|
| url.query | SQL 예약어/패턴 포함 |
| http.request.method | GET, POST |
| http.response.status_code | 200, 500 |

### 5.2 탐지 패턴 상세 분류

#### Category 1: Union-based SQLi

```
UNION SELECT
UNION ALL SELECT
/*!UNION*/ SELECT
UNION/**/SELECT
```

#### Category 2: Boolean-based SQLi

```
' OR 1=1--
' OR '1'='1
" OR "1"="1
') OR ('1'='1
```

#### Category 3: Time-based SQLi

```
'; SLEEP(5)--
'; WAITFOR DELAY '00:00:05'--
BENCHMARK(1000000,MD5('test'))
```

#### Category 4: Error-based SQLi

```
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(...
' AND extractvalue(1,concat(0x7e,...
' AND updatexml(1,concat(0x7e,...
```

#### Category 5: System Information Gathering

```
@@version
database()
user()
information_schema.tables
information_schema.columns
```

#### Category 6: Encoded Patterns

```
%27%20OR%201%3D1
%55%4E%49%4F%4E (UNION in hex)
CHAR(85,78,73,79,78) (UNION in CHAR)
```

---

## 6. 탐지 로직 (Detection Logic)

요청 URL의 query string에

SQL 예약어, 함수, 논리 연산자, 또는 해당 문자열의 인코딩 형태가 포함될 경우

해당 요청을 **SQL Injection 의심 이벤트**로 분류한다.

**탐지 우선순위**:
1. 명확한 SQL 구문 (UNION SELECT, DROP TABLE)
2. 논리 우회 패턴 (' OR 1=1)
3. 시스템 함수 호출 (database(), @@version)
4. 인코딩된 패턴 (%27, CHAR())

---

## 7. 오탐 가능성 (False Positives)

다음과 같은 경우 오탐 가능성이 존재한다.

### 7.1 정당한 사용

- **검색 기능**
    - 사용자가 "SELECT" 단어를 검색
    - 프로그래밍 관련 콘텐츠 검색
- **코드 샘플 전송**
    - 교육 사이트, 포럼
    - 개발자 커뮤니티

### 7.2 애플리케이션 특성

- **동적 쿼리 생성**
    - 일부 레거시 시스템
    - 복잡한 검색 조건
- **로깅/디버깅**
    - SQL 쿼리를 URL에 포함하는 디버그 모드

### 7.3 오탐 최소화 전략

- 컨텍스트 분석 (파라미터 이름)
- 반복 패턴 확인
- IP 평판 검증
- 정상 사용 패턴 학습

---

## 8. 위험도 평가 및 근거

### 8.1 위험도

- **attack_severity**: Medium (단일 이벤트 기준)
- **attack_severity**: Critical (성공 시)

### 8.2 위험도 평가 근거

#### Medium 등급 근거:

1. **CVSS 기반 평가**
    - Base Score: 7.5 (High)
    - Attack Vector: Network (AV:N)
    - Attack Complexity: Low (AC:L)
    - Privileges Required: None (PR:N)
    - User Interaction: None (UI:N)
    - Confidentiality: High (C:H)
    - Integrity: Low (I:L)
    - Availability: None (A:N)

2. **실제 영향도**
    - 전체 데이터베이스 덤프 가능
    - 관리자 권한 탈취
    - 데이터 변조/삭제
    - 다른 시스템으로 피벗

3. **통계적 근거**
    - OWASP Top 10 지속 등재
    - Verizon DBIR: 웹 애플리케이션 공격의 24%
    - 평균 피해액: $196,000 (IBM)

#### Critical 등급 승격 조건:

- UNION SELECT 성공 (데이터 추출)
- 관리자 테이블 접근 시도
- information_schema 접근
- 대량 자동화 시도
- 시간 기반 공격 성공

---

## 9. 대응 전략 (Response Strategy)

### 9.1 초기 대응 (단일 이벤트)

- **로그 레벨**: medium
- **모니터링**: 강화 감시 대상 등록
- **분석**: 페이로드 패턴 기록

### 9.2 2차 대응 (반복 발생 시)

- **임계치**: 1분 10회 이상
- **자동 대응**:
    - IP 임시 차단 (15분)
    - WAF 룰 강화
    - 레이트 리밋 적용
- **분석 항목**:
    - 사용된 SQLi 기법 분류
    - 타겟 테이블/컬럼 파악
    - 공격 성공 여부 판단

### 9.3 3차 대응 (성공 징후 시)

- **로그 레벨**: critical
- **즉시 조치**:
    - IP 영구 차단
    - 데이터베이스 감사
    - 영향받은 데이터 확인
    - 침해 사고 대응 절차 시작

### 9.4 예방 조치

- **Prepared Statements 사용**
- **입력값 검증 강화**
- **최소 권한 원칙**
- **SQL 에러 메시지 숨김**
- **WAF SQLi 방어 룰 활성화**

---

## 10. 구현 위치

### 10.1 Logstash filter

```ruby
if [url][query] =~ /(?i)(union\s+select|' or 1=1|' or '1'='1|sleep\(|benchmark\(|concat\(|group_concat\(|0x[0-9a-f]+|waitfor\s+delay|exec\(|execute\(|information_schema|sysobjects|syscolumns)/ {
  mutate {
    add_field => {
      "[attack][rule_id]"    => "WEB-SQLI-001"
      "[attack][type]"       => "SQL Injection"
      "[attack][category]"   => "Injection"
      "[attack][severity]"   => "medium"
      "[attack][confidence]" => "medium"
    }
    add_tag => ["attack", "sqli"]
  }
}
```

---

## 11. 필드 정의 및 생성 위치

| 필드 | 생성 위치 | 설명 | 값/조건 |
|------|----------|------|---------|
| url.query | Logstash | 쿼리 파라미터 | SQL 패턴 포함 |
| attack.rule_id | Logstash | 룰 식별자 | WEB-SQLI-001 |
| attack.type | Logstash | 공격 유형 | SQL Injection |
| attack.category | Logstash | 상위 분류 | Injection |
| attack.severity | Logstash | 영향도 | medium / critical |
| attack.confidence | Logstash / OpenSearch | 신뢰도 | low / medium / high |

---

## 12. 비탐지 범위 (Non-goals)

본 룰은 다음 항목을 탐지 대상으로 하지 않는다.

- **POST Body 내 SQL Injection**
    - Apache access log 한계
    - 별도 애플리케이션 로그 필요
- **Stored/Second-Order SQLi**
    - 저장 후 실행되는 패턴
    - 시간차 공격
- **복잡한 인코딩/난독화**
    - 다중 인코딩
    - 커스텀 인코딩

---

## 13. 참고 자료

- **OWASP SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection
- **CWE-89**: https://cwe.mitre.org/data/definitions/89.html
- **sqlmap**: https://github.com/sqlmapproject/sqlmap
- **PortSwigger SQLi**: https://portswigger.net/web-security/sql-injection

---

## 14. 변경 이력

| 버전 | 날짜 | 변경 내용 | 작성자 |
|------|------|----------|--------|
| v1.0 | 2026-01-02 | 초기 룰 작성 | 2SeC Team |