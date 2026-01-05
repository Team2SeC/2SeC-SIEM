# WEB-AUTH-001: Authentication Abuse / Login Bruteforce Detection Rule

## 1. 탐지 룰 개요

- **Rule ID**: WEB-AUTH-001
- **공격 유형**: Authentication Abuse / Login Bruteforce / Credential Stuffing
- **공격 분류**: Authentication Abuse
- **로그 소스**: DVWA Apache access log
- **적용 단계**: Logstash (Classification / Enrichment)

---

## 2. 위협 시나리오 (Threat Scenario)

### 2.1 위협 개요

인증 남용(Authentication Abuse)은 공격자가 **정당한 사용자 계정에 무단으로 접근**하기 위해 수행하는 공격이다. 주요 공격 기법으로는 무차별 대입 공격(Bruteforce), 자격 증명 스터핑(Credential Stuffing), 패스워드 스프레이(Password Spraying) 등이 있다.

본 룰은 다음과 같은 시나리오를 탐지하기 위해 설계되었다.

- **Bruteforce Attack (무차별 대입 공격)**
    - 하나의 계정에 대해 다양한 비밀번호 시도
    - 자동화 도구 사용 (Hydra, Medusa, Burp Intruder 등)
    - 짧은 시간 내 대량 로그인 시도
- **Credential Stuffing (자격 증명 스터핑)**
    - 유출된 ID/비밀번호 조합을 대량으로 시도
    - 다른 서비스에서 유출된 계정 정보 재사용
    - 성공률은 낮지만 대규모로 수행
- **Password Spraying (패스워드 스프레이)**
    - 여러 계정에 대해 소수의 일반적인 비밀번호 시도
    - 계정 잠금 정책 우회
    - "password123", "admin", "12345678" 등 흔한 비밀번호 사용
- **Account Enumeration (계정 열거)**
    - 존재하는 계정 ID 확인
    - 로그인 실패 메시지 차이 악용
    - 이메일 주소 또는 사용자명 수집

### 2.2 보호 대상 자산과 영향

| 자산 | 영향 |
|------|------|
| 사용자 계정 | Unauthorized access |
| 사용자 데이터 | Confidentiality breach |
| 세션 토큰 | Session hijacking |
| 시스템 무결성 | Data manipulation |
| 서비스 가용성 | Resource exhaustion from automated attempts |

---

## 3. 관측 신호 (Observable Signals)

### 3.1 로그 기반 관측 가능 지점

본 공격 시나리오는 **Apache access log**에서 다음 신호로 관측 가능하다.

- 요청 URL의 **path 패턴** (로그인 경로)
- HTTP 요청 메서드 (POST 주요, GET 일부)
- HTTP 응답 코드 (401, 403, 200, 302)
- 짧은 시간 내 반복적인 로그인 시도
- 동일 Source IP에서 다수 요청

### 3.2 주요 관측 필드

| 필드 | 설명 |
|------|------|
| url.path | 로그인 경로 (`/login.php`, `/auth`, etc.) |
| http.request.method | 요청 메서드 (POST 주요) |
| http.response.status_code | 응답 코드 (401, 403, 200, 302) |
| source.ip | 공격 주체 IP |
| http.response.body.bytes | 응답 크기 (성공/실패 구분 보조) |

---

## 4. 탐지 근거 (Detection Rationale)

본 탐지 룰은 **국제 표준 가이드라인 + 실무 경험 + 프로젝트 실험**을 종합하여 정의되었다.

### 4.1 표준 및 권장 사항

#### OWASP Top 10

- https://owasp.org/Top10/
- **A07:2021 – Identification and Authentication Failures**

OWASP Top 10 2021에서 인증 실패는 **7번째로 중요한 웹 애플리케이션 위험**으로 분류되며, 다음을 포함한다:

- 자동화된 공격 허용 (브루트포스, credential stuffing)
- 약한 비밀번호 허용
- 비효율적인 credential recovery 프로세스

#### OWASP Authentication Cheat Sheet

- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

인증 공격 방어 권장 사항:

- **레이트 리밋 적용**: IP당, 계정당 로그인 시도 횟수 제한
- **CAPTCHA 도입**: 자동화 공격 방지
- **계정 잠금**: 일정 횟수 실패 시 일시적 잠금
- **로그인 실패 로깅**: 모든 실패 시도 기록 및 모니터링

#### MITRE ATT&CK

- https://attack.mitre.org/
- **T1110: Brute Force**
    - T1110.001: Password Guessing
    - T1110.002: Password Cracking
    - T1110.003: Password Spraying
    - T1110.004: Credential Stuffing

MITRE ATT&CK에서 Brute Force는 **Credential Access** 전술의 핵심 기법으로 분류된다.

#### NIST SP 800-63B

- https://pages.nist.gov/800-63-3/sp800-63b.html
- Digital Identity Guidelines: Authentication and Lifecycle Management

NIST에서는 레이트 리밋 및 자동화 공격 탐지를 **필수 보안 통제**로 권고한다.

### 4.2 실무 및 침해 사례

#### 실제 침해 사고 사례

1. **Dropbox 계정 침해 (2012)**
    - 유출된 credential로 6,800만 개 계정 침해
    - Credential Stuffing 공격
2. **Adobe 계정 침해 (2013)**
    - 3,800만 개 계정 정보 유출
    - 이후 다른 서비스에서 credential stuffing에 활용
3. **Yahoo 계정 침해 (2013-2014)**
    - 30억 개 이상 계정 정보 유출
    - 이후 수년간 credential stuffing 공격에 악용

#### 통계 데이터

- **Verizon DBIR 2023**
    - 데이터 침해의 49%가 stolen credentials 사용
    - 브루트포스 공격은 전체 침해 시도의 18%
- **Akamai Credential Abuse Report (2023)**
    - 일일 평균 500만 건의 credential stuffing 시도 탐지
    - 성공률: 약 0.1-2% (하지만 대규모 시도로 상당한 피해)
- **Google Security Blog**
    - 구글은 매일 수백만 건의 brute force 시도를 차단
    - CAPTCHA 도입으로 90% 이상 감소

### 4.3 프로젝트 실험 근거

#### Hydra 브루트포스 실험

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt dvwa.example.com http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"
```

관측된 패턴:
- 초당 10-20개 POST 요청
- `/login.php` 경로 집중
- 대부분 401 또는 200 (로그인 실패 페이지) 응답
- User-Agent: `Mozilla/4.0 (Hydra)`

#### Burp Suite Intruder 실험

DVWA 로그인 페이지 대상:
- 수동으로 비밀번호 리스트 설정
- 초당 5-10개 요청 (기본 설정)
- 302 응답 시 성공 (리다이렉트)
- 200 응답 시 실패 (동일 페이지 유지)

#### 정상 사용자 vs 공격 비교

| 특징 | 정상 사용자 | 브루트포스 공격 |
|------|------------|----------------|
| 로그인 시도 횟수 | 1-3회 (평균) | 수십~수천 회 |
| 시간 간격 | 수초~수분 | 초당 여러 번 |
| 실패 후 행동 | 비밀번호 재설정 | 계속 시도 |
| User-Agent | 정상 브라우저 | 도구 식별자 또는 동일 |
| 성공 시 행동 | 정상 활동 | 즉시 다른 계정 시도 |

**결론**: 짧은 시간 내 반복적인 로그인 시도는 **명백한 자동화 공격 지표**이다.

---

## 5. 탐지 조건 (Detection Conditions)

### 5.1 기본 탐지 조건

| 조건 필드 | 조건 |
|----------|------|
| url.path | `/login.php`, `/login`, `/auth`, `/signin`, `/sign-in`, `/logon`, `/authentication`, `/admin/login` 등 |
| http.request.method | POST (주요), GET (일부 레거시 시스템) |
| http.response.status_code | 200 (실패 페이지), 401 (Unauthorized), 403 (Forbidden), 302 (성공 시 리다이렉트) |

### 5.2 탐지 패턴 상세 분류

#### Case 1: 일반 로그인 경로

```
/login
/login.php
/login.html
/signin
/sign-in
/sign_in
/logon
/logon.php
/authenticate
/authentication
/auth
```

**특징**:
- 가장 일반적인 로그인 경로
- POST 메서드 사용
- 브루트포스 주요 대상

#### Case 2: 관리자 로그인 경로

```
/admin/login
/admin/login.php
/administrator/login
/wp-admin
/wp-login.php
/manager/login
/control-panel/login
```

**특징**:
- 관리자 계정 타겟팅
- 높은 권한 획득 목적
- 공격 성공 시 피해 심각

#### Case 3: API 기반 인증

```
/api/auth
/api/login
/api/v1/authenticate
/api/v1/token
/oauth/token
```

**특징**:
- RESTful API 인증
- JSON 응답
- 토큰 기반 인증

#### Case 4: CMS별 로그인 경로

```
# WordPress
/wp-login.php
/wp-admin

# Joomla
/administrator/index.php

# Drupal
/user/login

# Magento
/admin
/customer/account/login
```

**특징**:
- 특정 CMS 타겟팅
- 알려진 경로 악용
- 버전별 취약점 활용 가능

#### Case 5: 응답 코드별 의미

| 응답 코드 | 의미 | 탐지 관점 |
|----------|------|----------|
| 200 | 로그인 실패 (동일 페이지 반환) | 실패 시도 카운트 |
| 302 | 로그인 성공 (리다이렉트) | 성공 확인, 계정 노출 |
| 401 | Unauthorized (인증 실패) | 명시적 실패 |
| 403 | Forbidden (계정 잠금 등) | 계정 잠금 정책 동작 |

---

## 6. 탐지 로직 (Detection Logic)

요청 URL의 path가 **로그인 또는 인증 관련 경로**에 해당하고,

HTTP 메서드가 POST이며,

응답 코드가 401, 403, 200, 302 중 하나인 경우

인증 시도로 분류한다.

**단일 이벤트 기준 분류(Classification)만 수행**하며,

실제 공격 여부 판단은 **동일 IP의 반복 횟수 및 시간 기반 탐지**에서 수행한다.

### Level 2 탐지 기준 (OpenSearch)

- **동일 IP에서 1분 내 5회 이상 로그인 실패**
    - Bruteforce 의심
    - Alert 생성
- **동일 IP에서 10분 내 10회 이상 로그인 시도**
    - 자동화 공격 가능성
    - Alert + IP 차단 고려
- **실패 → 성공 전환**
    - 브루트포스 성공
    - 즉시 Alert + 계정 잠금 + 분석

---

## 7. 오탐 가능성 (False Positives)

### 7.1 정상 사용자 행동

- **비밀번호를 잊어버린 사용자**
    - 2-3회 실패 후 비밀번호 재설정 이동
    - 해결: 임계치를 5회 이상으로 설정
- **자동 로그인 기능 오류**
    - 저장된 비밀번호가 만료되어 반복 실패
    - 해결: 동일 User-Agent + Cookie 패턴 분석
- **공유 IP (NAT, Proxy)**
    - 회사/학교 등에서 여러 사용자가 동일 IP 사용
    - 해결: IP + User-Agent 조합 또는 세션 기반 분석

### 7.2 개발/테스트 환경

- **자동화 테스트**
    - CI/CD 파이프라인에서 로그인 테스트
    - 해결: 테스트 IP 화이트리스트
- **QA 테스트**
    - 기능 테스트 시 반복 로그인
    - 해결: QA 계정 또는 IP 제외

### 7.3 레거시 시스템

- **세션 만료 후 자동 재로그인**
    - 일부 레거시 시스템에서 발생
    - 해결: 응답 패턴 분석

※ 오탐 최소화를 위해 **임계치를 신중하게 설정**하고, **행위 패턴을 종합적으로 분석**해야 한다.

---

## 8. 위험도 평가 및 근거

### 8.1 위험도

- **attack_severity**: High (단일 이벤트 기준도 주목)
- **attack_severity**: Critical (반복 발생 시)
- **attack_severity**: Critical (성공 시)

### 8.2 위험도 평가 근거

#### High 등급 근거:

1. **직접적인 계정 침해 위협**
    - 성공 시 사용자 계정 완전 장악
    - 개인정보 유출, 데이터 변조 가능
2. **CVSS 기반 평가**
    - Base Score: 7.5-8.5 (High)
    - Attack Vector: Network (AV:N)
    - Attack Complexity: Low (AC:L)
    - Privileges Required: None (PR:N)
    - User Interaction: None (UI:N)
    - Confidentiality: High (C:H)
    - Integrity: High (I:H)
3. **실제 침해 빈도**
    - Verizon DBIR: 데이터 침해의 49%가 stolen credentials
    - 브루트포스는 가장 흔한 공격 벡터 중 하나

#### Critical 등급 승격 조건:

- **동일 IP에서 1분 내 5회 이상 로그인 시도**
    - 자동화 브루트포스 명확
    - 즉시 대응 필요
- **브루트포스 성공 (실패 → 302 전환)**
    - 계정 침해 성공
    - 긴급 대응 필요
    - 계정 잠금 + 비밀번호 강제 재설정
- **관리자 계정 대상 공격**
    - /admin/login, /wp-admin 등
    - 성공 시 시스템 전체 장악 가능

### 8.3 통계적 근거

- **Verizon DBIR 2023**
    - 데이터 침해의 49%가 stolen credentials
    - 브루트포스는 18%
- **Akamai (2023)**
    - 일일 500만 건 credential stuffing 시도
    - 성공률 0.1-2% (하지만 대규모 시도로 상당한 피해)
- **IBM Cost of a Data Breach Report (2023)**
    - 계정 침해로 인한 평균 피해액: $4.45M
    - Credential 관련 침해의 평균 탐지 시간: 277일

---

## 9. 대응 전략 (Response Strategy)

### 9.1 초기 대응 (단일 이벤트)

- **로그 레벨**: medium
- **알림(Alert)**: 미발생
- **모니터링 시작**: 동일 IP 추적

### 9.2 2차 대응 (반복 발생 시)

- **1분 내 5회 이상 로그인 시도**
    - 로그 레벨: high
    - 즉시 Alert
    - Dashboard 분석:
        - Source IP별 로그인 시도 횟수
        - 실패 → 성공 전환 여부
        - 타겟 계정 Top 목록 (계정 열거 탐지)
        - User-Agent 분포 (자동화 도구 확인)
- **자동 대응**:
    - IP 임시 차단 (15분)
    - CAPTCHA 적용
    - 레이트 리밋 강화

### 9.3 3차 대응 (성공 시)

- **브루트포스 성공 탐지**
    - 로그 레벨: critical
    - 긴급 Alert
    - 자동 대응:
        - 해당 계정 즉시 잠금
        - 활성 세션 모두 종료
        - IP 차단 (24시간)
        - 비밀번호 강제 재설정 플래그
    - 수동 분석:
        - 계정 활동 로그 검토
        - 데이터 변조 여부 확인
        - 2차 피해 확인

### 9.4 예방 조치

- **레이트 리밋 적용**
    - IP당: 1분 내 5회
    - 계정당: 5분 내 3회
- **CAPTCHA 도입**
    - 2회 실패 후 CAPTCHA
    - 자동화 공격 효과적 차단
- **계정 잠금 정책**
    - 5회 실패 시 15분 잠금
    - 관리자에게 알림
- **강력한 비밀번호 정책**
    - 최소 12자
    - 대소문자, 숫자, 특수문자 조합
    - 흔한 비밀번호 차단
- **Multi-Factor Authentication (MFA)**
    - 비밀번호 + OTP/SMS
    - 브루트포스 무력화

---

## 10. 구현 위치

### 10.1 1차 분류: Logstash filter

```ruby
if [url][path] =~ /(?i)(\/login\.php|\/login|\/auth|\/signin|\/sign-in|\/logon|\/authentication|\/admin\/login|\/wp-login\.php)/
   and [http][request][method] == "POST" {
  mutate {
    add_field => {
      "[attack][rule_id]"    => "WEB-AUTH-001"
      "[attack][type]"       => "Login Bruteforce"
      "[attack][category]"   => "Authentication Abuse"
      "[attack][severity]"   => "high"
      "[attack][confidence]" => "low"
    }
    add_tag => ["attack", "auth_bruteforce"]
  }
}
```

### 10.2 2차 탐지: OpenSearch 집계

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "attack.rule_id": "WEB-AUTH-001" } },
        {
          "terms": {
            "http.response.status_code": ["200", "401", "403"]
          }
        }
      ],
      "filter": [
        { "range": { "@timestamp": { "gte": "now-1m" } } }
      ]
    }
  },
  "aggs": {
    "by_source_ip": {
      "terms": {
        "field": "source.ip",
        "min_doc_count": 5
      }
    }
  }
}
```

### 10.3 성공 탐지 쿼리

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "attack.rule_id": "WEB-AUTH-001" } },
        { "term": { "http.response.status_code": "302" } }
      ],
      "filter": [
        { "range": { "@timestamp": { "gte": "now-5m" } } }
      ]
    }
  }
}
```

---

## 11. 필드 정의 및 생성 위치

| 필드 | 생성 위치 | 설명 | 값/조건 |
|------|----------|------|---------|
| url.path | Logstash | 요청 경로 | `/login.php`, `/auth` 등 |
| http.request.method | Logstash | 요청 메서드 | POST (주요), GET |
| http.response.status_code | Logstash | 응답 코드 | 200, 401, 403, 302 |
| source.ip | Logstash | 클라이언트 IP | IP 주소 |
| attack.rule_id | Logstash | 룰 식별자 | WEB-AUTH-001 |
| attack.type | Logstash | 공격 유형 | Login Bruteforce |
| attack.category | Logstash | 상위 분류 | Authentication Abuse |
| attack.severity | Logstash | 영향도 | high (단일) / critical (반복) |
| attack.confidence | Logstash / OpenSearch | 신뢰도 | - 단일 시도: low<br>- 3-4회 반복: medium<br>- 5회 이상: high |
| detection.stage | Logstash | 탐지 단계 | classification |
| detection.source | Logstash | 탐지 주체 | logstash |
| detection.version | 수동 관리 | 룰 버전 | v1.0 |

---

## 12. 비탐지 범위 (Non-goals)

본 룰은 다음 항목을 탐지 대상으로 하지 않는다.

- **실제 비밀번호 크래킹 성공 여부**
    - 애플리케이션 로그 분석 필요
    - 웹 로그만으로는 한계
- **세션 하이재킹**
    - 쿠키 도용, XSS 등 별도 공격
- **소셜 엔지니어링**
    - 피싱을 통한 credential 수집
- **내부자 위협**
    - 정당한 credential 사용

이는 본 프로젝트의 **웹 접근 로그 기반 탐지 범위**를 명확히 하기 위함이다.

---

## 13. 확장 계획

### Phase 2
- **계정명 파싱**
    - POST body에서 username 추출
    - 계정별 시도 횟수 분석
- **응답 시간 분석**
    - 성공 vs 실패 응답 시간 차이
    - Timing attack 탐지

### Phase 3
- **행위 패턴 분석**
    - 로그인 성공 후 활동 분석
    - 비정상 활동 탐지
- **머신러닝 기반 탐지**
    - 정상 로그인 패턴 학습
    - 이상 징후 자동 탐지

---

## 14. 참고 자료

### 표준 문서
- **OWASP Top 10**: https://owasp.org/Top10/
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **MITRE ATT&CK T1110**: https://attack.mitre.org/techniques/T1110/
- **NIST SP 800-63B**: https://pages.nist.gov/800-63-3/sp800-63b.html

### 도구 문서
- **Hydra**: https://github.com/vanhauser-thc/thc-hydra
- **Medusa**: https://github.com/jmk-foofus/medusa
- **Burp Suite Intruder**: https://portswigger.net/burp/documentation/desktop/tools/intruder

### 연구 자료
- **Verizon DBIR**: https://www.verizon.com/business/resources/reports/dbir/
- **Akamai Credential Abuse**: https://www.akamai.com/resources/research/credential-stuffing
- **IBM Cost of Data Breach**: https://www.ibm.com/security/data-breach

---

## 15. 변경 이력

| 버전 | 날짜 | 변경 내용 | 작성자 |
|------|------|----------|--------|
| v1.0 | 2026-01-02 | 초기 룰 작성 및 상세화 | 2SeC Team |

---

**문서 승인**: ☐ 보안 팀장 | ☐ 인프라 팀장 | ☐ 개발 팀장

**다음 검토 예정일**: 2026-02-02
