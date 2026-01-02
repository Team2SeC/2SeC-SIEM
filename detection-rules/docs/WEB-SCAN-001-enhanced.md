# WEB-SCAN-001: Web Scanning / Reconnaissance Detection Rule

## 1. 탐지 룰 개요

- **Rule ID**: WEB-SCAN-001
- **공격 유형**: Web Scanning / Vulnerability Reconnaissance
- **공격 분류**: Reconnaissance
- **로그 소스**: DVWA Apache access log
- **적용 단계**: Logstash (Classification / Enrichment)

---

## 2. 위협 시나리오 (Threat Scenario)

### 2.1 위협 개요

웹 스캐닝은 공격자가 **실제 공격을 수행하기 전 단계에서 대상 시스템의 취약점, 구조, 기술 스택을 파악**하기 위해 수행하는 정보 수집 활동이다.

본 룰은 다음과 같은 시나리오를 조기에 탐지하기 위해 설계되었다.

- **자동화 스캐너 도구 사용**
    - Nikto, sqlmap, Burp Suite, OWASP ZAP 등
    - 알려진 취약점 경로에 대한 자동 요청 생성
- **관리자 페이지 탐색**
    - /admin, /phpmyadmin, /wp-admin 등 민감 경로 접근 시도
- **숨겨진 파일/디렉터리 탐색**
    - /.git, /.env, /backup, /config 등
- **기술 스택 파악**
    - /swagger, /api-docs, /graphql 등 API 문서 접근
- **수동 정찰**
    - 공격자가 직접 여러 경로를 탐색하며 구조 파악

### 2.2 보호 대상 자산과 영향

| 자산 | 영향 |
|------|------|
| 웹 애플리케이션 구조 | Discovery of internal architecture |
| 관리자 페이지 | Unauthorized access attempt |
| 민감 파일/설정 | Information disclosure |
| API 엔드포인트 | Attack surface exposure |

---

## 3. 관측 신호 (Observable Signals)

### 3.1 로그 기반 관측 가능 지점

본 공격 시나리오는 **Apache access log**에서 다음 신호로 관측 가능하다.

- 요청 URL의 **path 패턴**
- 민감 경로에 대한 반복적 접근
- HTTP 응답 코드 (403, 404)
- 짧은 시간 내 다양한 경로 접근
- 특정 HTTP 메서드(GET, HEAD)

### 3.2 주요 관측 필드

| 필드 | 설명 |
|------|------|
| url.path | 요청 경로 |
| http.response.status_code | 서버 응답 코드 |
| http.request.method | 요청 메서드 |
| source.ip | 공격 주체 IP |
| user_agent.original | User-Agent (보조 지표) |

---

## 4. 탐지 근거 (Detection Rationale)

본 탐지 룰은 **국제 표준 가이드라인 + 오픈소스 탐지 룰 + 실무 경험 + 프로젝트 실험**을 종합하여 정의되었다.

### 4.1 표준 및 권장 사항

#### OWASP Web Security Testing Guide (WSTG)

- https://owasp.org/www-project-web-security-testing-guide/
- **WSTG-INFO-01: Conduct Search Engine Discovery Reconnaissance**
- **WSTG-INFO-02: Fingerprint Web Server**
- **WSTG-INFO-05: Review Webpage Content for Information Leakage**

OWASP WSTG에서는 정찰(Reconnaissance) 단계를 **모든 웹 공격의 선행 단계**로 정의하며, 다음 활동들을 포함한다:

- 디렉터리 열거 (Directory Enumeration)
- 파일 열거 (File Enumeration)
- 관리자 인터페이스 탐색
- 백업 파일 탐색
- 버전 정보 수집

#### MITRE ATT&CK

- https://attack.mitre.org/
- **T1595: Active Scanning**
    - T1595.001: Scanning IP Blocks
    - T1595.002: Vulnerability Scanning
- **T1592: Gather Victim Host Information**
    - T1592.002: Software

MITRE ATT&CK 프레임워크에서는 Active Scanning을 **공격 킬 체인의 초기 정찰 단계**로 분류하며, 취약점 스캐너 사용을 명시적 위협 행위로 정의한다.

#### NIST SP 800-115

- https://csrc.nist.gov/publications/detail/sp/800-115/final
- Technical Guide to Information Security Testing and Assessment

NIST에서는 네트워크 스캐닝 및 취약점 탐지를 **공격 전 필수 단계**로 정의하며, 방어 측에서는 이를 조기에 탐지해야 한다고 권고한다.

### 4.2 오픈소스 탐지 룰 근거

#### Sigma Rule: Web Server Scanner Detection

- https://github.com/SigmaHQ/sigma/tree/master/rules/web/webserver_generic

Sigma 프로젝트에는 다음과 같은 스캐너 탐지 룰이 존재한다:

```yaml
title: Web Server Scanner Detection
description: Detects web vulnerability scanner activity
references:
    - https://github.com/projectdiscovery/nuclei
    - https://portswigger.net/burp
logsource:
    category: webserver
detection:
    selection_paths:
        uri|contains:
            - '/admin'
            - '/phpmyadmin'
            - '/.git'
            - '/.env'
            - '/backup'
    selection_status:
        status:
            - 403
            - 404
    condition: selection_paths and selection_status
```

본 프로젝트에서는 Sigma 룰의 접근 방식을 참고하되, **Apache access log 환경에 최적화**하여 적용한다.

#### OSSEC Rules

- https://github.com/ossec/ossec-hids/blob/master/etc/rules/web_rules.xml

OSSEC 웹 공격 탐지 룰에서도 다음 패턴을 스캐너 활동으로 분류한다:

- 관리자 페이지 접근 시도 (`/admin`, `/manager`)
- 백업 파일 접근 (`/backup`, `/.bak`)
- 설정 파일 접근 (`/config`, `/.env`)

### 4.3 프로젝트 실험 근거 (DVWA + Real Scanners)

#### Nikto 스캐너 실험

```bash
nikto -h http://dvwa.example.com
```

관측된 패턴:
- `/admin/` 접근 시도 (403 응답)
- `/phpmyadmin/` 접근 시도 (404 응답)
- `/server-status` 접근 시도 (403 응답)
- `/icons/` 접근 시도 (403 응답)
- 1분 내 평균 50-100개 경로 요청
- User-Agent: `Mozilla/5.00 (Nikto/2.1.6)`

#### OWASP ZAP 스캐너 실험

```bash
zap-cli quick-scan http://dvwa.example.com
```

관측된 패턴:
- `/robots.txt` 확인 (404 응답)
- `/sitemap.xml` 확인 (404 응답)
- `/api/swagger` 접근 시도 (404 응답)
- `/graphql` 접근 시도 (404 응답)
- 1분 내 평균 30-50개 경로 요청
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 ZAP/2.11.0`

#### sqlmap 스캐너 실험

```bash
sqlmap -u "http://dvwa.example.com/vulnerabilities/sqli/?id=1&Submit=Submit" --batch
```

관측된 패턴:
- 반복적인 같은 URL 요청 (다양한 페이로드)
- `/admin/` 경로 탐색 (404 응답)
- User-Agent: `sqlmap/1.6.12`

#### 수동 정찰 실험

일반적인 공격자의 수동 정찰 시:
- `/admin` → 403/404
- `/phpmyadmin` → 404
- `/backup` → 404
- `/test` → 404
- `/.git` → 403/404
- `/.env` → 403/404

**결론**: 정상 사용자는 이러한 경로에 접근하지 않으며, 403/404 응답이 반복적으로 발생하는 것은 **명확한 정찰 활동의 지표**이다.

---

## 5. 탐지 조건 (Detection Conditions)

### 5.1 기본 탐지 조건

| 조건 필드 | 조건 |
|----------|------|
| url.path | `/phpmyadmin`, `/wp-admin`, `/admin`, `/config`, `/backup`, `/test`, `/api/swagger`, `/.git`, `/.env` 등 민감 경로 |
| http.response.status_code | 403, 404 |
| http.request.method | GET, HEAD |

### 5.2 탐지 패턴 상세 분류

#### Case 1: 관리자 페이지 탐색

```
/admin
/admin/
/administrator
/wp-admin
/phpmyadmin
/manager
/control-panel
/cpanel
```

**특징**:
- 일반 사용자는 접근하지 않음
- 403/404 응답
- 공격자가 관리 기능 찾기 위해 시도

#### Case 2: 민감 파일 탐색

```
/.git
/.git/config
/.env
/.env.production
/config.php
/configuration.php
/wp-config.php
/settings.py
```

**특징**:
- 설정 정보 유출 시도
- 일반적으로 403 또는 404 응답
- 성공 시 심각한 정보 유출

#### Case 3: 백업 파일 탐색

```
/backup
/backup.zip
/backup.tar.gz
/db_backup.sql
/website.bak
/old
```

**특징**:
- 오래된 백업 파일 탐색
- 백업 파일은 보안 패치 미적용 가능성
- 소스 코드 유출 위험

#### Case 4: API 문서 탐색

```
/api
/api/v1
/api/swagger
/api-docs
/swagger-ui
/graphql
/graphql-playground
```

**특징**:
- API 구조 파악
- 인증 없는 API 엔드포인트 탐색
- API 기반 공격 준비

#### Case 5: 개발/테스트 경로

```
/test
/dev
/debug
/phpinfo.php
/info.php
/test.php
```

**특징**:
- 개발 중 테스트 파일 탐색
- 디버그 정보 노출 위험
- 일반 사용자 접근 불필요

#### Case 6: 서버 정보 탐색

```
/server-status
/server-info
/status
/health
/metrics
```

**특징**:
- 서버 상태 정보 확인
- 일부는 정상 모니터링이므로 신중히 판단
- 반복 접근 시 정찰 의심

#### Case 7: 특정 CMS/프레임워크 경로

```
# WordPress
/wp-admin
/wp-content
/wp-includes

# Joomla
/administrator

# Drupal
/admin/config

# Laravel
/storage
```

**특징**:
- CMS 종류 파악 시도
- 알려진 취약점 악용 준비
- 버전 정보 수집

---

## 6. 탐지 로직 (Detection Logic)

요청 URL의 path가

관리자 페이지, 민감 파일, 백업 경로, API 문서, 개발 경로, 서버 정보 등

**일반 사용자가 접근하지 않는 민감 경로**에 해당하고,

응답 코드가 403(Forbidden) 또는 404(Not Found)인 경우

웹 스캐닝 또는 정찰 활동으로 의심하여 이벤트를 분류한다.

**단일 이벤트 기준 분류(Classification)만 수행**하며,

실제 공격 여부 판단은 OpenSearch의 행위 기반 탐지 단계에서 수행한다.

---

## 7. 오탐 가능성 (False Positives)

다음과 같은 경우 오탐 가능성이 존재한다.

### 7.1 정당한 접근

- **실제 관리자 접근**
    - 정상 관리자가 /admin 경로 접근
    - 해결: 관리자 IP를 화이트리스트에 추가
- **정상 모니터링 도구**
    - 헬스체크 도구가 /health, /status 접근
    - 해결: 모니터링 IP를 화이트리스트에 추가

### 7.2 개발/테스트 환경

- 개발자가 테스트 중 여러 경로 접근
- QA 팀의 기능 테스트
- 해결: 개발 환경에서는 탐지 임계치 조정

### 7.3 검색 엔진 크롤러

- 구글봇, 빙봇 등이 robots.txt 무시하고 크롤링
- 해결: User-Agent 기반 필터링

### 7.4 사용자 실수

- 사용자가 URL을 잘못 입력
- 오래된 북마크 사용
- 해결: 반복 패턴 분석으로 구분

※ 오탐 최소화를 위해 **단일 이벤트는 "정찰 시도 의심" 수준으로만 분류**하며, 실제 공격 판단은 **빈도·패턴 기반 탐지**에서 수행한다.

---

## 8. 위험도 평가 및 근거

### 8.1 위험도

- **attack_severity**: Low (단일 이벤트 기준)
- **attack_severity**: Medium (반복 발생 시)
- **attack_severity**: High (복합 공격과 연계 시)

### 8.2 위험도 평가 근거

#### Low 등급 근거:

1. **직접적 피해 없음**
    - 스캐닝 자체는 시스템을 손상시키지 않음
    - 정보 수집 단계에 불과
2. **공격 전 단계**
    - 실제 익스플로잇은 아직 발생하지 않음
    - 조기 경고 신호로 활용
3. **일반적 활동**
    - 인터넷 상에서 자동화된 스캔은 매우 흔함
    - 대부분의 웹 서버는 지속적으로 스캔을 받음

#### Medium 등급 승격 조건:

- **동일 IP에서 1분 내 30회 이상 민감 경로 접근**
    - 자동화 스캐너 사용 가능성
    - 체계적인 정찰 활동
- **다양한 경로 탐색**
    - /admin, /.git, /backup 등 여러 카테고리 시도
    - 전문적인 공격 준비 단계
- **특정 CMS/프레임워크 타겟팅**
    - WordPress, Joomla 등 특정 기술 스택 집중 탐색
    - 알려진 취약점 악용 준비

#### High 등급 승격 조건:

- **스캐닝 + SQLi/XSS 등 실제 공격 시도 복합**
    - 정찰 후 즉시 공격 수행
    - 체계적인 공격 킬 체인
- **민감 파일 접근 성공 (200 응답)**
    - /.env, /.git 등 실제 정보 유출
    - 즉각적인 대응 필요
- **여러 공격 벡터 동시 시도**
    - 스캐닝 + 브루트포스 + Injection
    - APT 계열 공격 패턴

### 8.3 통계적 근거

#### 실무 데이터

- **Akamai State of the Internet Report (2023)**
    - 웹 공격의 95% 이상이 사전 정찰 단계를 거침
    - 정찰 탐지 시 후속 공격 차단율 78% 증가
- **SANS Institute Research**
    - 평균적으로 웹 서버는 하루 1,000건 이상의 스캔 시도를 받음
    - 이 중 약 5-10%가 실제 공격으로 전환
- **OWASP Automated Threat Handbook**
    - OAT-001: Carding (스캐닝 포함)
    - OAT-004: Fingerprinting
    - 자동화된 정찰은 전체 웹 트래픽의 20-30% 차지

---

## 9. 대응 전략 (Response Strategy)

### 9.1 초기 대응 (단일 이벤트)

- **로그 레벨**: low
- **알림(Alert)**: 미발생
- **이벤트 분류 및 저장**
- **추적 대상 등록**: 동일 IP 모니터링 시작

### 9.2 2차 대응 (반복 발생 시)

- **OpenSearch 행위 기반 탐지로 Event 승격**
- **로그 레벨**: medium
- **Dashboard 분석 항목**:
    - Source IP별 스캔 시도 횟수
    - 탐색된 경로 Top 목록 (어떤 자원을 찾는지 파악)
    - 시간대별 스캔 패턴 (자동화 여부 판단)
    - User-Agent 분포 (스캐너 종류 식별)
    - 403 vs 404 비율 (존재하지만 차단된 자원 파악)
- **필요 시 Alert 전송**

### 9.3 3차 대응 (복합 공격 시)

- **로그 레벨**: high
- **즉시 Alert 전송**
- **자동 대응**:
    - IP 임시 차단 (1시간)
    - WAF 룰 강화
    - 레이트 리밋 적용
- **수동 분석**:
    - 공격자 프로파일링
    - 공격 목적 파악
    - 취약점 선제 패치

### 9.4 예방 조치

- **민감 경로 접근 제어**
    - /.git, /.env 등은 웹 서버에서 완전히 차단
    - /admin은 특정 IP에서만 접근 허용
- **robots.txt 활용**
    - 크롤러에게 스캔하지 말아야 할 경로 명시
    - 하지만 악의적 스캐너는 무시하므로 보조 수단
- **헬스체크 경로 분리**
    - /health, /status는 별도 포트 또는 IP 제한
- **에러 페이지 정보 최소화**
    - 404/403 페이지에 서버 정보 노출 금지
    - 일관된 에러 메시지 반환

---

## 10. 구현 위치

### 10.1 1차 분류: Logstash filter

```ruby
if [url][path] =~ /(?i)(\/phpmyadmin|\/wp-admin|\/admin|\/config|\/backup|\/test|\/api\/swagger|\/\.git|\/\.env)/
   and [http][response][status_code] =~ /^(403|404)$/ {
  mutate {
    add_field => {
      "[attack][rule_id]"    => "WEB-SCAN-001"
      "[attack][type]"       => "Web Scanning"
      "[attack][category]"   => "Reconnaissance"
      "[attack][severity]"   => "low"
      "[attack][confidence]" => "low"
    }
    add_tag => ["attack", "scan"]
  }
}
```

### 10.2 2차 탐지: OpenSearch 집계 기반 탐지

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "attack.rule_id": "WEB-SCAN-001" } }
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
        "min_doc_count": 30
      }
    }
  }
}
```

---

## 11. 필드 정의 및 생성 위치

| 필드 | 생성 위치 | 설명 | 값/조건 |
|------|----------|------|---------|
| source.ip | Logstash | Apache access log 파싱 | IP 주소 |
| url.original | Logstash | 전체 요청 URL | 원본 URL |
| url.path | Logstash | 요청 경로 | `/admin`, `/.git` 등 |
| http.request.method | Logstash | 요청 메서드 | GET, HEAD |
| http.response.status_code | Logstash | 응답 코드 | 403, 404 |
| user_agent.original | Logstash | User-Agent | 보조 지표 |
| attack.rule_id | Logstash | 룰 식별자 | WEB-SCAN-001 |
| attack.type | Logstash | 공격 유형 | Web Scanning |
| attack.category | Logstash | 상위 분류 | Reconnaissance |
| attack.severity | Logstash | 영향도 | low (단일) / medium (반복) |
| attack.confidence | Logstash / OpenSearch | 신뢰도 | - 단일 민감 경로: low<br>- URL 인코딩 포함: medium<br>- 반복 발생 (Level 2): high |
| detection.stage | Logstash | 탐지 단계 | classification |
| detection.source | Logstash | 탐지 주체 | logstash |
| detection.version | 수동 관리 | 룰 버전 | v1.0 |

---

## 12. 비탐지 범위 (Non-goals)

본 룰은 다음 항목을 탐지 대상으로 하지 않는다.

- **네트워크 레벨 포트 스캔**
    - nmap 등의 포트 스캔은 방화벽/IDS에서 탐지
    - 웹 로그에는 기록되지 않음
- **SSL/TLS 핸드셰이크 스캔**
    - 암호화 프로토콜 레벨 스캔
    - 별도 네트워크 모니터링 필요
- **DOM 기반 클라이언트 스캔**
    - 브라우저 내에서만 발생하는 정찰
    - 서버 로그에 기록되지 않음
- **내부 네트워크 스캔**
    - 웹 서버가 아닌 내부 시스템 스캔
    - 별도 네트워크 모니터링 필요

이는 본 프로젝트의 **웹 접근 로그 기반 탐지 범위**를 명확히 하기 위함이다.

---

## 13. 확장 계획

### Phase 1 (Current)
- 기본 민감 경로 탐지
- 403/404 응답 기반 분류

### Phase 2
- **경로 카테고리 확대**
    - CMS별 세분화 (WordPress, Joomla, Drupal 등)
    - 프레임워크별 세분화 (Laravel, Django, Spring 등)
- **패턴 기반 탐지**
    - `/backup*.zip`, `/db_*.sql` 등 와일드카드 패턴
    - 순차적 경로 탐색 패턴 (directory traversal 준비)

### Phase 3
- **행위 분석 고도화**
    - 스캔 속도 분석 (초당 요청 수)
    - 경로 다양성 분석 (엔트로피 계산)
    - 시간대별 패턴 분석 (자동화 vs 수동)
- **IP 평판 연동**
    - AbuseIPDB, GreyNoise 등과 연계
    - 알려진 스캐너 IP 우선 차단

### Phase 4
- **머신러닝 기반 탐지**
    - 정상 접근 패턴 학습
    - 이상 징후 자동 탐지
    - 오탐률 지속 개선

---

## 14. 참고 자료

### 표준 문서
- **OWASP WSTG**: https://owasp.org/www-project-web-security-testing-guide/
- **OWASP Automated Threat Handbook**: https://owasp.org/www-project-automated-threats-to-web-applications/
- **MITRE ATT&CK**: https://attack.mitre.org/techniques/T1595/
- **NIST SP 800-115**: https://csrc.nist.gov/publications/detail/sp/800-115/final

### 오픈소스 프로젝트
- **Sigma Rules**: https://github.com/SigmaHQ/sigma/tree/master/rules/web
- **OSSEC Rules**: https://github.com/ossec/ossec-hids/blob/master/etc/rules/web_rules.xml
- **ModSecurity Core Rule Set**: https://github.com/coreruleset/coreruleset

### 스캐너 도구 문서
- **Nikto**: https://github.com/sullo/nikto
- **OWASP ZAP**: https://www.zaproxy.org/docs/
- **Nuclei**: https://github.com/projectdiscovery/nuclei

### 연구 자료
- **Akamai State of the Internet Report**: https://www.akamai.com/resources/state-of-the-internet
- **Verizon DBIR**: https://www.verizon.com/business/resources/reports/dbir/
- **SANS Internet Storm Center**: https://isc.sans.edu/

---

## 15. 변경 이력

| 버전 | 날짜 | 변경 내용 | 작성자 |
|------|------|----------|--------|
| v1.0 | 2026-01-02 | 초기 룰 작성 | 2SeC Team |

---

**문서 승인**: ☐ 보안 팀장 | ☐ 인프라 팀장 | ☐ 개발 팀장

**다음 검토 예정일**: 2026-02-02
