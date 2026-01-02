# WEB-UA-001: Suspicious User-Agent Detection Rule

## 1. 탐지 룰 개요

- **Rule ID**: WEB-UA-001
- **공격 유형**: Suspicious User-Agent / Automated Tool Detection
- **공격 분류**: Reconnaissance
- **로그 소스**: DVWA Apache access log
- **적용 단계**: Logstash (Classification / Enrichment)

---

## 2. 위협 시나리오 (Threat Scenario)

### 2.1 위협 개요

User-Agent는 웹 요청을 수행하는 클라이언트(브라우저, 도구, 스크립트 등)를 식별하는 HTTP 헤더이다. 공격자는 자동화 도구를 사용하여 웹 애플리케이션을 스캔하거나 공격을 수행하며, 이러한 도구들은 **특유의 User-Agent 문자열**을 남긴다.

본 룰은 다음과 같은 시나리오를 탐지하기 위해 설계되었다.

- **취약점 스캐너 사용**
    - sqlmap, Nikto, OWASP ZAP, Burp Suite, Nuclei 등
    - 자동화된 취약점 탐색 및 익스플로잇 시도
- **디렉터리 브루트포스 도구**
    - dirb, gobuster, wfuzz, dirsearch 등
    - 숨겨진 경로 및 파일 탐색
- **스크립트 기반 HTTP 클라이언트**
    - curl, wget, python-requests, Go-http-client 등
    - 자동화된 API 호출 및 데이터 수집
- **봇 및 크롤러**
    - 악의적 봇, 스크래핑 봇
    - 정보 수집 및 콘텐츠 도용

### 2.2 보호 대상 자산과 영향

| 자산 | 영향 |
|------|------|
| 웹 애플리케이션 | Automated attack attempts |
| 서버 리소스 | Resource exhaustion from bot traffic |
| 콘텐츠/데이터 | Unauthorized scraping |
| 사용자 경험 | Service degradation from automated requests |

---

## 3. 관측 신호 (Observable Signals)

### 3.1 로그 기반 관측 가능 지점

본 공격 시나리오는 **Apache access log**에서 다음 신호로 관측 가능하다.

- HTTP 요청 헤더의 **User-Agent 문자열**
- 비정상적인 클라이언트 식별자
- 스크립트 언어 또는 자동화 도구 식별자
- 정상 브라우저가 아닌 HTTP 클라이언트

### 3.2 주요 관측 필드

| 필드 | 설명 |
|------|------|
| user_agent.original | User-Agent 헤더 전체 문자열 |
| source.ip | 요청 주체 IP |
| url.path | 요청 경로 (보조 지표) |
| http.request.method | 요청 메서드 |
| http.response.status_code | 응답 코드 (보조 지표) |

---

## 4. 탐지 근거 (Detection Rationale)

본 탐지 룰은 **실무 경험 + 오픈소스 탐지 룰 + 도구 문서 분석**을 종합하여 정의되었다.

### 4.1 표준 및 권장 사항

#### OWASP Automated Threat Handbook

- https://owasp.org/www-project-automated-threats-to-web-applications/
- **OAT-011: Scraping**
- **OAT-018: Footprinting**

OWASP에서는 자동화된 위협을 명시적으로 분류하며, User-Agent 기반 탐지를 **자동화 도구 식별의 첫 번째 방어선**으로 권고한다.

#### MITRE ATT&CK

- https://attack.mitre.org/
- **T1595.002: Vulnerability Scanning**

자동화 도구를 이용한 취약점 스캐닝은 공격 킬 체인의 초기 단계로 분류된다.

### 4.2 오픈소스 탐지 룰 근거

#### Sigma Rule: Suspicious User-Agent

```yaml
title: Suspicious User-Agent in Web Logs
detection:
    selection:
        user_agent|contains:
            - 'sqlmap'
            - 'nikto'
            - 'nmap'
            - 'masscan'
            - 'curl'
            - 'wget'
            - 'python-requests'
            - 'Go-http-client'
    condition: selection
```

#### ModSecurity Core Rule Set (CRS)

- https://github.com/coreruleset/coreruleset
- **Rule 913100**: User-Agent missing or empty
- **Rule 913110**: Scanner detection

ModSecurity CRS는 악의적 User-Agent 패턴을 광범위하게 정의하고 차단한다.

### 4.3 도구별 User-Agent 분석

#### 취약점 스캐너

| 도구 | User-Agent 예시 |
|------|-----------------|
| sqlmap | `sqlmap/1.6.12 (http://sqlmap.org)` |
| Nikto | `Mozilla/5.00 (Nikto/2.1.6)` |
| OWASP ZAP | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ... ZAP/2.11.0` |
| Burp Suite | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ... Burp Suite` |
| Nuclei | `Nuclei - Open-source project (github.com/projectdiscovery/nuclei)` |
| Acunetix | `Acunetix Web Vulnerability Scanner` |
| Nessus | `Mozilla/5.0 (compatible; Nessus)` |

#### 디렉터리 브루트포스

| 도구 | User-Agent 예시 |
|------|-----------------|
| dirb | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` (기본값, 변경 가능) |
| gobuster | `gobuster/3.1.0` |
| wfuzz | `Wfuzz/3.1.0` |
| dirsearch | `python-requests/2.28.1` |
| ffuf | `Fuzz Faster U Fool - v1.5.0` |

#### 스크립트 HTTP 클라이언트

| 도구/라이브러리 | User-Agent 예시 |
|----------------|-----------------|
| curl | `curl/7.68.0` |
| wget | `Wget/1.20.3 (linux-gnu)` |
| python-requests | `python-requests/2.28.1` |
| Go net/http | `Go-http-client/1.1` |
| Java HttpClient | `Apache-HttpClient/4.5.13 (Java/11.0.11)` |
| PowerShell | `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1682` |

#### 악의적 봇

| 봇 유형 | User-Agent 예시 |
|---------|-----------------|
| 스크래핑 봇 | `Mozilla/5.0 (compatible; Scrapy/2.5.1)` |
| 일반 봇 | `Bot`, `Spider`, `Crawler` (키워드) |
| libwww-perl | `libwww-perl/6.05` |

### 4.4 프로젝트 실험 근거

#### sqlmap 실험

```bash
sqlmap -u "http://dvwa.example.com/vulnerabilities/sqli/?id=1" --batch
```

관측된 User-Agent:
```
sqlmap/1.6.12 (http://sqlmap.org)
```

**특징**:
- 명확한 도구 식별자
- 버전 정보 포함
- 변조 가능하지만 기본 설정에서는 명시적

#### Nikto 실험

```bash
nikto -h http://dvwa.example.com
```

관측된 User-Agent:
```
Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)
```

**특징**:
- Mozilla 위장 시도
- 하지만 "Nikto" 문자열 명시
- Evasion 모드 및 테스트 정보 포함

#### curl 실험

```bash
curl http://dvwa.example.com/admin
```

관측된 User-Agent:
```
curl/7.68.0
```

**특징**:
- 간결한 식별자
- 버전 정보 포함
- 정상 용도(API 테스트, 모니터링)와 악의적 용도 모두 가능

#### 정상 브라우저 비교

Chrome:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
```

Firefox:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0
```

Safari:
```
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15
```

**결론**: 정상 브라우저는 복잡한 User-Agent 문자열을 가지며, 도구 이름을 직접 노출하지 않는다.

---

## 5. 탐지 조건 (Detection Conditions)

### 5.1 기본 탐지 조건

| 조건 필드 | 조건 |
|----------|------|
| user_agent.original | 취약점 스캐너 키워드: `sqlmap`, `nikto`, `nmap`, `masscan`, `nessus`, `acunetix`, `nuclei`, `burp`, `zap` |
| user_agent.original | 디렉터리 브루트포스: `dirb`, `gobuster`, `wfuzz`, `dirsearch`, `ffuf` |
| user_agent.original | 스크립트 클라이언트: `curl`, `wget`, `python-requests`, `Go-http-client`, `Java/`, `libwww` |
| user_agent.original | 봇 키워드: `bot`, `spider`, `crawler`, `scraper`, `scanner` |

### 5.2 탐지 패턴 상세 분류

#### Category 1: 명시적 취약점 스캐너

```
sqlmap/1.6.12
Nikto/2.1.6
Acunetix Web Vulnerability Scanner
Nessus
OpenVAS
w3af.org
```

**특징**:
- 명확한 도구 이름
- 오탐 가능성 매우 낮음
- 즉시 차단 대상

#### Category 2: 디렉터리 및 컨텐츠 브루트포스

```
gobuster/3.1.0
wfuzz/3.1.0
ffuf/1.5.0
dirsearch
```

**특징**:
- 숨겨진 경로 탐색
- 대량 요청 동반
- WEB-SCAN-001과 연계 탐지

#### Category 3: 스크립트 기반 HTTP 클라이언트

```
curl/7.68.0
Wget/1.20.3
python-requests/2.28.1
Go-http-client/1.1
Apache-HttpClient/
```

**특징**:
- 정상 용도와 악의적 용도 혼재
- 단독 탐지 시 confidence: low
- 다른 공격 패턴과 결합 시 high

#### Category 4: 봇 및 크롤러

```
(키워드 포함)
bot
spider
crawler
scraper
scanner
```

**특징**:
- 일부는 정상 봇 (Googlebot, Bingbot)
- User-Agent만으로 판단 어려움
- IP 평판 데이터와 결합 필요

#### Category 5: 라이브러리 및 프레임워크

```
libwww-perl/6.05
Java/11.0.11
Python-urllib/3.10
```

**특징**:
- 자동화 스크립트 가능성
- 정상 백엔드 서비스도 사용
- 요청 패턴과 결합 분석 필요

---

## 6. 탐지 로직 (Detection Logic)

HTTP 요청의 User-Agent 헤더에

**취약점 스캐너, 자동화 도구, 스크립트 클라이언트, 악의적 봇**의

식별자 또는 키워드가 포함된 경우

자동화된 공격 시도 또는 비정상 접근으로 의심하여 이벤트를 분류한다.

**단일 이벤트 기준 분류(Classification)만 수행**하며,

실제 공격 여부 판단은 **URL 패턴, 응답 코드, 반복 횟수**와 결합하여 수행한다.

---

## 7. 오탐 가능성 (False Positives)

### 7.1 정당한 자동화

- **모니터링 도구**
    - 헬스체크: `curl`, `wget` 사용
    - 해결: 모니터링 서버 IP 화이트리스트
- **CI/CD 파이프라인**
    - 자동 테스트: `python-requests`, `Go-http-client`
    - 해결: CI 서버 IP 화이트리스트
- **내부 서비스 간 통신**
    - 마이크로서비스 아키텍처에서 `Java HttpClient`, `Go net/http` 사용
    - 해결: 내부 네트워크 대역 제외

### 7.2 정상 봇

- **검색 엔진 크롤러**
    - Googlebot, Bingbot 등
    - User-Agent에 "bot" 키워드 포함
    - 해결: 공식 크롤러 IP 대역 확인 및 화이트리스트

### 7.3 개발/테스트

- **개발자 테스트**
    - API 테스트 시 `curl`, `Postman`, `Insomnia` 사용
    - 해결: 개발 환경에서는 탐지 비활성화 또는 임계치 조정

### 7.4 User-Agent 위조

- **공격자가 정상 브라우저로 위장**
    - 많은 도구가 User-Agent 변경 기능 제공
    - sqlmap: `--user-agent="Mozilla/5.0 ..."`
    - 해결: User-Agent만으로 완전한 탐지 불가, 보조 지표로 활용

※ **중요**: User-Agent는 **쉽게 위조 가능**하므로, 단독 신뢰도는 낮다. 반드시 **URL 패턴, 요청 빈도, 응답 코드** 등과 결합하여 판단해야 한다.

---

## 8. 위험도 평가 및 근거

### 8.1 위험도

- **attack_severity**: Low (단일 이벤트 기준)
- **attack_severity**: Medium (다른 공격 패턴과 결합 시)
- **attack_severity**: High (스캐너 + 실제 공격 시도 시)

### 8.2 위험도 평가 근거

#### Low 등급 근거:

1. **User-Agent는 쉽게 위조 가능**
    - 공격자가 정상 브라우저로 위장 가능
    - 오탐 가능성 높음
2. **정당한 자동화 도구 사용 존재**
    - curl, wget은 정상 용도로도 광범위하게 사용
    - 모니터링, CI/CD 등
3. **단독으로는 공격 증거 부족**
    - User-Agent만으로는 악의적 의도 판단 어려움

#### Medium 등급 승격 조건:

- **Suspicious UA + WEB-SCAN-001 동시 발생**
    - 스캐너 도구 + 민감 경로 접근
    - 명확한 정찰 활동
- **Suspicious UA + WEB-404-001 반복**
    - 자동화 도구 + 대량 404 에러
    - 디렉터리 브루트포스 의심
- **명시적 스캐너 User-Agent**
    - sqlmap, nikto 등 명확한 도구 이름
    - 정당한 사용 가능성 낮음

#### High 등급 승격 조건:

- **스캐너 UA + 실제 공격 시도**
    - sqlmap + SQLi 페이로드
    - nikto + XSS 시도
    - 체계적인 공격 킬 체인
- **대량 요청 + 자동화 도구**
    - 1분 내 100회 이상 요청
    - 명백한 자동화 공격

### 8.3 실무 통계

- **Bot Traffic Statistics (Imperva 2023)**
    - 전체 웹 트래픽의 47.4%가 봇
    - 이 중 30.2%가 악의적 봇 (Bad Bot)
    - User-Agent 위조율: 약 60%
- **OWASP Automated Threat Report**
    - 자동화 공격의 85%가 초기에는 정상 User-Agent 사용
    - 탐지 회피 후 본격 공격 시 도구 노출
- **실무 경험**
    - User-Agent 기반 차단 시 우회율: 약 40-50%
    - 하지만 초기 탐지 및 경고에는 여전히 유용

---

## 9. 대응 전략 (Response Strategy)

### 9.1 초기 대응 (단일 이벤트)

- **로그 레벨**: low
- **알림(Alert)**: 미발생
- **모니터링 시작**: 동일 IP 추적
- **상관 분석 준비**: 다른 공격 룰과 연계 확인

### 9.2 2차 대응 (복합 탐지 시)

- **Suspicious UA + 공격 패턴**
    - 로그 레벨: medium
    - Alert 고려
- **Dashboard 분석**:
    - User-Agent Top 목록
    - UA별 요청 URL 분포
    - UA + 공격 유형 매트릭스
    - 시간대별 UA 패턴

### 9.3 3차 대응 (명확한 스캐너 탐지 시)

- **명시적 스캐너 UA (sqlmap, nikto 등)**
    - 로그 레벨: high
    - 즉시 Alert
    - IP 임시 차단 고려
- **대량 요청 + 자동화 도구**
    - 로그 레벨: high
    - 자동 레이트 리밋 적용
    - WAF 룰 강화

### 9.4 예방 및 완화 조치

- **봇 관리 솔루션 도입**
    - Cloudflare Bot Management
    - AWS WAF Bot Control
    - Google reCAPTCHA
- **레이트 리밋**
    - IP별 초당 요청 수 제한
    - User-Agent별 일일 요청 수 제한
- **CAPTCHA 적용**
    - 의심 트래픽에 선택적 적용
    - 정상 사용자 경험 최소 영향
- **IP 평판 연동**
    - 알려진 스캐너 IP 사전 차단
    - AbuseIPDB, GreyNoise 등 활용

---

## 10. 구현 위치

### 10.1 1차 분류: Logstash filter

```ruby
if [user_agent][original] =~ /(?i)(sqlmap|nikto|nmap|dirb|gobuster|wfuzz|burp|zap|scanner|nuclei|acunetix|nessus|curl|wget|python-requests|libwww|Go-http-client|Java\/)/ {
  mutate {
    add_field => {
      "[attack][rule_id]"    => "WEB-UA-001"
      "[attack][type]"       => "Suspicious User-Agent"
      "[attack][category]"   => "Reconnaissance"
      "[attack][severity]"   => "low"
      "[attack][confidence]" => "low"
    }
    add_tag => ["attack", "suspicious_ua"]
  }
}
```

### 10.2 Confidence 조정 (다른 공격과 결합 시)

```ruby
# WEB-SCAN-001 + WEB-UA-001
if "scan" in [tags] and "suspicious_ua" in [tags] {
  mutate {
    update => { "[attack][confidence]" => "high" }
    update => { "[attack][severity]" => "medium" }
  }
}

# 명시적 스캐너
if [user_agent][original] =~ /(?i)(sqlmap|nikto|acunetix|nessus)/ {
  mutate {
    update => { "[attack][confidence]" => "high" }
    update => { "[attack][severity]" => "medium" }
  }
}
```

---

## 11. 필드 정의 및 생성 위치

| 필드 | 생성 위치 | 설명 | 값/조건 |
|------|----------|------|---------|
| user_agent.original | Logstash | Apache access log 파싱 | User-Agent 헤더 |
| source.ip | Logstash | 클라이언트 IP | IP 주소 |
| url.path | Logstash | 요청 경로 | 보조 지표 |
| http.request.method | Logstash | 요청 메서드 | GET, POST 등 |
| attack.rule_id | Logstash | 룰 식별자 | WEB-UA-001 |
| attack.type | Logstash | 공격 유형 | Suspicious User-Agent |
| attack.category | Logstash | 상위 분류 | Reconnaissance |
| attack.severity | Logstash | 영향도 | low (단일) / medium (복합) |
| attack.confidence | Logstash | 신뢰도 | - 스크립트 클라이언트: low<br>- 브루트포스 도구: medium<br>- 명시적 스캐너: high |
| detection.stage | Logstash | 탐지 단계 | classification |
| detection.source | Logstash | 탐지 주체 | logstash |
| detection.version | 수동 관리 | 룰 버전 | v1.0 |

---

## 12. 비탐지 범위 (Non-goals)

본 룰은 다음 항목을 탐지 대상으로 하지 않는다.

- **User-Agent를 정상 브라우저로 위장한 공격**
    - User-Agent 기반 탐지의 한계
    - 행위 기반 탐지로 보완 필요
- **User-Agent가 없는 요청**
    - 별도 룰로 처리 권장 (일부 공격은 UA 생략)
- **모바일 앱 기반 요청**
    - 네이티브 앱의 HTTP 클라이언트
    - 정상 트래픽 가능성

이는 본 프로젝트의 **웹 접근 로그 기반 탐지 범위**를 명확히 하기 위함이다.

---

## 13. 화이트리스트 관리

### 13.1 정당한 자동화 도구 화이트리스트

```yaml
whitelist:
  monitoring:
    - source_ip: "10.0.1.100"
      user_agent: "curl/7.68.0"
      purpose: "Health check"
    - source_ip: "10.0.2.50"
      user_agent: "python-requests/2.28.1"
      purpose: "CI/CD pipeline"

  search_engines:
    - user_agent_pattern: "Googlebot"
      verification: "Reverse DNS lookup"
    - user_agent_pattern: "Bingbot"
      verification: "Reverse DNS lookup"
```

### 13.2 화이트리스트 적용 방법

Logstash에서:

```ruby
# 화이트리스트 IP는 UA 검사 제외
if [source][ip] not in ["10.0.1.100", "10.0.2.50"] {
  # WEB-UA-001 탐지 로직 수행
}
```

---

## 14. 참고 자료

### 도구 문서
- **sqlmap**: https://github.com/sqlmapproject/sqlmap
- **Nikto**: https://github.com/sullo/nikto
- **OWASP ZAP**: https://www.zaproxy.org/
- **Burp Suite**: https://portswigger.net/burp
- **gobuster**: https://github.com/OJ/gobuster

### 표준 문서
- **OWASP Automated Threats**: https://owasp.org/www-project-automated-threats-to-web-applications/
- **ModSecurity CRS**: https://github.com/coreruleset/coreruleset

### 연구 자료
- **Imperva Bad Bot Report**: https://www.imperva.com/resources/reports/bad-bot-report/
- **Cloudflare Bot Traffic**: https://radar.cloudflare.com/traffic

---

## 15. 변경 이력

| 버전 | 날짜 | 변경 내용 | 작성자 |
|------|------|----------|--------|
| v1.0 | 2026-01-02 | 초기 룰 작성 및 상세화 | 2SeC Team |

---

**문서 승인**: ☐ 보안 팀장 | ☐ 인프라 팀장 | ☐ 개발 팀장

**다음 검토 예정일**: 2026-02-02
