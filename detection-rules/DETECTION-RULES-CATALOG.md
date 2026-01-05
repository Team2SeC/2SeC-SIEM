# 2SeC SIEM Detection Rules Catalog

**버전**: v1.0
**최종 업데이트**: 2026-01-02
**관리 팀**: 2SeC Security Team

---

## 목차

1. [개요](#개요)
2. [탐지 룰 전체 목록](#탐지-룰-전체-목록)
3. [카테고리별 룰 분류](#카테고리별-룰-분류)
4. [심각도별 룰 분류](#심각도별-룰-분류)
5. [탐지 단계별 룰 분류](#탐지-단계별-룰-분류)
6. [Security Analytics 적용](#security-analytics-적용)
7. [배포 방법](#배포-방법)
8. [필드 매핑 테이블](#필드-매핑-테이블)
9. [임계치 표준화](#임계치-표준화)
10. [룰 상호 연계](#룰-상호-연계)
11. [운영 가이드](#운영-가이드)
12. [변경 이력](#변경-이력)

---

## 개요

본 문서는 2SeC SIEM 프로젝트의 **모든 탐지 룰을 통합 관리**하기 위한 마스터 카탈로그이다.

### 목적

- **탐지 룰 전체 현황 파악**: 어떤 공격을 탐지하고 있는지 한눈에 확인
- **운영 효율성 향상**: 룰 추가/수정/삭제 시 영향도 분석
- **탐지 체계 일관성 유지**: 명명 규칙, 필드 표준, 임계치 통일
- **문서와 구현 동기화**: 문서 ↔ Logstash ↔ OpenSearch 일관성 보장

### 탐지 체계 개요

```
┌─────────────────────────────────────────────────────────────┐
│                   Apache Access Log                          │
│              (CloudWatch → Kinesis → Logstash)               │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│   Level 1: Classification (OpenSearch Ingest Pipeline)       │
│                                                               │
│  • 단일 이벤트 기준 공격 유형 분류                                │
│  • attack_rule_id, attack_type, attack_category 태깅          │
│  • attack_severity, attack_confidence 설정                    │
│  • 알림 미발생 (Observation 단계)                              │
│                                                               │
│  📋 9개 룰: WEB-SQLI-001, WEB-XSS-001, WEB-CMD-001,         │
│            WEB-PATH-001, WEB-SCAN-001, WEB-UA-001,          │
│            WEB-404-001, WEB-AUTH-001, WEB-TIMEOUT-001       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    OpenSearch                                │
│            (Index: 2sec-siem-YYYY.MM.DD)                     │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│      Level 2: Behavior Detection (OpenSearch Queries)        │
│                                                               │
│  • 시간창 + 임계치 기반 행위 탐지                                 │
│  • 동일 IP 반복 시도, 복합 공격 패턴 탐지                         │
│  • Event 승격 및 Alert 생성                                   │
│                                                               │
│  📋 9개 행위 탐지 룰 + 1개 복합 공격 룰                          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│             Level 3: Alert & Response                        │
│                                                               │
│  • Dashboard 시각화                                           │
│  • 알림 전송 (Slack, Email 등)                                │
│  • 자동 대응 (IP 차단, WAF 룰 적용 등)                          │
│  • 침해 사고 대응 절차 시작                                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 탐지 룰 전체 목록

| Rule ID | 공격 유형 | 카테고리 | Severity | Level 1 | Level 2 | 상세 문서 |
|---------|----------|---------|----------|---------|---------|----------|
| **WEB-SQLI-001** | SQL Injection | Injection | Medium | ✅ | ✅ | [상세](./docs/WEB-SQLI-001.md) |
| **WEB-XSS-001** | Cross-Site Scripting | Client-Side | Medium | ✅ | ✅ | [상세](./docs/WEB-XSS-001-enhanced.md) |
| **WEB-CMD-001** | Command Injection | Injection | High | ✅ | ✅ | [상세](./docs/WEB-CMD-001-enhanced.md) |
| **WEB-PATH-001** | Path Traversal / LFI | File Access | Medium | ✅ | ✅ | [상세](./docs/WEB-PATH-001.md) |
| **WEB-SCAN-001** | Web Scanning | Reconnaissance | Low | ✅ | ✅ | [상세](./docs/WEB-SCAN-001-enhanced.md) |
| **WEB-UA-001** | Suspicious User-Agent | Reconnaissance | Low | ✅ | - | [상세](./docs/WEB-UA-001-enhanced.md) |
| **WEB-404-001** | Repeated 404 Access | Reconnaissance | Low | ✅ | ✅ | [상세](./docs/WEB-404-001.md) |
| **WEB-AUTH-001** | Login Bruteforce | Authentication Abuse | High | ✅ | ✅ | [상세](./docs/WEB-AUTH-001-enhanced.md) |
| **WEB-TIMEOUT-001** | Slow Request / Timeout | Availability | Medium | ✅ | ✅ | [상세](./docs/WEB-TIMEOUT-001-enhanced.md) |
| **BEHAVIOR-MULTI-001** | Multi-Vector Attack | Multi-Stage | Critical | - | ✅ | [OpenSearch Query](./opensearch-behavior-detection.json) |

**전체 룰 수**:
- Level 1 (Classification): 9개
- Level 2 (Behavior): 10개 (9개 개별 + 1개 복합)

---

## 카테고리별 룰 분류

### Injection

| Rule ID | 공격 유형 | Severity | 설명 |
|---------|----------|----------|------|
| WEB-SQLI-001 | SQL Injection | Medium | SQL 예약어, 논리 연산자, DB 함수 탐지 |
| WEB-CMD-001 | Command Injection | High | OS 명령어, 명령어 체이닝 연산자 탐지 |

**방어 전략**: 입력 검증, Prepared Statements, 최소 권한 원칙

---

### Client-Side

| Rule ID | 공격 유형 | Severity | 설명 |
|---------|----------|----------|------|
| WEB-XSS-001 | Cross-Site Scripting | Medium | HTML 태그, JavaScript 이벤트 핸들러 탐지 |

**방어 전략**: Output Encoding, CSP 헤더, HTML Sanitization

---

### File Access

| Rule ID | 공격 유형 | Severity | 설명 |
|---------|----------|----------|------|
| WEB-PATH-001 | Path Traversal / LFI | Medium | 디렉터리 이동 패턴, 민감 파일명 탐지 |

**방어 전략**: 입력 검증, Whitelist, chroot jail

---

### Reconnaissance

| Rule ID | 공격 유형 | Severity | 설명 |
|---------|----------|----------|------|
| WEB-SCAN-001 | Web Scanning | Low | 민감 경로 접근, 403/404 패턴 탐지 |
| WEB-UA-001 | Suspicious User-Agent | Low | 자동화 도구, 스캐너 User-Agent 탐지 |
| WEB-404-001 | Repeated 404 Access | Low | 404 반복 발생, 디렉터리 브루트포스 탐지 |

**방어 전략**: 접근 제어, robots.txt, CAPTCHA, 레이트 리밋

---

### Authentication Abuse

| Rule ID | 공격 유형 | Severity | 설명 |
|---------|----------|----------|------|
| WEB-AUTH-001 | Login Bruteforce | High | 로그인 경로 반복 접근 탐지 |

**방어 전략**: 계정 잠금, CAPTCHA, MFA, 레이트 리밋

---

### Availability

| Rule ID | 공격 유형 | Severity | 설명 |
|---------|----------|----------|------|
| WEB-TIMEOUT-001 | Slow Request / Timeout | Medium | 408 응답 반복, Slowloris 계열 탐지 |

**방어 전략**: 타임아웃 설정, 연결 제한, WAF, CDN

---

### Multi-Stage

| Rule ID | 공격 유형 | Severity | 설명 |
|---------|----------|----------|------|
| BEHAVIOR-MULTI-001 | Multi-Vector Attack | Critical | 여러 공격 유형 동시 시도 탐지 |

**방어 전략**: 종합적 보안 통제, 자동 차단, 긴급 대응

---

## 심각도별 룰 분류

### Critical (긴급 대응 필요)

| Rule ID | 조건 |
|---------|------|
| WEB-CMD-001 | 반복 발생 또는 성공 시 |
| WEB-AUTH-001 | 반복 발생 또는 성공 시 |
| WEB-AUTH-001 | 관리자 로그인 대상 시 |
| BEHAVIOR-MULTI-001 | 항상 |

**대응**: 즉시 Alert, IP 차단, 긴급 분석, 침해 사고 대응 절차 시작

---

### High (우선 대응 필요)

| Rule ID | 조건 |
|---------|------|
| WEB-CMD-001 | 단일 이벤트 기준 |
| WEB-SQLI-001 | 반복 발생 시 |
| WEB-XSS-001 | 반복 발생 시 |
| WEB-PATH-001 | 반복 발생 시 |
| WEB-AUTH-001 | 단일 이벤트 기준 |
| WEB-TIMEOUT-001 | 반복 발생 시 |

**대응**: Alert 생성, Dashboard 분석, IP 차단 고려, 수동 대응

---

### Medium (모니터링 강화)

| Rule ID | 조건 |
|---------|------|
| WEB-SQLI-001 | 단일 이벤트 기준 |
| WEB-XSS-001 | 단일 이벤트 기준 |
| WEB-PATH-001 | 단일 이벤트 기준 |
| WEB-SCAN-001 | 반복 발생 시 |
| WEB-UA-001 | 명시적 스캐너 또는 복합 탐지 시 |
| WEB-404-001 | 반복 발생 시 |
| WEB-TIMEOUT-001 | 단일 이벤트 기준 |

**대응**: 로그 기록, 모니터링 강화, 패턴 분석

---

### Low (정보 수집)

| Rule ID | 조건 |
|---------|------|
| WEB-SCAN-001 | 단일 이벤트 기준 |
| WEB-UA-001 | 단일 이벤트 기준 |
| WEB-404-001 | 단일 이벤트 기준 |

**대응**: 로그 기록, 추적 시작

---

## 탐지 단계별 룰 분류

### Level 1: Classification (Security Analytics - Sigma)

**목적**: 단일 이벤트 기준 공격 유형 분류

| Rule ID | 탐지 기준 | 출력 |
|---------|----------|------|
| WEB-SQLI-001 | URL query에 SQL 패턴 | Security Analytics Alert |
| WEB-XSS-001 | URL query에 XSS 패턴 | Security Analytics Alert |
| WEB-CMD-001 | URL query에 CMD 패턴 | Security Analytics Alert |
| WEB-PATH-001 | URL path/query에 경로 이동 패턴 | Security Analytics Alert |
| WEB-SCAN-001 | 민감 경로 + 403/404 | Security Analytics Alert |
| WEB-UA-001 | Suspicious User-Agent | Security Analytics Alert |
| WEB-404-001 | 404 응답 | Security Analytics Alert |
| WEB-AUTH-001 | 로그인 경로 + POST | Security Analytics Alert |
| WEB-TIMEOUT-001 | 408 응답 | Security Analytics Alert |

**구현 위치**: `detection-rules/sigma/`  
**Log Type**: Apache Access  
**참고**: OpenSearch Ingest Pipeline은 정규화만 수행

---

### Level 2: Behavior Detection (OpenSearch)

**목적**: 시간창 + 임계치 기반 행위 탐지, Event 승격

| Rule ID | 탐지 기준 | 임계치 | Alert |
|---------|----------|--------|-------|
| BEHAVIOR-SQLI-001 | 동일 IP 반복 SQLi | 1분 10회 | High |
| BEHAVIOR-XSS-001 | 동일 IP 반복 XSS | 1분 10회 | High |
| BEHAVIOR-CMD-001 | 동일 IP 반복 CMDi | 1분 10회 | Critical |
| BEHAVIOR-PATH-001 | 동일 IP 반복 Path Traversal | 1분 10회 | High |
| BEHAVIOR-SCAN-001 | 동일 IP 반복 스캔 | 1분 30회 | Medium |
| BEHAVIOR-404-001 | 동일 IP 반복 404 | 1분 30회 | Medium |
| BEHAVIOR-AUTH-001 | 동일 IP 반복 로그인 | 1분 5회 | Critical |
| BEHAVIOR-TIMEOUT-001 | 동일 IP 반복 408 | 5분 20회 | High |
| BEHAVIOR-MULTI-001 | 복합 공격 (3개 이상 유형) | 5분 내 3개 유형 | Critical |

**구현 위치**:  
`detection-rules/opensearch-behavior-detection.json` (attack.* 기반)  
`detection-rules/opensearch-behavior-detection-raw.json` (raw 필드 기반)

---

## 배포 방법

### 1) OpenSearch Ingest Pipeline

- 파일: `detection-rules/opensearch-ingest-classification-pipeline.json`
- Pipeline ID: `2sec-siem-classification-v1`
- 역할: 정규화만 수행 (탐지는 Security Analytics에서 처리)

### 2) Index Template

- 파일: `detection-rules/opensearch-index-template.json`
- Template ID: `2sec-siem-template-v1`

### 3) Alerting Monitors (behavior 기반)

- 파일: `detection-rules/monitors/*.json`
- API: `POST /_plugins/_alerting/monitors`

### 4) Sigma 룰 Import

- 위치: `detection-rules/sigma/`
- 적용: Security Analytics > Rules > Import Rules
- Log Type: Apache Access

### 5) 배포 스크립트

- 실행: `detection-rules/scripts/apply-opensearch-assets.sh`
- 환경 변수: `OPENSEARCH_URL` 필수  
  선택: `OPENSEARCH_USER`, `OPENSEARCH_PASS` 또는 `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`

---

## 필드 매핑 테이블

### 공통 필드 (모든 룰)

| 필드명 | 생성 위치 | 타입 | 설명 | 예시 값 |
|--------|----------|------|------|---------|
| `@timestamp` | Logstash | date | 이벤트 발생 시각 | `2026-01-02T10:30:15.000Z` |
| `source.ip` | Logstash | ip | 클라이언트 IP | `192.168.1.100` |
| `url.original` | Logstash | keyword | 전체 요청 URL | `/login.php?user=admin` |
| `url.path` | Logstash | keyword | 요청 경로 | `/login.php` |
| `url.query` | Logstash | text | 쿼리 스트링 | `user=admin&pass=test` |
| `http.request.method` | Logstash | keyword | HTTP 메서드 | `GET`, `POST` |
| `http.response.status_code` | Logstash | keyword | HTTP 응답 코드 | `200`, `404`, `408` |
| `user_agent.original` | Logstash | text | User-Agent 헤더 | `Mozilla/5.0 ...` |

---

### 탐지 결과 필드

| 필드명 | 생성 위치 | 타입 | 설명 | 예시 값 |
|--------|----------|------|------|---------|
| `attack.rule_id` | OpenSearch Ingest | keyword | 탐지 룰 ID | `WEB-SQLI-001` |
| `attack.type` | OpenSearch Ingest | keyword | 공격 유형 | `SQL Injection` |
| `attack.category` | OpenSearch Ingest | keyword | 공격 카테고리 | `Injection` |
| `attack.severity` | OpenSearch Ingest | keyword | 심각도 | `low`, `medium`, `high`, `critical` |
| `attack.confidence` | OpenSearch | keyword | 신뢰도 | `low`, `medium`, `high` |
| `detection.stage` | OpenSearch | keyword | 탐지 단계 | `classification`, `detection` |
| `detection.source` | OpenSearch | keyword | 탐지 주체 | `opensearch`, `query` |
| `detection.version` | 수동 관리 | keyword | 룰 버전 | `v1.0` |

---

### 태그 (Tags)

| 태그명 | 의미 | 관련 룰 |
|--------|------|---------|
| `attack` | 공격 의심 이벤트 | 모든 룰 |
| `sqli` | SQL Injection | WEB-SQLI-001 |
| `xss` | Cross-Site Scripting | WEB-XSS-001 |
| `cmdi` | Command Injection | WEB-CMD-001 |
| `path_traversal` | Path Traversal | WEB-PATH-001 |
| `scan` | Web Scanning | WEB-SCAN-001 |
| `suspicious_ua` | Suspicious User-Agent | WEB-UA-001 |
| `repeated_404` | Repeated 404 | WEB-404-001 |
| `auth_bruteforce` | Authentication Bruteforce | WEB-AUTH-001 |
| `timeout` | Request Timeout | WEB-TIMEOUT-001 |

---

## 임계치 표준화

### Level 2 탐지 임계치

| 공격 카테고리 | 시간창 | 임계치 | 근거 |
|--------------|--------|--------|------|
| **Injection** (SQLi, XSS, Path, CMD) | 1분 | 10회 | 자동화 도구 일반적 속도, 정상 사용자와 명확히 구분 |
| **Reconnaissance** (Scan, 404, UA) | 1분 | 30회 | 스캐너 특성상 빠른 탐색, 오탐 최소화 위해 높은 임계치 |
| **Authentication** (Login BF) | 1분 | 5회 | 계정 보호 최우선, 낮은 임계치로 조기 탐지 |
| **Availability** (Timeout) | 5분 | 20회 | Slow Request 특성상 긴 시간창, 네트워크 불안정 고려 |
| **Multi-Vector** | 5분 | 3개 유형 | 복합 공격은 심각도 높음, 즉시 탐지 |

### 임계치 조정 가이드

**임계치를 낮춰야 하는 경우**:
- 실제 공격 사례 발생 (미탐 방지)
- 고위험 자산 보호 (관리자 페이지 등)
- 정상 트래픽이 적은 환경

**임계치를 높여야 하는 경우**:
- 오탐률이 높은 경우
- 정상 사용 패턴이 공격과 유사한 경우
- 트래픽이 많은 환경

**변경 시 필수 절차**:
1. 변경 사유 문서화
2. 테스트 환경에서 검증
3. 점진적 적용 (1주일 모니터링)
4. 오탐/미탐 데이터 수집
5. 최종 승인 및 적용
6. 변경 이력 기록

---

## 룰 상호 연계

### Confidence 상승 패턴

```ruby
# WEB-SCAN-001 + WEB-UA-001
if "scan" in [tags] and "suspicious_ua" in [tags] {
  # Confidence: low → high
  # 명확한 스캐너 활동
}

# SQLi/XSS/CMDi + URL 인코딩
if [url][query] =~ /%[0-9a-fA-F]{2}/ and "attack" in [tags] {
  # Confidence: medium → high
  # 우회 시도 의도 명확
}

# 복수 공격 패턴
if attack_tags.length >= 2 {
  # Confidence: → high
  # 체계적 공격
}
```

### Severity 상승 패턴

```ruby
# 관리자 로그인 대상 브루트포스
if "auth_bruteforce" in [tags] and [url][path] =~ /\/admin/ {
  # Severity: high → critical
}

# 명시적 스캐너 User-Agent
if [user_agent][original] =~ /sqlmap|nikto/ {
  # Severity: low → medium
}
```

### Alert 트리거 패턴

| 패턴 | 조건 | Alert Level | 자동 대응 |
|------|------|-------------|----------|
| 단일 Critical 룰 | WEB-CMD-001 단일 탐지 | High | 모니터링 강화 |
| 반복 High 룰 | WEB-AUTH-001 1분 5회 | Critical | IP 차단 (15분) |
| 복합 공격 | 3개 이상 공격 유형 | Critical | IP 차단 (24시간) + Escalate |
| 대규모 DDoS | 전체 408 급증 | Critical | DDoS 방어 모드 |

---

## 운영 가이드

### 일일 운영

- **오전 점검** (10:00)
    - 전날 Alert 현황 리뷰
    - 오탐 사례 수집
    - 차단 IP 목록 검토
- **실시간 모니터링**
    - Dashboard 확인 (1시간마다)
    - Critical Alert 즉시 대응
- **오후 리포트** (17:00)
    - 일일 공격 통계 정리
    - Top 공격 IP 분석
    - 룰 성능 확인

### 주간 운영

- **월요일**: 주간 보안 리뷰 회의
- **수요일**: 오탐 사례 분석 및 룰 조정
- **금요일**: 주간 리포트 작성

### 월간 운영

- **룰 효과성 평가**
    - 탐지율 / 오탐률 계산
    - 미탐 사례 분석
- **임계치 튜닝**
    - 통계 데이터 기반 조정
- **룰 버전 업그레이드**
    - 새로운 공격 패턴 추가
    - 성능 최적화

### 긴급 상황 대응

1. **Alert 수신** → Slack/Email 알림
2. **초기 분석** (5분 이내)
    - 공격 유형 확인
    - 영향 범위 파악
3. **즉시 대응** (10분 이내)
    - IP 차단
    - WAF 룰 강화
4. **상세 분석** (30분 이내)
    - 공격자 프로파일링
    - 취약점 확인
5. **복구 및 보고** (1시간 이내)
    - 서비스 정상화
    - 침해 사고 보고서 작성

---

## 변경 이력

| 버전 | 날짜 | 변경 내용 | 작성자 |
|------|------|----------|--------|
| v1.0 | 2026-01-02 | 초기 카탈로그 작성<br>- 9개 Level 1 룰<br>- 10개 Level 2 룰<br>- 필드 매핑 테이블<br>- 임계치 표준화 | 2SeC Team |

---

## 다음 단계

### Phase 2 (2026 Q1)
- [ ] Windows 명령어 패턴 확장 (WEB-CMD-001)
- [ ] Blind Injection 탐지 (시간 기반)
- [ ] 계정명 파싱 및 계정별 탐지
- [ ] IP 평판 데이터 연동

### Phase 3 (2026 Q2)
- [ ] 머신러닝 기반 이상 탐지
- [ ] 자동화된 룰 튜닝 시스템
- [ ] SOAR 연동 (자동 대응 강화)

---

**문서 관리자**: 2SeC Security Team
**문의**: security@2sec.team
**최종 검토**: 2026-01-02
