# WEB-TIMEOUT-001: Slow Request / Timeout Attack Detection Rule

## 1. 탐지 룰 개요

- **Rule ID**: WEB-TIMEOUT-001
- **공격 유형**: Slow Request / Request Timeout / Slowloris-style DoS
- **공격 분류**: Availability
- **로그 소스**: DVWA Apache access log
- **적용 단계**: Logstash (Classification / Enrichment)

---

## 2. 위협 시나리오 (Threat Scenario)

### 2.1 위협 개요

Slow Request 공격은 HTTP 요청을 의도적으로 느리게 전송하거나, 요청을 완성하지 않은 채 연결을 유지하여 **웹 서버의 연결 리소스를 고갈**시키는 서비스 거부(DoS/DDoS) 공격이다.

본 룰은 다음과 같은 시나리오를 탐지하기 위해 설계되었다.

- **Slowloris 공격**
    - 다수의 HTTP 요청을 시작하되 완성하지 않음
    - 헤더를 천천히 전송하여 연결 유지
    - 서버의 동시 연결 한도 소진
- **Slow POST (R-U-Dead-Yet)**
    - POST 요청의 body를 매우 느리게 전송
    - `Content-Length`는 크지만 실제 데이터는 느리게 전송
    - 서버 연결 및 메모리 리소스 고갈
- **Slow Read 공격**
    - 서버 응답을 매우 느리게 읽음
    - TCP window size를 작게 설정
    - 서버가 응답 완료를 기다리며 리소스 점유
- **Request Timeout 악용**
    - 정상적인 요청이지만 서버 타임아웃 설정 악용
    - 대량의 타임아웃 유발로 로그 및 모니터링 시스템 부하

### 2.2 보호 대상 자산과 영향

| 자산 | 영향 |
|------|------|
| 웹 서버 | Connection pool exhaustion |
| 서버 리소스 | CPU, Memory, Network bandwidth |
| 서비스 가용성 | Denial of Service |
| 정상 사용자 | Service degradation or unavailability |

---

## 3. 관측 신호 (Observable Signals)

### 3.1 로그 기반 관측 가능 지점

본 공격 시나리오는 **Apache access log**에서 다음 신호로 관측 가능하다.

- HTTP 응답 코드 **408 (Request Timeout)**
- 요청 라인이 비정상적이거나 불완전 (`"-"` 또는 빈 값)
- 짧은 시간 내 동일 IP에서 반복적인 408 발생
- 특정 HTTP 메서드(GET, POST, HEAD)

### 3.2 주요 관측 필드

| 필드 | 설명 |
|------|------|
| http.response.status_code | HTTP 응답 코드 (408) |
| source.ip | 공격 주체 IP |
| http.request.method | 요청 메서드 (GET, POST, HEAD) |
| url.original | 요청 URL (비정상 패턴 확인) |
| http.response.body.bytes | 응답 크기 (보통 작음) |

---

## 4. 탐지 근거 (Detection Rationale)

본 탐지 룰은 **실무 경험 + 공격 도구 분석 + 프로젝트 실험**을 종합하여 정의되었다.

### 4.1 표준 및 권장 사항

#### OWASP Top 10

- **A05:2021 – Security Misconfiguration**

부적절한 서버 설정(타임아웃 설정, 연결 제한 등)은 Slow Request 공격에 취약하게 만든다.

#### MITRE ATT&CK

- https://attack.mitre.org/
- **T1499: Endpoint Denial of Service**
    - T1499.001: OS Exhaustion Flood
    - T1499.002: Service Exhaustion Flood

MITRE ATT&CK에서 Slow Request는 **Service Exhaustion Flood**의 한 형태로 분류된다.

#### OWASP Denial of Service Cheat Sheet

- https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

Slow Request 공격 방어 권장 사항:

- 타임아웃 설정 최적화
- 연결 제한 설정
- 요청 속도 모니터링
- 로드 밸런서 및 WAF 활용

### 4.2 공격 도구 분석

#### Slowloris

- **도구**: https://github.com/gkbrk/slowloris
- **원리**:
    - 다수의 HTTP 요청 시작
    - 헤더를 천천히 전송 (`X-a: b\r\n` 반복)
    - 연결을 장시간 유지
    - 서버의 최대 동시 연결 수 도달 시 정상 요청 차단

**Apache 로그 패턴**:
```
- - - [02/Jan/2026:10:15:30 +0000] "-" 408 - "-" "-"
```

- 요청 라인이 `"-"` (불완전한 요청)
- 408 응답
- User-Agent 없음 또는 사용자 정의

#### PyLoris (Python Slowloris)

```bash
python pyloris.py -t http://dvwa.example.com -c 500 -w 100
```

- `-c 500`: 500개 연결 생성
- `-w 100`: 헤더 전송 간격 100초

관측 패턴:
- 초당 수십~수백 개의 408 응답
- 동일 IP에서 반복 발생
- 요청 라인 불완전

#### SlowHTTPTest

- **도구**: https://github.com/shekyan/slowhttptest
- **기능**:
    - Slowloris
    - Slow POST
    - Slow Read
    - Range Header attack

```bash
slowhttptest -c 1000 -H -g -o slowloris_stats -i 10 -r 200 -t GET -u http://dvwa.example.com
```

관측 패턴:
- 대량 408 응답
- 연결 수 급증
- 서버 응답 지연

### 4.3 프로젝트 실험 근거

#### Slowloris 공격 실험

```bash
python slowloris.py -s 500 dvwa.example.com
```

**관측된 로그**:
```
192.168.1.100 - - [02/Jan/2026:10:20:15 +0000] "-" 408 - "-" "slowloris/0.1"
192.168.1.100 - - [02/Jan/2026:10:20:16 +0000] "-" 408 - "-" "slowloris/0.1"
192.168.1.100 - - [02/Jan/2026:10:20:17 +0000] "-" 408 - "-" "slowloris/0.1"
...
```

**특징**:
- 초당 10-50개 408 응답
- 5분 내 수백~수천 개 408 발생
- 동일 IP 반복
- User-Agent: `slowloris/0.1`

#### Slow POST 실험

```bash
slowhttptest -c 1000 -B -g -o slow_post_stats -i 10 -r 200 -t POST -u http://dvwa.example.com/login.php
```

**관측된 패턴**:
- POST 요청 시작
- Content-Length 헤더는 큼 (예: 100000 bytes)
- 실제 body 전송은 매우 느림 (1 byte/10초)
- 서버 타임아웃 도달 시 408 또는 500 응답

#### 정상 사용자 vs 공격 비교

| 특징 | 정상 사용자 | Slow Request 공격 |
|------|------------|------------------|
| 408 발생 빈도 | 매우 드물음 (네트워크 불안정 시) | 대량 반복 발생 |
| 요청 완성도 | 정상적인 HTTP 요청 | 불완전하거나 의도적으로 느림 |
| 동일 IP 반복 | 거의 없음 | 짧은 시간 내 수십~수백 회 |
| User-Agent | 정상 브라우저 | 도구 식별자 또는 없음 |
| 후속 행동 | 재시도 또는 포기 | 지속적인 새 연결 시도 |

**결론**: 짧은 시간 내 동일 IP에서 반복적인 408 응답은 **Slow Request 공격의 명확한 지표**이다.

### 4.4 통계 및 침해 사례

#### 실제 공격 사례

1. **Slowloris 공격 (2009)**
    - 이란 정부 웹사이트 대상 공격
    - 단일 PC로 서버 마비
    - Apache 기본 설정 취약점 악용
2. **R-U-Dead-Yet (2010)**
    - POST 기반 Slow 공격
    - 전자상거래 사이트 다수 피해
3. **Cloudflare 보고서 (2022)**
    - Layer 7 DDoS 공격의 15%가 Slow Request 계열
    - HTTP/2 환경에서도 여전히 유효

#### 통계 데이터

- **Cloudflare DDoS Report (2023)**
    - Layer 7 공격의 18%가 Slowloris 계열
    - 평균 공격 지속 시간: 2-6시간
- **Akamai State of the Internet (2023)**
    - Slow HTTP 공격 증가 추세
    - 특히 전자상거래 및 금융 서비스 타겟
- **실무 경험**
    - 단일 공격자가 수백~수천 대의 봇넷 동원 시 대규모 피해
    - 정상 트래픽과 혼재되어 탐지 어려움

---

## 5. 탐지 조건 (Detection Conditions)

### 5.1 기본 탐지 조건

| 조건 필드 | 조건 |
|----------|------|
| http.response.status_code | 408 (Request Timeout) |
| http.request.method | GET, POST, HEAD |
| url.original | 요청 라인 비정상 (`"-"` 또는 불완전) |

### 5.2 탐지 패턴 상세 분류

#### Case 1: Slowloris 패턴

**로그 예시**:
```
192.168.1.100 - - [02/Jan/2026:10:20:15 +0000] "-" 408 - "-" "slowloris/0.1"
```

**특징**:
- 요청 라인 `"-"` (불완전)
- 408 응답
- 반복 발생
- User-Agent에 도구 이름 또는 없음

#### Case 2: Slow POST 패턴

**로그 예시**:
```
192.168.1.100 - - [02/Jan/2026:10:25:30 +0000] "POST /login.php HTTP/1.1" 408 - "-" "python-requests/2.28.1"
```

**특징**:
- POST 요청
- 408 응답
- 로그인, 업로드 등 POST가 필요한 경로 타겟
- 스크립트 기반 HTTP 클라이언트

#### Case 3: 일반 타임아웃 vs 공격 구분

| 특징 | 일반 타임아웃 | Slow Request 공격 |
|------|-------------|------------------|
| 빈도 | 산발적 | 집중적, 반복적 |
| IP 패턴 | 다양한 IP | 동일 IP 또는 소수 IP |
| 시간 패턴 | 불규칙 | 일정한 간격 |
| User-Agent | 정상 브라우저 | 도구 또는 없음 |
| 후속 요청 | 재시도 또는 없음 | 지속적인 새 연결 |

---

## 6. 탐지 로직 (Detection Logic)

HTTP 응답 코드가 **408 (Request Timeout)** 인 요청을

Slow Request 의심 이벤트로 분류한다.

**단일 이벤트 기준 분류(Classification)만 수행**하며,

실제 공격 여부 판단은 **동일 IP의 반복 횟수 및 시간 기반 탐지**에서 수행한다.

### Level 2 탐지 기준 (OpenSearch)

- **동일 IP에서 5분 내 20회 이상 408 응답**
    - Slow Request 공격 의심
    - Alert 생성
- **동일 IP에서 5분 내 50회 이상 408 응답**
    - 명확한 DoS 공격
    - 즉시 IP 차단
- **전체 408 응답 급증 (평소 대비 10배 이상)**
    - DDoS 공격 가능성
    - 긴급 대응

---

## 7. 오탐 가능성 (False Positives)

### 7.1 정상 네트워크 불안정

- **느린 네트워크 연결**
    - 모바일 네트워크, 위성 인터넷 등
    - 해결: IP 지역 및 네트워크 패턴 분석
- **클라이언트 문제**
    - 사용자 기기의 일시적 문제
    - 해결: 반복 패턴이 아니면 무시

### 7.2 프록시/로드밸런서

- **프록시 타임아웃**
    - 중간 프록시에서 타임아웃 발생
    - 해결: 프록시 IP 확인 및 설정 검토
- **로드밸런서 문제**
    - 백엔드 서버 응답 지연
    - 해결: 백엔드 서버 상태 모니터링

### 7.3 레거시 클라이언트

- **오래된 브라우저/앱**
    - HTTP/1.0 사용, Keep-Alive 미지원 등
    - 해결: User-Agent 기반 예외 처리

※ 오탐 최소화를 위해 **임계치를 보수적으로 설정**(5분 내 20회 이상)하고, **IP 평판 및 User-Agent**와 결합 분석한다.

---

## 8. 위험도 평가 및 근거

### 8.1 위험도

- **attack_severity**: Medium (단일 이벤트 기준)
- **attack_severity**: High (반복 발생 시)
- **attack_severity**: Critical (대규모 DDoS 시)

### 8.2 위험도 평가 근거

#### Medium 등급 근거:

1. **서비스 가용성 위협**
    - 성공 시 정상 사용자 접근 차단
    - 비즈니스 연속성 영향
2. **리소스 고갈**
    - 연결 풀, 메모리, CPU 등
    - 전체 서버 성능 저하
3. **탐지 및 완화 가능**
    - 적절한 설정 및 모니터링으로 방어 가능
    - 완전한 서비스 중단까지는 시간 소요

#### High 등급 승격 조건:

- **동일 IP에서 5분 내 20회 이상 408**
    - 체계적인 공격
    - 서비스 영향 가능성
- **다수 IP에서 동시 발생**
    - DDoS 공격 가능성
    - 대규모 리소스 소진
- **실제 서비스 지연 발생**
    - 정상 사용자 불편 호소
    - 비즈니스 영향 시작

#### Critical 등급 승격 조건:

- **전체 408 응답 급증 (평소 대비 10배 이상)**
    - 대규모 DDoS 공격
    - 긴급 대응 필요
- **서비스 완전 중단**
    - 정상 요청 처리 불가
    - 비즈니스 중단

### 8.3 통계적 근거

- **Cloudflare DDoS Report (2023)**
    - Layer 7 DDoS 공격의 18%가 Slow Request 계열
    - 평균 공격 지속 시간: 2-6시간
- **Akamai (2023)**
    - Slow HTTP 공격으로 인한 평균 다운타임: 3-8시간
    - 평균 복구 비용: $100K-$300K
- **Gartner**
    - 시간당 다운타임 비용: $300K (대형 전자상거래)
    - 평판 손상 및 고객 이탈

---

## 9. 대응 전략 (Response Strategy)

### 9.1 초기 대응 (단일 이벤트)

- **로그 레벨**: low
- **알림(Alert)**: 미발생
- **모니터링 시작**: 동일 IP 추적

### 9.2 2차 대응 (반복 발생 시)

- **5분 내 20회 이상 408**
    - 로그 레벨: high
    - Alert 생성
    - Dashboard 분석:
        - Source IP별 408 발생 횟수
        - 시간대별 408 트렌드
        - User-Agent 분포
        - 요청 경로 패턴
    - 자동 대응:
        - IP 임시 차단 (30분)
        - 레이트 리밋 강화
        - 타임아웃 설정 조정

### 9.3 3차 대응 (대규모 공격 시)

- **대규모 DDoS 탐지**
    - 로그 레벨: critical
    - 긴급 Alert
    - 자동 대응:
        - DDoS 방어 모드 활성화
        - 악의적 IP 대량 차단
        - CDN/WAF 강화
    - 수동 대응:
        - ISP 연락 (upstream filtering)
        - 클라우드 Auto-Scaling
        - 긴급 패치 및 설정 변경

### 9.4 예방 및 완화 조치

#### 서버 설정 최적화

```apache
# Apache 설정
Timeout 60
KeepAliveTimeout 15
MaxKeepAliveRequests 100
RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500

# 동시 연결 제한
<IfModule mpm_worker_module>
    ServerLimit 16
    StartServers 2
    MaxRequestWorkers 150
    MinSpareThreads 25
    MaxSpareThreads 75
    ThreadsPerChild 25
</IfModule>
```

#### Nginx 설정

```nginx
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 5s 5s;
send_timeout 10s;

limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
limit_req zone=req_limit burst=20;
```

#### 네트워크 레벨 방어

- **방화벽 룰**
    - 동일 IP 연결 수 제한
    - SYN flood 방어
- **로드 밸런서**
    - 타임아웃 설정
    - 연결 제한
- **WAF 활용**
    - Cloudflare, AWS WAF 등
    - Slow Request 자동 탐지 및 차단

#### 모니터링 및 알림

- **실시간 모니터링**
    - 408 응답 수 추적
    - 동시 연결 수 추적
    - 서버 리소스 사용률
- **자동 알림**
    - 임계치 초과 시 Alert
    - 대시보드 시각화

---

## 10. 구현 위치

### 10.1 1차 분류: Logstash filter

```ruby
if [http][response][status_code] == "408" {
  mutate {
    add_field => {
      "[attack][rule_id]"    => "WEB-TIMEOUT-001"
      "[attack][type]"       => "Slow Request"
      "[attack][category]"   => "Availability"
      "[attack][severity]"   => "medium"
      "[attack][confidence]" => "low"
    }
    add_tag => ["attack", "timeout"]
  }
}
```

### 10.2 2차 탐지: OpenSearch 집계

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "attack.rule_id": "WEB-TIMEOUT-001" } }
      ],
      "filter": [
        { "range": { "@timestamp": { "gte": "now-5m" } } }
      ]
    }
  },
  "aggs": {
    "by_source_ip": {
      "terms": {
        "field": "source.ip",
        "min_doc_count": 20
      }
    }
  }
}
```

### 10.3 전체 408 급증 탐지

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "http.response.status_code": "408" } }
      ],
      "filter": [
        { "range": { "@timestamp": { "gte": "now-5m" } } }
      ]
    }
  },
  "aggs": {
    "total_408": {
      "value_count": {
        "field": "http.response.status_code"
      }
    }
  }
}
```

---

## 11. 필드 정의 및 생성 위치

| 필드 | 생성 위치 | 설명 | 값/조건 |
|------|----------|------|---------|
| http.response.status_code | Logstash | HTTP 응답 코드 | 408 |
| source.ip | Logstash | 클라이언트 IP | IP 주소 |
| http.request.method | Logstash | 요청 메서드 | GET, POST, HEAD |
| url.original | Logstash | 요청 URL | 비정상 패턴 확인 |
| attack.rule_id | Logstash | 룰 식별자 | WEB-TIMEOUT-001 |
| attack.type | Logstash | 공격 유형 | Slow Request |
| attack.category | Logstash | 상위 분류 | Availability |
| attack.severity | Logstash | 영향도 | medium (단일) / high (반복) |
| attack.confidence | Logstash / OpenSearch | 신뢰도 | - 단일: low<br>- 10-19회 반복: medium<br>- 20회 이상: high |
| detection.stage | Logstash | 탐지 단계 | classification |
| detection.source | Logstash | 탐지 주체 | logstash |
| detection.version | 수동 관리 | 룰 버전 | v1.0 |

---

## 12. 비탐지 범위 (Non-goals)

본 룰은 다음 항목을 탐지 대상으로 하지 않는다.

- **네트워크 레벨 DDoS**
    - SYN flood, UDP flood 등
    - 방화벽/IDS에서 탐지
- **Volumetric DDoS**
    - 대역폭 소진 공격
    - ISP/CDN 레벨 방어
- **Application-specific DoS**
    - 특정 애플리케이션 로직 악용
    - 애플리케이션 로그 분석 필요

이는 본 프로젝트의 **웹 접근 로그 기반 탐지 범위**를 명확히 하기 위함이다.

---

## 13. 확장 계획

### Phase 2
- **요청 속도 분석**
    - 헤더/body 전송 속도 계산
    - 비정상적으로 느린 요청 탐지
- **연결 지속 시간 분석**
    - 비정상적으로 긴 연결 탐지

### Phase 3
- **머신러닝 기반 탐지**
    - 정상 요청 패턴 학습
    - 이상 징후 자동 탐지
- **예측적 차단**
    - 공격 초기 단계에서 자동 차단

---

## 14. 참고 자료

### 공격 도구
- **Slowloris**: https://github.com/gkbrk/slowloris
- **SlowHTTPTest**: https://github.com/shekyan/slowhttptest
- **PyLoris**: https://sourceforge.net/projects/pyloris/

### 표준 문서
- **OWASP DoS Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
- **MITRE ATT&CK T1499**: https://attack.mitre.org/techniques/T1499/

### 방어 가이드
- **Apache Performance Tuning**: https://httpd.apache.org/docs/2.4/misc/perf-tuning.html
- **Nginx Security**: https://nginx.org/en/docs/http/ngx_http_limit_req_module.html

### 연구 자료
- **Cloudflare DDoS Report**: https://www.cloudflare.com/ddos/
- **Akamai State of the Internet**: https://www.akamai.com/resources/state-of-the-internet

---

## 15. 변경 이력

| 버전 | 날짜 | 변경 내용 | 작성자 |
|------|------|----------|--------|
| v1.0 | 2026-01-02 | 초기 룰 작성 및 상세화 | 2SeC Team |

---

**문서 승인**: ☐ 보안 팀장 | ☐ 인프라 팀장 | ☐ 개발 팀장

**다음 검토 예정일**: 2026-02-02
