# 2SeC (2 Seconds to Secure)

**IaC 기반 AWS Web Log SIEM 파이프라인 구축 프로젝트**

2SeC는 웹 공격을 신속하게 탐지·분류·알림하기 위한  
**AWS 기반 SIEM(Security Information and Event Management) 파이프라인**을  
Infrastructure as Code(IaC) 원칙에 따라 설계·구현한 프로젝트입니다.

본 프로젝트는 **kt Cloud TECH UP 사이버보안 과정**의 팀 프로젝트로 진행되었습니다.



## 👥 Team

- 황준하
- 김민지
- 이영원
- 정완우
- 허예은



## 🎯 Project Goals

- 웹 공격 로그를 **안정적·확장 가능**하게 수집 및 분석
- 수동 설정을 최소화한 **완전 자동화 SIEM 환경 구축**
- Sigma 룰 기반의 **표준화된 탐지 체계** 적용
- GitHub Actions + Terraform 기반 **운영 친화적 인프라 관리**



## 🧱 Overall Architecture

```text
DVWA (EC2)
  ↓
CloudWatch Logs
  ↓
Kinesis Data Stream
  ↓
ECS Fargate (Logstash)
  ↓
OpenSearch (SIEM Index)
  ↓
Security Analytics / Alerting
```


## 🛠 Tech Stack

### Infrastructure & Cloud
- AWS EC2, ECS (Fargate)
- CloudWatch Logs
- Kinesis Data Streams
- OpenSearch Service
- S3, DynamoDB

### IaC & Automation
- Terraform
- GitHub Actions (OIDC 기반 인증)
- AWS IAM (Least Privilege)

### SIEM & Log Processing
- Logstash
- OpenSearch Security Analytics
- Sigma Rules (YAML)


## 🔐 Security Design Highlights

### 1. Terraform Backend 보안
- S3 Remote Backend
- Server-Side Encryption (SSE)
- Public Access Block (완전 비공개)
- Versioning 활성화
- DynamoDB State Lock
- 동시성 충돌 방지
- 안전한 롤백 지원

### 2. GitHub Actions OIDC 인증
- 장기 Access Key 미사용
- token.actions.githubusercontent.com 기반 AssumeRole
- main / dev 브랜치 조건부 접근 허용
- CI Role의 자기 권한 변경 Deny (권한 상승 방지)

### 3. 최소 권한 원칙
- Logstash
- Kinesis Read
- DynamoDB Checkpoint
- OpenSearch Data Plane 최소 권한
- EC2
- SSH 제거
- SSM Session Manager 사용


## 📦 Logstash & ECS Deployment
- Logstash는 ECR 커스텀 이미지로 관리
- GitHub Actions:
- 이미지 Build & Push
- ECS Service 강제 롤링 배포 (--force-new-deployment)
- Terraform의 ignore_changes = [task_definition] 설정으로
의도치 않은 재배포 방지


## 🔍 Detection Rules
Sigma 기반 탐지 체계
- Web 공격 패턴 (SQLi, XSS, Path Traversal 등)
- OpenSearch Security Analytics와 호환
- 타 SIEM으로의 이식 용이

---

## 배포 자동화
scripts/apply-opensearch-assets.sh
- AWS SigV4 기반 IAM 인증
- 순차 배포
1.	Ingest Pipeline
2.	Index Template
3.	Alert Monitor



## 🚨 Alerting
- OpenSearch Alerting Plugin 사용
- 탐지 룰 기반 실시간 알림
- (Webhook 연동은 확장 예정)


## 🧪 Operations Runbook (요약)
“로그가 안 들어온다” 발생 시 체크 순서
1. DVWA EC2
- 서비스 접속
- 컨테이너 상태
- 로그 파일 생성 여부

2. CloudWatch Logs
- 로그 그룹 / 스트림 확인

3. Kinesis
- Subscription Filter
- Stream 유입

4. ECS (Logstash)
- Service desired count
- 컨테이너 로그

5.	OpenSearch
- 인덱스 생성 여부
- 접근 정책 확인



## 🔄 Change & Deployment Policy

### Infrastructure 변경
- 대상: infra/dev/**
- 절차:
- terraform plan → 승인 → apply
- Backend 설정 변경은 매우 위험

### Logstash 파이프라인 변경
- 대상: logstash/**
- 이미지 재빌드 후 ECS 강제 롤링 배포 필요



## 🚀 Future Work
- CTI(Cyber Threat Intelligence) 연동
- LLM 기반 로그 요약 및 분석
- 백업/복구 체계(S3 Snapshot Repository) 보완
- Webhook 알림 고도화


