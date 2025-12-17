# 2SeC-SIEM

IaC 기반 AWS 인프라 위에 웹 서비스(DVWA/Juice Shop)를 구성하고, 실전 공격·방어 시나리오를 기반으로 SIEM 환경을 구축하는 보안 실습 프로젝트입니다.
레드팀 공격과 블루팀 모니터링을 동시에 수행하며, 보안 로그의 수집·처리·저장·탐지까지 엔드투엔드로 경험하는 것을 목표로 합니다.

⸻

프로젝트 목표

본 프로젝트는 다음과 같은 결과물을 도출하는 것을 1차 목표로 합니다.
	1.	Terraform 기반 AWS 인프라 자동화 구축
	2.	웹 서비스 배포(DVWA / OWASP Juice Shop) 및 공격 실습
	3.	CloudWatch → Kinesis → Logstash(ECS) → OpenSearch로 이어지는 SIEM 로그 파이프라인 구성
	4.	탐지 룰(Sigma) 작성 및 공격 이벤트 기반 대시보드 구축
	5.	실제 공격 로그 기반 보안 모니터링 경험 확보

2차 확장 목표로는 다음을 고려합니다.
	•	LLM 기반 SOAR 기능 구현
	•	Threat Intelligence(CTI) 연동 및 탐지 품질 향상

사용 기술 및 도구

Cloud / Infra
	•	AWS EC2, VPC, Subnet, 보안 그룹
	•	S3 (백업 및 스냅샷)
	•	IAM
	•	OpenSearch (SIEM 대시보드)
	•	ECS Fargate (Logstash)
	•	Kinesis Data Stream
	•	CloudWatch Logs

IaC / DevOps
	•	Terraform
	•	GitHub Actions (CI/CD)
	•	GitHub 기반 협업 전략(Pull Request / Code Review)

Security / Logging
	•	DVWA, OWASP Juice Shop (공격 대상)
	•	Logstash (grok, geoip, mutate, date)
	•	Sigma Rules
	•	Filebeat or CloudWatch Agent (수집)
	•	Attack tools (SQLMap, wfuzz, Hydra 등)