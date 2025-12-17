variable "project_name" {
  description = "프로젝트 이름 (태그 및 리소스 네이밍 prefix)"
  type        = string
}

variable "environment" {
  description = "환경 이름 (예: dev, prod)"
  type        = string
}

variable "aws_region" {
  description = "AWS 리전 (예: ap-northeast-2)"
  type        = string
}

variable "common_tags" {
  description = "공통 태그 맵 (Project, Environment, ManagedBy 등)"
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "ECS 서비스가 동작할 VPC ID"
  type        = string
}

variable "private_subnet_id" {
  description = "Logstash Fargate 태스크를 배치할 프라이빗 서브넷 ID"
  type        = string
}

variable "logstash_image_repository" {
  description = "Logstash Docker 이미지 리포지토리 URI (ECR)"
  type        = string
}

variable "logstash_image_tag" {
  description = "Logstash Docker 이미지 태그 (예: latest, git SHA 등)"
  type        = string
  default     = "latest"
}

variable "kinesis_stream_name" {
  description = "Logstash가 읽을 Kinesis Data Stream 이름 (환경 변수로 전달)"
  type        = string
}

variable "kinesis_stream_arn" {
  description = "Logstash가 읽을 Kinesis Data Stream ARN (IAM 정책에 사용)"
  type        = string
}

variable "kcl_application_name" {
  description = "Kinesis Client Library(KCL) 애플리케이션 이름 (체크포인트/소비자 그룹 식별자)"
  type        = string
}

variable "cpu" {
  description = "Fargate 태스크 vCPU (예: 256, 512, 1024)"
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate 태스크 메모리(MiB, 예: 1024, 2048)"
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "ECS Service의 원하는 태스크 개수"
  type        = number
  default     = 1
}

variable "log_retention_days" {
  description = "Logstash CloudWatch Logs 보존 기간(일)"
  type        = number
  default     = 7
}

variable "opensearch_host" {
  description = "Logstash가 접속할 OpenSearch 도메인 호스트 (https:// 없이 도메인만, 예: vpc-xxx.ap-northeast-2.es.amazonaws.com)"
  type        = string
}


