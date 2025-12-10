variable "project_name" {
  type        = string
  description = "프로젝트 이름 (태그 및 리소스 네이밍 prefix)"
}

variable "environment" {
  type        = string
  description = "환경 이름 (예: dev, prod)"
}

variable "aws_region" {
  type        = string
  description = "AWS 리전 (예: ap-northeast-2)"
}

variable "common_tags" {
  description = "공통 태그 맵 (Project, Environment, ManagedBy 등)"
  type        = map(string)
  default     = {}
}

variable "log_group_name" {
  type        = string
  description = "CloudWatch Logs → Kinesis 구독을 설정할 로그 그룹 이름"
}

variable "kinesis_shard_count" {
  type        = number
  description = "Kinesis Data Stream 샤드 개수 (초기 PoC는 1 권장)"
  default     = 1
}

variable "kinesis_retention_hours" {
  type        = number
  description = "Kinesis Data Stream 데이터 보존 시간(시간 단위)"
  default     = 24
}


