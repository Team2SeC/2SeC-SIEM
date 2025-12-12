variable "project_name" {
  description = "프로젝트 이름 (태그 및 도메인 네이밍 prefix)"
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
  description = "OpenSearch를 배치할 VPC ID"
  type        = string
}

variable "vpc_cidr_block" {
  description = "VPC CIDR (보안 그룹 인바운드 기본 허용 범위)"
  type        = string
}

variable "subnet_ids" {
  description = "OpenSearch 도메인에 연결할 서브넷 ID 리스트 (보통 프라이빗 서브넷)"
  type        = list(string)
}

variable "allowed_cidr_blocks" {
  description = "OpenSearch에 접근 허용할 CIDR 목록 (null이면 vpc_cidr_block 사용)"
  type        = list(string)
  default     = null
}

variable "engine_version" {
  description = "OpenSearch 엔진 버전"
  type        = string
  default     = "OpenSearch_2.11"
}

variable "instance_type" {
  description = "OpenSearch 데이터 노드 인스턴스 타입"
  type        = string
  default     = "t3.small.search"
}

variable "instance_count" {
  description = "OpenSearch 데이터 노드 개수"
  type        = number
  default     = 1
}

variable "ebs_volume_size" {
  description = "OpenSearch 데이터 노드 EBS 볼륨 크기(GB)"
  type        = number
  default     = 10
}

variable "log_retention_days" {
  description = "OpenSearch 로그 CloudWatch 보존 일수"
  type        = number
  default     = 7
}

variable "master_user_name" {
  description = "OpenSearch 마스터 사용자 이름 (FGAC internal DB)"
  type        = string
  default     = "admin"
}

variable "master_user_password" {
  description = "OpenSearch 마스터 사용자 비밀번호 (FGAC internal DB, 미지정 시 자동 생성)"
  type        = string
  sensitive   = true
  default     = null
}
