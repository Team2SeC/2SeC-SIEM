variable "aws_region" {
  type        = string
  description = "AWS 리전을 설정합니다 (예: ap-northeast-2)."
  default     = "ap-northeast-2"
}

variable "project_name" {
  type        = string
  description = "프로젝트 공통 prefix (예: project02)."
  default     = "2SeC"
}

variable "environment" {
  type        = string
  description = "환경 구분 값 (예: dev, prod)."
  default     = "dev"
}

variable "logstash_image_repository" {
  type        = string
  description = "Logstash ECS 태스크에서 사용할 Docker 이미지 리포지토리 URI (ECR)"
}

variable "logstash_image_tag" {
  type        = string
  description = "Logstash Docker 이미지 태그 (예: latest, git SHA 등)"
  default     = "latest"
}

variable "logstash_kcl_application_name" {
  type        = string
  description = "Logstash Kinesis 소비자 그룹(KCL application_name)"
}

# OpenSearch
variable "opensearch_engine_version" {
  type        = string
  description = "OpenSearch 엔진 버전 (예: OpenSearch_2.11)"
  default     = "OpenSearch_3.3"
}

variable "opensearch_instance_type" {
  type        = string
  description = "OpenSearch 데이터 노드 인스턴스 타입"
  default     = "t3.medium.search"
}

variable "opensearch_instance_count" {
  type        = number
  description = "OpenSearch 데이터 노드 개수"
  default     = 1
}

variable "opensearch_ebs_volume_size" {
  type        = number
  description = "OpenSearch 데이터 노드 EBS 볼륨 크기(GB)"
  default     = 10
}

variable "opensearch_log_retention_days" {
  type        = number
  description = "OpenSearch CloudWatch Logs 보존 기간(일)"
  default     = 7
}

// opensearch_allowed_cidr_blocks 는 VPC 내부 도메인을 사용할 때만 의미가 있었으나,
// 현재 구성에서는 Public 도메인을 사용하므로 더 이상 사용하지 않음 (보존 주석)
// variable "opensearch_allowed_cidr_blocks" {
//   type        = list(string)
//   description = "OpenSearch에 접근 허용할 CIDR 목록 (미지정 시 VPC CIDR 사용)"
//   default     = null
// }

// opensearch_master_user_arn은 더 이상 사용하지 않음
# IAM 모듈에서 생성한 opensearch_admin_role_arn을 자동으로 사용
# variable "opensearch_master_user_arn" {
#   type        = string
#   description = "IAM 기반 OpenSearch 마스터 사용자 ARN"
# }

variable "opensearch_admin_iam_principals" {
  type        = list(string)
  description = "OpenSearch Dashboards에 접근할 수 있는 Admin IAM 주체 ARN 리스트 (IAM User 또는 Role ARN)"
  default     = []
}
