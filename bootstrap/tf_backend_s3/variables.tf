variable "aws_region" {
  type        = string
  description = "AWS 리전을 설정합니다 (예: ap-northeast-2)."
  default     = "ap-northeast-2"
}

variable "project_name" {
  type        = string
  description = "프로젝트 공통 prefix (예: project02)."
}

variable "environment" {
  type        = string
  description = "환경 구분 값 (예: dev, prod)."
  default     = "dev"
}


