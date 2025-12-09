variable "project_name" {
  type        = string
  description = "프로젝트 이름 (태그 및 리소스 네이밍 prefix)"
}

variable "environment" {
  type        = string
  description = "환경 이름 (예: dev, prod)"
}

variable "common_tags" {
  description = "공통 태그 맵 (Project, Environment, ManagedBy 등)"
  type        = map(string)
  default     = {}
}
