variable "project_name" {
  description = "프로젝트 이름"
  type        = string
}

variable "environment" {
  description = "환경 (dev, prod 등)"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs 보존 기간 (일)"
  type        = number
  default     = 7
}

variable "common_tags" {
  description = "공통 태그"
  type        = map(string)
  default     = {}
}
