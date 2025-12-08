variable "aws_region" {
  type        = string
  description = "AWS 리전을 설정합니다 (예: ap-northeast-2)."
  default     = "ap-northeast-2"
}

variable "github_owner" {
  type        = string
  description = "GitHub 조직 또는 사용자 이름 (예: my-org 또는 my-user)."
}

variable "github_repo" {
  type        = string
  description = "GitHub 리포지토리 이름 (예: project02)."
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

variable "oidc_role_name" {
  type        = string
  description = "GitHub Actions에서 사용할 AWS IAM Role 이름."
  default     = "github-actions-terraform-role"
}

variable "oidc_branch" {
  type        = string
  description = "OIDC로 Role Assume을 허용할 Git 브랜치(ref)."
  default     = "main"
}


