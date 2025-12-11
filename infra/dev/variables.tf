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


