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

variable "vpc_cidr_block" {
  type        = string
  description = "VPC CIDR 블록 (예: 10.0.0.0/16)"
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  type        = string
  description = "퍼블릭 서브넷 CIDR 블록 (예: 10.0.1.0/24)"
  default     = "10.0.1.0/24"
}

variable "public_subnet_az" {
  type        = string
  description = "퍼블릭 서브넷이 위치할 AZ (예: ap-northeast-2a)"
  default     = "ap-northeast-2a"
}

variable "web_ingress_cidrs" {
  type        = list(string)
  description = "웹 트래픽을 허용할 소스 CIDR 목록 (예: [\"0.0.0.0/0\"])"
  default     = ["0.0.0.0/0"]
}


