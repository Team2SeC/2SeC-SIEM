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

variable "vpc_id" {
  type        = string
  description = "EC2 인스턴스와 보안그룹을 배치할 VPC ID"
}

variable "subnet_id" {
  type        = string
  description = "EC2 인스턴스를 배치할 서브넷 ID (일반적으로 Public Subnet)"
}

variable "instance_type" {
  type        = string
  description = "EC2 인스턴스 타입"
  default     = "t3.micro"
}

variable "root_volume_size" {
  type        = number
  description = "루트 볼륨 크기 (GB)"
  default     = 30
}

variable "ssh_allowed_cidr_blocks" {
  type        = list(string)
  description = "SSH 접근을 허용할 CIDR 블록 리스트 (SSH 포트는 기본적으로 비활성화됨, SSM 사용 권장)"
  default     = ["0.0.0.0/0"]
}

variable "iam_instance_profile_name" {
  type        = string
  description = "EC2 인스턴스에 연결할 IAM Instance Profile 이름 (선택사항)"
  default     = null
}
