#--------------------------------------------------------------
# 2SeC SIEM Infrastructure - Variables
#--------------------------------------------------------------

#--------------------------------------------------------------
# General
#--------------------------------------------------------------
variable "project_name" {
  description = "프로젝트 이름"
  type        = string
  default     = "2sec"
}

variable "environment" {
  description = "환경 (dev/staging/prod)"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS 리전"
  type        = string
  default     = "ap-northeast-2"
}

#--------------------------------------------------------------
# Network
#--------------------------------------------------------------
variable "vpc_cidr" {
  description = "VPC CIDR 블록"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Public Subnet CIDR 블록"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "Private Subnet CIDR 블록"
  type        = string
  default     = "10.0.2.0/24"
}

#--------------------------------------------------------------
# Access Control
#--------------------------------------------------------------
variable "my_ip" {
  description = "SSH/Dashboard 접속 허용할 IP (CIDR 형식, 예: 1.2.3.4/32)"
  type        = string
  sensitive   = true
}

variable "key_name" {
  description = "EC2 SSH 키페어 이름"
  type        = string
}

#--------------------------------------------------------------
# EC2
#--------------------------------------------------------------
variable "ec2_instance_type" {
  description = "EC2 인스턴스 타입"
  type        = string
  default     = "t3.micro"
}

#--------------------------------------------------------------
# Kinesis
#--------------------------------------------------------------
variable "kinesis_shard_count" {
  description = "Kinesis Data Stream 샤드 수"
  type        = number
  default     = 1
}

variable "kinesis_retention_hours" {
  description = "Kinesis 데이터 보존 시간"
  type        = number
  default     = 24
}

#--------------------------------------------------------------
# ECS Fargate (Logstash)
#--------------------------------------------------------------
variable "logstash_cpu" {
  description = "Logstash 태스크 CPU (256 = 0.25 vCPU)"
  type        = number
  default     = 512
}

variable "logstash_memory" {
  description = "Logstash 태스크 메모리 (MB)"
  type        = number
  default     = 1024
}

variable "logstash_image" {
  description = "Logstash Docker 이미지"
  type        = string
  default     = "docker.elastic.co/logstash/logstash:8.11.0"
}

#--------------------------------------------------------------
# OpenSearch (비용 최적화 설정)
#--------------------------------------------------------------
variable "opensearch_version" {
  description = "OpenSearch 엔진 버전"
  type        = string
  default     = "OpenSearch_2.11"
}

variable "opensearch_instance_type" {
  description = "OpenSearch 인스턴스 타입 (비용 최적화: t3.small.search)"
  type        = string
  default     = "t3.small.search"
}

variable "opensearch_instance_count" {
  description = "OpenSearch 인스턴스 수"
  type        = number
  default     = 1
}

variable "opensearch_ebs_volume_size" {
  description = "OpenSearch EBS 볼륨 크기 (GB)"
  type        = number
  default     = 10
}

variable "opensearch_master_user" {
  description = "OpenSearch 마스터 사용자 이름"
  type        = string
  default     = "admin"
}

variable "opensearch_master_password" {
  description = "OpenSearch 마스터 사용자 비밀번호"
  type        = string
  sensitive   = true
}

#--------------------------------------------------------------
# CloudWatch Logs
#--------------------------------------------------------------
variable "log_retention_days" {
  description = "CloudWatch Logs 보존 기간 (일)"
  type        = number
  default     = 7
}

#--------------------------------------------------------------
# S3
#--------------------------------------------------------------
variable "snapshot_retention_days" {
  description = "S3 스냅샷 보존 기간 (일)"
  type        = number
  default     = 365
}
