terraform {
  required_version = "~> 1.14.0"

  # backend 설정 값은 HCL 파일(infra/dev/env/*.backend.hcl)로 분리해서 관리합니다.
  # 예: terraform init -backend-config="env/dev.backend.hcl"
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}


