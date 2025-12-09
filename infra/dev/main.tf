locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Network 모듈 (VPC, Subnet, NAT Gateway 등)
module "network" {
  source = "./modules/network"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region
  common_tags  = local.common_tags
}

# IAM 모듈 (EC2용 Role 및 Instance Profile)
module "iam" {
  source = "./modules/iam"

  project_name = var.project_name
  environment  = var.environment
  common_tags  = local.common_tags
}

# CloudWatch Logs 모듈
module "cloudwatch" {
  source = "./modules/cloudwatch"

  project_name       = var.project_name
  environment        = var.environment
  log_retention_days = 7
  common_tags        = local.common_tags
}

# EC2 DVWA 웹서버 모듈
module "ec2_web" {
  source = "./modules/ec2"

  project_name = var.project_name
  environment  = var.environment

  # Network 모듈 출력값 사용
  vpc_id    = module.network.vpc_id
  subnet_id = module.network.public_subnet_id

  # IAM 모듈 출력값 사용 (SSM Session Manager 필수)
  iam_instance_profile_name = module.iam.ec2_instance_profile_name

  # 인스턴스 설정
  instance_type    = "t3.micro"
  root_volume_size = 20

  common_tags = local.common_tags

  # IAM 및 CloudWatch 모듈이 먼저 생성되어야 함
  depends_on = [module.iam, module.cloudwatch]
}

## TODO:
## 이후 CloudWatch Logs, Kinesis, ECS(Logstash), OpenSearch, S3 Snapshot 등도
## module "..." { ... } 형태로 modules/ 아래에 정의한 뒤
## 이 main.tf에서 조합해 나가면 됩니다.


