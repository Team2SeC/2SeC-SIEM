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

# IAM 모듈 (EC2용 Role 및 Instance Profile, OpenSearch Admin Role)
module "iam" {
  source = "./modules/iam"

  project_name = var.project_name
  environment  = var.environment
  common_tags  = local.common_tags

  opensearch_admin_user_arns = var.opensearch_admin_iam_principals
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
  root_volume_size = 30

  common_tags = local.common_tags

  # IAM 및 CloudWatch 모듈이 먼저 생성되어야 함
  depends_on = [module.iam, module.cloudwatch]
}

# Kinesis Data Stream 모듈 (CloudWatch Logs → Kinesis)
module "kinesis" {
  source = "./modules/kinesis"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region

  common_tags    = local.common_tags
  log_group_name = module.cloudwatch.dvwa_log_group_name
}

module "opensearch" {
  source = "./modules/opensearch"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region
  common_tags  = local.common_tags

  engine_version  = var.opensearch_engine_version
  instance_type   = var.opensearch_instance_type
  instance_count  = var.opensearch_instance_count
  ebs_volume_size = var.opensearch_ebs_volume_size

  log_retention_days = var.opensearch_log_retention_days

  # IAM 모듈에서 생성한 OpenSearch Admin Role을 master_user_arn으로 사용
  master_user_arn = module.iam.opensearch_admin_role_arn
  # Logstash ECS 태스크 Role + OpenSearch Dashboards 접속용 Admin IAM 주체들
  additional_iam_principals = concat(
    [module.ecs.logstash_task_role_arn],
    var.opensearch_admin_iam_principals
  )
}

# ECS Fargate(Logstash) 모듈
module "ecs" {
  source = "./modules/ecs"

  project_name      = var.project_name
  environment       = var.environment
  aws_region        = var.aws_region
  common_tags       = local.common_tags
  vpc_id            = module.network.vpc_id
  private_subnet_id = module.network.private_subnet_id

  logstash_image_repository = var.logstash_image_repository
  logstash_image_tag        = var.logstash_image_tag

  kinesis_stream_name = module.kinesis.kinesis_stream_name
  kinesis_stream_arn  = module.kinesis.kinesis_stream_arn

  kcl_application_name = var.logstash_kcl_application_name

  # IAM 기반 접속: 도메인 엔드포인트는 환경 변수(OPENSEARCH_HOST)로만 전달
  opensearch_host        = module.opensearch.domain_endpoint
  opensearch_domain_name = module.opensearch.domain_name
}


## TODO:
## 이후 CloudWatch Logs, Kinesis, ECS(Logstash), OpenSearch, S3 Snapshot 등도
## module "..." { ... } 형태로 modules/ 아래에 정의한 뒤
## 이 main.tf에서 조합해 나가면 됩니다.
