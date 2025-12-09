locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# 예시: 네트워크(VPC/Subnet/SG 등)를 infra/modules/network 모듈로 분리했다고 가정하고,
# infra/dev/main.tf에서는 해당 모듈을 호출만 하는 루트 모듈 역할을 수행.

module "network" {
  source = "./modules/network"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region

  # 모듈 내부에서 공통 태그를 다시 계산해도 되고,
  # 이렇게 넘겨서 그대로 사용하는 형태로 설계해도 됨.
  common_tags = local.common_tags
}

## TODO:
## 이후 EC2(DVWA), CloudWatch Logs, Kinesis, ECS(Logstash), OpenSearch, S3 Snapshot 등도
## module "ec2_web_dvwa" { ... } 형태로 modules/ 아래에 정의한 뒤
## 이 main.tf에서 조합해 나가면 됩니다.


