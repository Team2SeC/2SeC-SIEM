#--------------------------------------------------------------
# 2SeC SIEM Infrastructure - Terraform Backend
#--------------------------------------------------------------
# 주의: S3 버킷은 terraform 실행 전에 수동으로 생성해야 합니다.
# aws s3 mb s3://2sec-terraform-state --region ap-northeast-2
#--------------------------------------------------------------

terraform {
  backend "s3" {
    bucket  = "2sec-terraform-state"
    key     = "infra/terraform.tfstate"
    region  = "ap-northeast-2"
    encrypt = true
  }
}
