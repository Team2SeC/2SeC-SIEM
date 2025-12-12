aws_region   = "ap-northeast-2"
project_name = "2SeC"
environment  = "dev"

logstash_image_repository = "839444048443.dkr.ecr.ap-northeast-2.amazonaws.com/2sec-dev-logstash"

# 기본 태그는 latest (GitHub Actions 등에서 덮어쓸 수 있음)
logstash_image_tag = "latest"

# Kinesis Client Library(KCL) application_name
# - Kinesis 체크포인트/소비자 그룹 식별자
logstash_kcl_application_name = "2sec-dev-logstash"


