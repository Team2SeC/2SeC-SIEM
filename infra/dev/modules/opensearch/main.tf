locals {
  name_prefix = "${var.project_name}-${var.environment}"
  # 단순 치환으로 domain_name 길이/문자 제한 만족 (공백/언더스코어는 하이픈으로)
  domain_name = substr(
    lower("siem-${replace(replace(var.project_name, " ", "-"), "_", "-")}-${var.environment}"),
    0,
    28
  )
}

data "aws_caller_identity" "current" {}

# OpenSearch Service Linked Role은 계정당 한 번만 생성되며 여러 도메인이 공유합니다.
# 이미 존재하는 경우 Terraform으로 관리하지 않고 data source로 참조만 합니다.
# 수동으로 생성: aws iam create-service-linked-role --aws-service-name opensearchservice.amazonaws.com
# 또는 첫 OpenSearch 도메인 생성 시 AWS가 자동으로 생성합니다.

resource "aws_cloudwatch_log_group" "opensearch_logs" {
  name              = "/aws/opensearch/${local.domain_name}"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-opensearch-logs"
    }
  )
}

resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  policy_name = "${local.name_prefix}-opensearch-log-policy"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "es.amazonaws.com"
        }
        Action = [
          "logs:PutLogEvents",
          "logs:CreateLogStream"
        ]
        Resource = "${aws_cloudwatch_log_group.opensearch_logs.arn}:*"
      }
    ]
  })
}

resource "aws_opensearch_domain" "this" {
  domain_name    = local.domain_name
  engine_version = var.engine_version

  cluster_config {
    instance_type            = var.instance_type
    instance_count           = var.instance_count
    zone_awareness_enabled   = false
    dedicated_master_enabled = false
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.ebs_volume_size
    throughput  = 125
    iops        = 3000
  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false

    master_user_options {
      master_user_arn = var.master_user_arn
    }
  }

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        # OpenSearch HTTP(Data plane)에 접근할 수 있는 IAM 주체들 (Logstash 태스크 Role + Admin Role/User 등)
        Principal = { AWS = distinct(concat(var.additional_iam_principals, [var.master_user_arn])) }
        # OpenSearch 도메인 HTTP(Data plane) 호출 허용 (인덱스 생성, 데이터 쓰기, 읽기, 삭제 등)
        Action = [
          "es:ESHttpGet",
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpDelete",
          "es:ESHttpHead",
          "es:ESHttpPatch"
        ]
        Resource = "arn:aws:es:${var.aws_region}:${data.aws_caller_identity.current.account_id}:domain/${local.domain_name}/*"
      }
    ]
  })

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_logs.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_logs.arn
    log_type                 = "SEARCH_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_logs.arn
    log_type                 = "ES_APPLICATION_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_logs.arn
    log_type                 = "AUDIT_LOGS"
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-opensearch"
    }
  )

  depends_on = [
    aws_cloudwatch_log_resource_policy.opensearch
  ]
}

#############################################
## (참고용) VPC 내부 전용 OpenSearch 예전 구성
## - 현재는 Public 도메인을 사용하므로 비활성화 상태
## - 나중에 VPC 전용으로 되돌리고 싶을 때 참고용으로 남겨둠
#############################################
#
# locals {
#   name_prefix = "${var.project_name}-${var.environment}"
#   # 단순 치환으로 domain_name 길이/문자 제한 만족 (공백/언더스코어는 하이픈으로)
#   domain_name = substr(
#     lower("siem-${replace(replace(var.project_name, " ", "-"), "_", "-")}-${var.environment}"),
#     0,
#     28
#   )
#   allowed_cidrs = var.allowed_cidr_blocks != null ? var.allowed_cidr_blocks : [var.vpc_cidr_block]
# }
#
# resource "aws_security_group" "opensearch" {
#   name        = "${local.name_prefix}-opensearch-sg"
#   description = "Security group for OpenSearch domain"
#   vpc_id      = var.vpc_id
#
#   ingress {
#     description = "HTTPS access to OpenSearch"
#     from_port   = 443
#     to_port     = 443
#     protocol    = "tcp"
#     cidr_blocks = local.allowed_cidrs
#   }
#
#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
#
#   tags = merge(
#     var.common_tags,
#     {
#       Name = "${local.name_prefix}-opensearch-sg"
#     }
#   )
# }
#
# resource "aws_opensearch_domain" "this" {
#   ...
#   vpc_options {
#     subnet_ids         = var.subnet_ids
#     security_group_ids = [aws_security_group.opensearch.id]
#   }
#   ...
# }

