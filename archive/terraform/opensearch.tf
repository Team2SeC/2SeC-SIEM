#--------------------------------------------------------------
# 2SeC SIEM Infrastructure - OpenSearch Domain
# 비용 최적화: t3.small.search (가장 저렴한 옵션)
#--------------------------------------------------------------

#--------------------------------------------------------------
# Data Source - Current AWS Account
#--------------------------------------------------------------
data "aws_caller_identity" "current" {}

#--------------------------------------------------------------
# OpenSearch Domain (Cost-Optimized)
#--------------------------------------------------------------
resource "aws_opensearch_domain" "main" {
  domain_name    = "${var.project_name}-siem"
  engine_version = var.opensearch_version

  # 비용 최적화: 단일 노드, 최소 인스턴스 타입
  cluster_config {
    instance_type          = var.opensearch_instance_type
    instance_count         = var.opensearch_instance_count
    zone_awareness_enabled = false

    # Dedicated Master 비활성화 (비용 절감)
    dedicated_master_enabled = false
  }

  # EBS 스토리지 설정
  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.opensearch_ebs_volume_size
    throughput  = 125
    iops        = 3000
  }

  # VPC 배포 (Private Subnet)
  vpc_options {
    subnet_ids         = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.opensearch.id]
  }

  # 암호화 설정
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

  # 내부 사용자 데이터베이스 (Fine-grained access control)
  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true

    master_user_options {
      master_user_name     = var.opensearch_master_user
      master_user_password = var.opensearch_master_password
    }
  }

  # 액세스 정책
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "es:*"
        Resource = "arn:aws:es:${var.aws_region}:${data.aws_caller_identity.current.account_id}:domain/${var.project_name}-siem/*"
        Condition = {
          IpAddress = {
            "aws:SourceIp" = [var.my_ip]
          }
        }
      }
    ]
  })

  # 로그 발행 설정
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_logs.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_logs.arn
    log_type                 = "SEARCH_SLOW_LOGS"
  }

  tags = {
    Name = "${var.project_name}-opensearch"
  }

  depends_on = [
    aws_iam_service_linked_role.opensearch
  ]
}

#--------------------------------------------------------------
# OpenSearch CloudWatch Log Group
#--------------------------------------------------------------
resource "aws_cloudwatch_log_group" "opensearch_logs" {
  name              = "/aws/opensearch/${var.project_name}-siem"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-opensearch-logs"
  }
}

#--------------------------------------------------------------
# OpenSearch Log Resource Policy
#--------------------------------------------------------------
resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  policy_name = "${var.project_name}-opensearch-log-policy"

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

#--------------------------------------------------------------
# OpenSearch ISM Policy (Index State Management)
# SIEM 인덱스 7일 보관 정책
#--------------------------------------------------------------
# Note: ISM 정책은 OpenSearch Dashboard에서 수동 설정 또는
# null_resource + local-exec로 API 호출 필요
# 아래는 참고용 ISM 정책 JSON입니다:
#
# {
#   "policy": {
#     "description": "SIEM index retention policy - 7 days",
#     "default_state": "hot",
#     "states": [
#       {
#         "name": "hot",
#         "actions": [],
#         "transitions": [
#           {
#             "state_name": "delete",
#             "conditions": {
#               "min_index_age": "7d"
#             }
#           }
#         ]
#       },
#       {
#         "name": "delete",
#         "actions": [
#           {
#             "delete": {}
#           }
#         ],
#         "transitions": []
#       }
#     ],
#     "ism_template": {
#       "index_patterns": ["siem-web-*"],
#       "priority": 100
#     }
#   }
# }
