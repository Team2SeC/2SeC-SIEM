locals {
  name_prefix = "${var.project_name}-${var.environment}"
  # 단순 치환으로 domain_name 길이/문자 제한 만족 (공백/언더스코어는 하이픈으로)
  domain_name = substr(
    lower("siem-${replace(replace(var.project_name, " ", "-"), "_", "-")}-${var.environment}"),
    0,
    28
  )
  allowed_cidrs = var.allowed_cidr_blocks != null ? var.allowed_cidr_blocks : [var.vpc_cidr_block]
}

data "aws_caller_identity" "current" {}

resource "aws_iam_service_linked_role" "opensearch" {
  aws_service_name = "opensearchservice.amazonaws.com"
}

resource "random_password" "opensearch_master" {
  count               = var.master_user_password == null ? 1 : 0
  length              = 16
  special             = true
  override_special    = "!@#$%^&*()-_=+"
}

locals {
  master_password = coalesce(
    var.master_user_password,
    try(random_password.opensearch_master[0].result, null)
  )
}

resource "aws_security_group" "opensearch" {
  name        = "${local.name_prefix}-opensearch-sg"
  description = "Security group for OpenSearch domain"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS access to OpenSearch"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = local.allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-opensearch-sg"
    }
  )
}

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

  vpc_options {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.opensearch.id]
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
    internal_user_database_enabled = true

    master_user_options {
      master_user_name     = var.master_user_name
      master_user_password = local.master_password
    }
  }

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = data.aws_caller_identity.current.arn }
        Action    = "es:*"
        Resource  = "arn:aws:es:${var.aws_region}:${data.aws_caller_identity.current.account_id}:domain/${local.domain_name}/*"
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

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-opensearch"
    }
  )

  depends_on = [
    aws_iam_service_linked_role.opensearch,
    aws_cloudwatch_log_resource_policy.opensearch
  ]
}
