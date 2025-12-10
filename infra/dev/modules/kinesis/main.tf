locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

# Kinesis Data Stream (DVWA Web Logs용)
resource "aws_kinesis_stream" "dvwa_logs" {
  name             = "${local.name_prefix}-web-logs"
  shard_count      = var.kinesis_shard_count
  retention_period = var.kinesis_retention_hours

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }

  # KMS 암호화는 필수는 아니지만, PoC에서도 기본 제공 KMS 키(alias/aws/kinesis)를 사용하는 것이 베스트 프랙티스
  encryption_type = "KMS"
  kms_key_id      = "alias/aws/kinesis"

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-web-logs"
    }
  )
}

# CloudWatch Logs → Kinesis Data Stream 전송을 위한 IAM Role
resource "aws_iam_role" "cw_to_kinesis" {
  name = "${local.name_prefix}-cw-to-kinesis"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-cw-to-kinesis"
    }
  )
}

resource "aws_iam_role_policy" "cw_to_kinesis" {
  name = "${local.name_prefix}-cw-to-kinesis-policy"
  role = aws_iam_role.cw_to_kinesis.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kinesis:PutRecord",
          "kinesis:PutRecords",
          "kinesis:DescribeStream",
          "kinesis:DescribeStreamSummary",
          "kinesis:ListShards"
        ]
        Resource = aws_kinesis_stream.dvwa_logs.arn
      }
    ]
  })
}

# CloudWatch Logs Subscription Filter:
#   /aws/ec2/dvwa-web-server 로그 그룹 → Kinesis Data Stream으로 실시간 전송
resource "aws_cloudwatch_log_subscription_filter" "dvwa_to_kinesis" {
  name           = "${local.name_prefix}-dvwa-to-kinesis"
  log_group_name = var.log_group_name

  # 빈 패턴("") → 모든 로그 전달 (필요 시 nginx/access.log 등 패턴으로 좁힐 수 있음)
  filter_pattern = ""

  destination_arn = aws_kinesis_stream.dvwa_logs.arn
  role_arn        = aws_iam_role.cw_to_kinesis.arn
}


