locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

# EC2용 IAM Role
resource "aws_iam_role" "ec2" {
  name = "${local.name_prefix}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-ec2-role"
    }
  )
}

# SSM Session Manager 정책 연결 (필수)
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# CloudWatch Agent 정책 연결
resource "aws_iam_role_policy_attachment" "ec2_cloudwatch" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# CloudWatch Logs 추가 권한 (Docker 로그 수집용)
resource "aws_iam_role_policy" "ec2_logs" {
  name = "${local.name_prefix}-ec2-logs-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/ec2/*"
      }
    ]
  })
}

# EC2 Instance Profile
resource "aws_iam_instance_profile" "ec2" {
  name = "${local.name_prefix}-ec2-profile"
  role = aws_iam_role.ec2.name

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-ec2-profile"
    }
  )
}

# OpenSearch Admin Role (admin-01~05 사용자들이 assume 가능)
resource "aws_iam_role" "opensearch_admin" {
  name = "${local.name_prefix}-opensearch-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.opensearch_admin_user_arns
        }
      }
    ]
  })

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-opensearch-admin-role"
    }
  )
}

# Kinesis 읽기 권한
resource "aws_iam_role_policy" "ec2_kinesis" {
  name = "${local.name_prefix}-ec2-kinesis-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kinesis:DescribeStream",
          "kinesis:GetShardIterator", 
          "kinesis:GetRecords",
          "kinesis:ListShards"
        ]
        Resource = "arn:aws:kinesis:*:*:stream/${var.project_name}-*"
      }
    ]
  })
}

# DynamoDB 체크포인트 권한  
resource "aws_iam_role_policy" "ec2_dynamodb" {
  name = "${local.name_prefix}-ec2-dynamodb-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:CreateTable",
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:PutItem", 
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Scan",
          "dynamodb:Query"
        ]
        Resource = "arn:aws:dynamodb:*:*:table/${var.project_name}-*"
      }
    ]
  })
}


# OpenSearch 쓰기 권한
resource "aws_iam_role_policy" "ec2_opensearch" {
  name = "${local.name_prefix}-ec2-opensearch-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "es:ESHttpPost",
          "es:ESHttpPut"
        ]
        Resource = "arn:aws:es:*:*:domain/${var.project_name}-*/*"
      }
    ]
  })
}