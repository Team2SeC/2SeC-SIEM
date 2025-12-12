#--------------------------------------------------------------
# 2SeC SIEM Infrastructure - Logstash Custom Docker & ECR
#--------------------------------------------------------------

#--------------------------------------------------------------
# ECR Repository for Custom Logstash Image
#--------------------------------------------------------------
resource "aws_ecr_repository" "logstash_custom" {
  name                 = "${var.project_name}-logstash-custom"
  image_tag_mutability = "MUTABLE"
  
#--------------------------------------------------------------
	# On Dev. Step, latest Tag Overwiting is Needed
		## => IMMUTABLE : On Prod. Env -- Tag is Unchangable => MUT
#--------------------------------------------------------------
  image_scanning_configuration {
    scan_on_push = true
  }

  lifecycle_policy {
    policy = jsonencode({
      rules = [
        {
          rulePriority = 1
          description  = "Keep last 10 production images"
          selection = {
            tagStatus     = "tagged"
            tagPrefixList = ["v", "prod", "release"]
            countType     = "imageCountMoreThan"
            countNumber   = 10
          }
          action = {
            type = "expire"
          }
        },
  #--------------------------------------------------------------
 # Assume : Tag seems to 'v1.0.0', 'prod-20251211', 'release-1.2' 
  #--------------------------------------------------------------
  
        {
          rulePriority = 2
          description  = "Keep last 3 development images"
          selection = {
            tagStatus     = "tagged"
            tagPrefixList = ["dev", "test", "latest"]
            countType     = "imageCountMoreThan"
            countNumber   = 3
          }
          action = {
            type = "expire"
          }
        },
        {
          rulePriority = 3
          description  = "Delete untagged images after 1 day"
          selection = {
            tagStatus   = "untagged"
            countType   = "sinceImagePushed"
            countUnit   = "days"
            countNumber = 1
          }
          action = {
            type = "expire"
          }
        }
      ]
    })
  }

  tags = {
    Name        = "${var.project_name}-logstash-ecr"
    Component   = "Logstash"
    Environment = var.environment
  }
}

#--------------------------------------------------------------
# ECR Repository Policy (ECS 접근 허용)
#--------------------------------------------------------------
resource "aws_ecr_repository_policy" "logstash_custom_policy" {
  repository = aws_ecr_repository.logstash_custom.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowECSAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.ecs_execution.arn
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ]
      }
    ]
  })
}
#--------------------------------------------------------------
We wnat to need auth := ECS pulls IMG
#--------------------------------------------------------------

#--------------------------------------------------------------
# ECS Task Role에 OpenSearch 접근 권한 추가 (중요!)
#--------------------------------------------------------------
resource "aws_iam_role_policy" "ecs_task_opensearch" {
  name = "${var.project_name}-ecs-opensearch-policy"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet",
          "es:ESHttpDelete",
          "es:ESHttpHead"
        ]
        Resource = "${aws_opensearch_domain.main.arn}/*"
      }
    ]
  })
}

#--------------------------------------------------------------
 # cf) iam.tf : ∃ kinesis + CloudWatch 
  # => ∄ OpenSearch Auth. -- Adding 
	  # ∵ Module ( Sep. Policy ) + Maintenance ( Omly OS ) + Debugging
	=> In my Opinion) After Checking - IAM Modifying ?
#--------------------------------------------------------------

#--------------------------------------------------------------
# ECS Task Role에 추가 CloudWatch 권한 (Logstash 에러 로그용)
#--------------------------------------------------------------
resource "aws_iam_role_policy" "ecs_task_additional_logs" {
  name = "${var.project_name}-ecs-additional-logs-policy"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "arn:aws:logs:${var.aws_region}:*:log-group:/aws/logstash/${var.project_name}-*",
          "arn:aws:logs:${var.aws_region}:*:log-group:/aws/logstash/${var.project_name}-*:*"
        ]
      }
    ]
  })
}

#--------------------------------------------------------------
# CloudWatch Log Group for Logstash Errors (사전 생성)
#--------------------------------------------------------------
resource "aws_cloudwatch_log_group" "logstash_errors" {
  name              = "/aws/logstash/${var.project_name}-errors"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.project_name}-logstash-errors"
    Component   = "Logstash"
    Environment = var.environment
  }
}

#--------------------------------------------------------------
# Secrets Manager for OpenSearch Password (보안 강화)
#--------------------------------------------------------------
resource "aws_secretsmanager_secret" "opensearch_password" {
  name                    = "${var.project_name}-opensearch-password"
  description             = "OpenSearch master user password for Logstash"
  recovery_window_in_days = 7

  tags = {
    Name        = "${var.project_name}-opensearch-secret"
    Component   = "OpenSearch"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "opensearch_password" {
  secret_id = aws_secretsmanager_secret.opensearch_password.id
  secret_string = jsonencode({
    password = var.opensearch_master_password
  })
}

#--------------------------------------------------------------
# ECS Task Role에 Secrets Manager 접근 권한
#--------------------------------------------------------------
resource "aws_iam_role_policy" "ecs_task_secrets" {
  name = "${var.project_name}-ecs-secrets-policy"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.opensearch_password.arn
      }
    ]
  })
}

#--------------------------------------------------------------
# 빌드용 CodeBuild IAM Role (선택적 - 자동 빌드 파이프라인용)
#--------------------------------------------------------------
resource "aws_iam_role" "codebuild_logstash" {
  name = "${var.project_name}-codebuild-logstash-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-codebuild-logstash-role"
    Component   = "CodeBuild"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "codebuild_logstash_policy" {
  name = "${var.project_name}-codebuild-logstash-policy"
  role = aws_iam_role.codebuild_logstash.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:GetAuthorizationToken",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream", 
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:log-group:/aws/codebuild/${var.project_name}-logstash-*"
      }
    ]
  })
}