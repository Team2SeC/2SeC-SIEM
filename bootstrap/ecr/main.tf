locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

# Logstash 등 커스텀 컨테이너 이미지를 위한 ECR 리포지토리
resource "aws_ecr_repository" "logstash" {
  name                 = "${lower(var.project_name)}-${var.environment}-logstash"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Name        = "${local.name_prefix}-logstash-ecr"
  }
}

# Lifecycle Policy: 최근 5개 이미지만 유지, 나머지는 자동 만료
resource "aws_ecr_lifecycle_policy" "logstash" {
  repository = aws_ecr_repository.logstash.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 5 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

