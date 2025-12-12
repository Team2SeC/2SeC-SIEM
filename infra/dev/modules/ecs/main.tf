data "aws_caller_identity" "current" {}

locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

# ECS Cluster for Logstash
resource "aws_ecs_cluster" "this" {
  name = "${local.name_prefix}-ecs-cluster"

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-ecs-cluster"
    }
  )
}

# Security Group for Logstash task (Fargate in private subnet)
resource "aws_security_group" "logstash" {
  name        = "${local.name_prefix}-logstash-sg"
  description = "Security group for Logstash Fargate tasks"
  vpc_id      = var.vpc_id

  # Inbound: 일반적으로 필요 없음 (Kinesis에서 pull, OpenSearch/S3로 push)
  # 필요 시 ALB/관리용 접근을 위해 인바운드 규칙을 별도로 추가.

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-logstash-sg"
    }
  )
}

# IAM Role for ECS task execution (pull image from ECR, write logs to CloudWatch)
resource "aws_iam_role" "execution" {
  name = "${local.name_prefix}-logstash-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-logstash-execution-role"
    }
  )
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# IAM Role for Logstash task (access Kinesis, DynamoDB checkpoints 등)
resource "aws_iam_role" "task" {
  name = "${local.name_prefix}-logstash-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-logstash-task-role"
    }
  )
}

# Kinesis + DynamoDB(KCL 체크포인트) 접근을 위한 최소 권한 정책
resource "aws_iam_role_policy" "task_kinesis_dynamodb" {
  name = "${local.name_prefix}-logstash-kinesis-dynamodb"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowKinesisRead"
        Effect = "Allow"
        Action = [
          "kinesis:DescribeStream",
          "kinesis:DescribeStreamSummary",
          "kinesis:ListShards",
          "kinesis:GetShardIterator",
          "kinesis:GetRecords"
        ]
        Resource = var.kinesis_stream_arn
      },
      {
        Sid    = "AllowDynamoDBCheckpoint"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeTable",
          "dynamodb:CreateTable",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Scan",
          "dynamodb:Query"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.kcl_application_name}"
      }
    ]
  })
}

# CloudWatch Logs group for Logstash container logs
resource "aws_cloudwatch_log_group" "logstash" {
  name              = "/${var.project_name}/${var.environment}/logstash"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-logstash-logs"
    }
  )
}

resource "aws_ecs_task_definition" "logstash" {
  family                   = "${local.name_prefix}-logstash"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "logstash"
      image     = "${var.logstash_image_repository}:${var.logstash_image_tag}"
      essential = true

      environment = [
        {
          name  = "AWS_REGION"
          value = var.aws_region
        },
        {
          name  = "KINESIS_STREAM_NAME"
          value = var.kinesis_stream_name
        },
        {
          name  = "APPLICATION_NAME"
          value = var.kcl_application_name
        }
        # OpenSearch / S3 / 기타 설정은 추후 env 또는 secrets 로 추가
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.logstash.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "logstash"
        }
      }

      # 포트 매핑이 필요하다면 여기에 정의 (보통 Logstash는 내부에서 outbound 전용으로 동작)
    }
  ])

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-logstash-taskdef"
    }
  )
}

resource "aws_ecs_service" "logstash" {
  name            = "${local.name_prefix}-logstash"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.logstash.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  network_configuration {
    subnets          = [var.private_subnet_id]
    security_groups  = [aws_security_group.logstash.id]
    assign_public_ip = false
  }

  lifecycle {
    ignore_changes = [
      task_definition
    ]
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-logstash-service"
    }
  )
}

