#--------------------------------------------------------------
# 2SeC SIEM Infrastructure - ECS Fargate (Logstash)
#--------------------------------------------------------------

#--------------------------------------------------------------
# ECS Cluster
#--------------------------------------------------------------
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${var.project_name}-cluster"
  }
}

#--------------------------------------------------------------
# ECS Task Definition - Logstash
#--------------------------------------------------------------
resource "aws_ecs_task_definition" "logstash" {
  family                   = "${var.project_name}-logstash"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.logstash_cpu
  memory                   = var.logstash_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "logstash"
      image     = var.logstash_image
      essential = true

      environment = [
        {
          name  = "KINESIS_STREAM_NAME"
          value = aws_kinesis_stream.main.name
        },
        {
          name  = "OPENSEARCH_HOST"
          value = aws_opensearch_domain.main.endpoint
        },
        {
          name  = "AWS_REGION"
          value = var.aws_region
        },
        # 추가
        {
          name  = "PROJECT_NAME"
          value = var.project_name
        },
        {
          name  = "OPENSEARCH_USERNAME" 
          value = var.opensearch_username
        },
        {
          name  = "ENVIRONMENT"
          value = var.environment
        }
      ]


      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "logstash"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:9600/ || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }

      portMappings = [
        {
          containerPort = 9600
          protocol      = "tcp"
        }
      ]
    }
  ])

  tags = {
    Name = "${var.project_name}-logstash-task"
  }
}

#--------------------------------------------------------------
# ECS Service - Logstash
#--------------------------------------------------------------
resource "aws_ecs_service" "logstash" {
  name            = "${var.project_name}-logstash-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.logstash.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.private.id]
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  deployment_configuration {
    maximum_percent         = 200
    minimum_healthy_percent = 100
  }

  tags = {
    Name = "${var.project_name}-logstash-service"
  }

  depends_on = [
    aws_iam_role_policy.ecs_task_kinesis,
    aws_opensearch_domain.main
  ]
}

#--------------------------------------------------------------
# Auto Scaling (Optional - for future use)
#--------------------------------------------------------------
# resource "aws_appautoscaling_target" "logstash" {
#   max_capacity       = 3
#   min_capacity       = 1
#   resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.logstash.name}"
#   scalable_dimension = "ecs:service:DesiredCount"
#   service_namespace  = "ecs"
# }
