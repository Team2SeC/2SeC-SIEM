#--------------------------------------------------------------
# 2SeC SIEM Infrastructure - CloudWatch Logs
#--------------------------------------------------------------

#--------------------------------------------------------------
# CloudWatch Log Group - Web Server Logs
#--------------------------------------------------------------
resource "aws_cloudwatch_log_group" "web_server" {
  name              = "/aws/ec2/web-server"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-web-server-logs"
  }
}

#--------------------------------------------------------------
# CloudWatch Log Group - ECS Logstash Logs
#--------------------------------------------------------------
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/aws/ecs/${var.project_name}-logstash"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-ecs-logs"
  }
}

#--------------------------------------------------------------
# CloudWatch Subscription Filter - Logs to Kinesis
#--------------------------------------------------------------
resource "aws_cloudwatch_log_subscription_filter" "kinesis" {
  name            = "${var.project_name}-kinesis-subscription"
  log_group_name  = aws_cloudwatch_log_group.web_server.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_stream.main.arn
  role_arn        = aws_iam_role.cloudwatch_to_kinesis.arn

  depends_on = [
    aws_iam_role_policy.cloudwatch_to_kinesis
  ]
}

#--------------------------------------------------------------
# CloudWatch Metric Alarm - EC2 CPU Utilization
#--------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "ec2_cpu" {
  alarm_name          = "${var.project_name}-ec2-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "EC2 CPU utilization is above 80%"

  dimensions = {
    InstanceId = aws_instance.web.id
  }

  tags = {
    Name = "${var.project_name}-ec2-cpu-alarm"
  }
}
