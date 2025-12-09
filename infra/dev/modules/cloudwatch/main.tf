locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

# DVWA EC2 인스턴스 로그 그룹
resource "aws_cloudwatch_log_group" "dvwa" {
  name              = "/aws/ec2/dvwa-web-server"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-dvwa-logs"
    }
  )
}
