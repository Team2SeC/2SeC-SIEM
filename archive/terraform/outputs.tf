#--------------------------------------------------------------
# 2SeC SIEM Infrastructure - Outputs
#--------------------------------------------------------------

#--------------------------------------------------------------
# Network Outputs
#--------------------------------------------------------------
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "VPC CIDR block"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_id" {
  description = "Public Subnet ID"
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "Private Subnet ID"
  value       = aws_subnet.private.id
}

output "nat_gateway_ip" {
  description = "NAT Gateway Elastic IP"
  value       = aws_eip.nat.public_ip
}

#--------------------------------------------------------------
# EC2 Outputs
#--------------------------------------------------------------
output "web_server_id" {
  description = "Web Server EC2 Instance ID"
  value       = aws_instance.web.id
}

output "web_server_public_ip" {
  description = "Web Server Public IP"
  value       = aws_instance.web.public_ip
}

output "web_server_private_ip" {
  description = "Web Server Private IP"
  value       = aws_instance.web.private_ip
}

#--------------------------------------------------------------
# Security Group Outputs
#--------------------------------------------------------------
output "web_security_group_id" {
  description = "Web Server Security Group ID"
  value       = aws_security_group.web.id
}

output "ecs_security_group_id" {
  description = "ECS Security Group ID"
  value       = aws_security_group.ecs.id
}

output "opensearch_security_group_id" {
  description = "OpenSearch Security Group ID"
  value       = aws_security_group.opensearch.id
}

#--------------------------------------------------------------
# Kinesis Outputs
#--------------------------------------------------------------
output "kinesis_stream_name" {
  description = "Kinesis Data Stream Name"
  value       = aws_kinesis_stream.main.name
}

output "kinesis_stream_arn" {
  description = "Kinesis Data Stream ARN"
  value       = aws_kinesis_stream.main.arn
}

#--------------------------------------------------------------
# ECS Outputs
#--------------------------------------------------------------
output "ecs_cluster_name" {
  description = "ECS Cluster Name"
  value       = aws_ecs_cluster.main.name
}

output "ecs_cluster_arn" {
  description = "ECS Cluster ARN"
  value       = aws_ecs_cluster.main.arn
}

output "ecs_service_name" {
  description = "ECS Logstash Service Name"
  value       = aws_ecs_service.logstash.name
}

#--------------------------------------------------------------
# Logstash Outputs (새로 추가) 👈
#--------------------------------------------------------------
output "logstash_ecr_repository_url" {
  description = "ECR repository URL for Logstash custom image"
  value       = aws_ecr_repository.logstash_custom.repository_url
}

output "logstash_ecr_repository_name" {
  description = "ECR repository name for Logstash"
  value       = aws_ecr_repository.logstash_custom.name
}

output "logstash_config_info" {
  description = "Logstash configuration information"
  value = {
    dockerfile_path    = "./logstash/Dockerfile"
    config_path       = "./logstash/config/"
    logstash_config   = "./logstash/config/logstash.config"
    logstash_yml      = "./logstash/config/logstash.yml"
    pipelines_yml     = "./logstash/config/pipelines.yml"
  }
}

#--------------------------------------------------------------
# OpenSearch Outputs
#--------------------------------------------------------------
output "opensearch_domain_name" {
  description = "OpenSearch Domain Name"
  value       = aws_opensearch_domain.main.domain_name
}

output "opensearch_endpoint" {
  description = "OpenSearch Domain Endpoint"
  value       = aws_opensearch_domain.main.endpoint
}

output "opensearch_dashboard_endpoint" {
  description = "OpenSearch Dashboard Endpoint"
  value       = "${aws_opensearch_domain.main.endpoint}/_dashboards"
}

output "opensearch_arn" {
  description = "OpenSearch Domain ARN"
  value       = aws_opensearch_domain.main.arn
}

#--------------------------------------------------------------
# S3 Outputs
#--------------------------------------------------------------
output "s3_snapshot_bucket_name" {
  description = "S3 Snapshot Bucket Name"
  value       = aws_s3_bucket.snapshot.id
}

output "s3_snapshot_bucket_arn" {
  description = "S3 Snapshot Bucket ARN"
  value       = aws_s3_bucket.snapshot.arn
}

#--------------------------------------------------------------
# CloudWatch Outputs
#--------------------------------------------------------------
output "cloudwatch_log_group_web" {
  description = "CloudWatch Log Group for Web Server"
  value       = aws_cloudwatch_log_group.web_server.name
}

output "cloudwatch_log_group_ecs" {
  description = "CloudWatch Log Group for ECS"
  value       = aws_cloudwatch_log_group.ecs.name
}

#--------------------------------------------------------------
# Connection Info
#--------------------------------------------------------------
output "ssh_command" {
  description = "SSH command to connect to web server"
  value       = "ssh -i ~/.ssh/${var.key_name}.pem ec2-user@${aws_instance.web.public_ip}"
}
