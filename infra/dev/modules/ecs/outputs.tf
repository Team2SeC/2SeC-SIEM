output "ecs_cluster_id" {
  description = "ECS Cluster ID"
  value       = aws_ecs_cluster.this.id
}

output "ecs_cluster_name" {
  description = "ECS Cluster 이름"
  value       = aws_ecs_cluster.this.name
}

output "logstash_service_name" {
  description = "Logstash ECS Service 이름"
  value       = aws_ecs_service.logstash.name
}

output "logstash_task_definition_arn" {
  description = "Logstash ECS Task Definition ARN"
  value       = aws_ecs_task_definition.logstash.arn
}

output "logstash_security_group_id" {
  description = "Logstash Fargate 태스크용 보안그룹 ID"
  value       = aws_security_group.logstash.id
}

output "logstash_log_group_name" {
  description = "Logstash 컨테이너 로그를 기록하는 CloudWatch Log Group 이름"
  value       = aws_cloudwatch_log_group.logstash.name
}

output "logstash_task_role_arn" {
  description = "Logstash ECS 태스크 Role ARN (OpenSearch 도메인 리소스 정책 등에 사용)"
  value       = aws_iam_role.task.arn
}


