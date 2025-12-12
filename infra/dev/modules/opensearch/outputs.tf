output "domain_name" {
  description = "OpenSearch 도메인 이름"
  value       = aws_opensearch_domain.this.domain_name
}

output "domain_endpoint" {
  description = "OpenSearch 도메인 엔드포인트 (HTTPS)"
  value       = aws_opensearch_domain.this.endpoint
}

output "dashboard_endpoint" {
  description = "OpenSearch Dashboards 엔드포인트"
  value       = aws_opensearch_domain.this.dashboard_endpoint
}

output "security_group_id" {
  description = "OpenSearch 보안 그룹 ID"
  value       = aws_security_group.opensearch.id
}

output "log_group_name" {
  description = "OpenSearch 로그 CloudWatch Log Group 이름"
  value       = aws_cloudwatch_log_group.opensearch_logs.name
}
