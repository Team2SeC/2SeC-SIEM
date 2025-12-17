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

// VPC 전용 도메인에서 사용하던 Security Group 출력 값.
// 현재는 Public 도메인을 사용하므로 SG를 생성하지 않으며, 참조 오류 방지를 위해 비활성화.
// output "security_group_id" {
//   description = "OpenSearch 보안 그룹 ID"
//   value       = aws_security_group.opensearch.id
// }
//
output "log_group_name" {
  description = "OpenSearch 로그 CloudWatch Log Group 이름"
  value       = aws_cloudwatch_log_group.opensearch_logs.name
}

output "domain_arn" {
  description = "OpenSearch 도메인 ARN (데이터 플레인 권한 설정 등에 사용)"
  value       = "arn:aws:es:${var.aws_region}:${data.aws_caller_identity.current.account_id}:domain/${local.domain_name}/*"
}
