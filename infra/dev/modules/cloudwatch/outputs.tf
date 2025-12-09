output "dvwa_log_group_name" {
  description = "DVWA 로그 그룹 이름"
  value       = aws_cloudwatch_log_group.dvwa.name
}

output "dvwa_log_group_arn" {
  description = "DVWA 로그 그룹 ARN"
  value       = aws_cloudwatch_log_group.dvwa.arn
}
