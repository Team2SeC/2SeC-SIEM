output "kinesis_stream_name" {
  description = "DVWA 웹 로그용 Kinesis Data Stream 이름"
  value       = aws_kinesis_stream.dvwa_logs.name
}

output "kinesis_stream_arn" {
  description = "DVWA 웹 로그용 Kinesis Data Stream ARN"
  value       = aws_kinesis_stream.dvwa_logs.arn
}

output "subscription_filter_name" {
  description = "CloudWatch Logs → Kinesis 구독 필터 이름"
  value       = aws_cloudwatch_log_subscription_filter.dvwa_to_kinesis.name
}


