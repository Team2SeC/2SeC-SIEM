output "logstash_repository_name" {
  description = "Logstash용 ECR 리포지토리 이름"
  value       = aws_ecr_repository.logstash.name
}

output "logstash_repository_url" {
  description = "Logstash용 ECR 리포지토리 URL (이미지 푸시/풀 시 사용)"
  value       = aws_ecr_repository.logstash.repository_url
}

output "logstash_repository_arn" {
  description = "Logstash용 ECR 리포지토리 ARN"
  value       = aws_ecr_repository.logstash.arn
}


