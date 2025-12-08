output "github_actions_role_arn" {
  description = "GitHub Actions에서 사용할 IAM Role ARN"
  value       = aws_iam_role.github_actions.arn
}

output "github_oidc_provider_arn" {
  description = "GitHub OIDC Provider ARN"
  value       = aws_iam_openid_connect_provider.github.arn
}


