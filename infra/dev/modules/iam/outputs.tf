output "ec2_role_arn" {
  description = "EC2 IAM Role ARN"
  value       = aws_iam_role.ec2.arn
}

output "ec2_role_name" {
  description = "EC2 IAM Role 이름"
  value       = aws_iam_role.ec2.name
}

output "ec2_instance_profile_name" {
  description = "EC2 Instance Profile 이름 (EC2 인스턴스에 연결)"
  value       = aws_iam_instance_profile.ec2.name
}

output "ec2_instance_profile_arn" {
  description = "EC2 Instance Profile ARN"
  value       = aws_iam_instance_profile.ec2.arn
}

output "opensearch_admin_role_arn" {
  description = "OpenSearch Admin Role ARN (OpenSearch master_user_arn으로 사용)"
  value       = aws_iam_role.opensearch_admin.arn
}