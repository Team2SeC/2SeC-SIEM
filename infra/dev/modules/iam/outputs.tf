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
