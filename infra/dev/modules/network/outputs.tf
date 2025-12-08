output "vpc_id" {
  description = "생성된 VPC ID"
  value       = aws_vpc.this.id
}

output "public_subnet_id" {
  description = "퍼블릭 서브넷 ID"
  value       = aws_subnet.public.id
}

output "web_security_group_id" {
  description = "웹 트래픽용 보안 그룹 ID"
  value       = aws_security_group.web.id
}


