output "instance_id" {
  description = "EC2 인스턴스 ID"
  value       = aws_instance.web.id
}

output "instance_public_ip" {
  description = "EC2 인스턴스 퍼블릭 IP"
  value       = aws_instance.web.public_ip
}

output "instance_private_ip" {
  description = "EC2 인스턴스 프라이빗 IP"
  value       = aws_instance.web.private_ip
}

output "security_group_id" {
  description = "웹 서버 보안그룹 ID"
  value       = aws_security_group.web.id
}

output "dvwa_url" {
  description = "DVWA 접속 URL (Docker 컨테이너는 루트 경로로 서비스)"
  value       = "http://${aws_instance.web.public_ip}"
}

output "instance_ami_id" {
  description = "사용된 AMI ID"
  value       = aws_instance.web.ami
}
