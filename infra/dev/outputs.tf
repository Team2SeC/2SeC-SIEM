## Network 모듈 출력
output "vpc_id" {
  description = "VPC ID"
  value       = module.network.vpc_id
}

output "public_subnet_id" {
  description = "Public Subnet ID"
  value       = module.network.public_subnet_id
}

output "private_subnet_id" {
  description = "Private Subnet ID"
  value       = module.network.private_subnet_id
}

## IAM 모듈 출력
output "ec2_role_name" {
  description = "EC2 IAM Role 이름"
  value       = module.iam.ec2_role_name
}

output "ec2_instance_profile_name" {
  description = "EC2 Instance Profile 이름"
  value       = module.iam.ec2_instance_profile_name
}

## EC2 DVWA 웹서버 출력
output "dvwa_instance_id" {
  description = "DVWA EC2 인스턴스 ID"
  value       = module.ec2_web.instance_id
}

output "dvwa_public_ip" {
  description = "DVWA 웹서버 퍼블릭 IP"
  value       = module.ec2_web.instance_public_ip
}

output "dvwa_url" {
  description = "DVWA 접속 URL"
  value       = module.ec2_web.dvwa_url
}

output "dvwa_security_group_id" {
  description = "DVWA 웹서버 보안그룹 ID"
  value       = module.ec2_web.security_group_id
}

## CloudWatch 로그 그룹 출력
output "dvwa_log_group_name" {
  description = "DVWA CloudWatch 로그 그룹 이름"
  value       = module.cloudwatch.dvwa_log_group_name
}

## OpenSearch 출력
output "opensearch_domain_name" {
  description = "OpenSearch 도메인 이름"
  value       = module.opensearch.domain_name
}

output "opensearch_domain_endpoint" {
  description = "OpenSearch 도메인 엔드포인트"
  value       = module.opensearch.domain_endpoint
}

output "opensearch_dashboard_endpoint" {
  description = "OpenSearch Dashboards 엔드포인트"
  value       = module.opensearch.dashboard_endpoint
}

output "opensearch_security_group_id" {
  description = "OpenSearch 보안그룹 ID"
  value       = module.opensearch.security_group_id
}

output "opensearch_log_group_name" {
  description = "OpenSearch 로그 그룹 이름"
  value       = module.opensearch.log_group_name
}

## 접속 정보 안내
output "access_info" {
  description = "DVWA 접속 및 관리 정보"
  value       = <<-EOT

  ========================================
  DVWA 웹서버 배포 완료!
  ========================================

  📌 DVWA 웹 인터페이스
     URL: ${module.ec2_web.dvwa_url}
     로그인: admin / password

  📌 EC2 접속 (SSM Session Manager)
     aws ssm start-session --target ${module.ec2_web.instance_id}

  📌 Docker 관리
     sudo docker ps
     sudo docker logs dvwa
     sudo docker restart dvwa

  📌 CloudWatch Logs 확인
     aws logs tail ${module.cloudwatch.dvwa_log_group_name} --follow

  ⚠️  주의: 포트 80이 사용 중인 경우 자동으로 8080 포트 사용

  ========================================
  EOT
}


