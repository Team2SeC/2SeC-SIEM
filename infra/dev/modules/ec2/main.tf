locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

# 최신 Amazon Linux 2023 AMI 조회
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Web Server 보안그룹
resource "aws_security_group" "web" {
  name        = "${local.name_prefix}-web-sg"
  description = "Security group for DVWA Web Server"
  vpc_id      = var.vpc_id

  # HTTP
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH 포트 제거 - SSM Session Manager 사용 권장
  # 필요시 아래 주석 해제하여 사용 (보안상 권장하지 않음)
  # ingress {
  #   description = "SSH"
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"
  #   cidr_blocks = var.ssh_allowed_cidr_blocks
  # }

  # Outbound - 전체 허용
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-web-sg"
    }
  )
}

# DVWA Web Server EC2 Instance
resource "aws_instance" "web" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = var.iam_instance_profile_name

  # DVWA Docker 설치 Bootstrap Script
  user_data = <<-EOF
              #!/bin/bash

              set -e

              install_docker() {
                  if ! command -v docker &> /dev/null; then
                      sudo yum update -y
                      sudo yum install docker -y
                      sudo systemctl start docker
                      sudo systemctl enable docker
                      sudo usermod -aG docker $USER
                  fi
              }

              check_dependencies() {
                  if ! command -v docker &> /dev/null; then
                      install_docker
                  fi

                  if ! sudo docker info &> /dev/null; then
                      sudo systemctl start docker
                      sleep 2
                  fi
              }

              configure_firewall() {
                  if command -v firewall-cmd &> /dev/null; then
                      sudo firewall-cmd --permanent --add-port=80/tcp 2>/dev/null || true
                      sudo firewall-cmd --reload 2>/dev/null || true
                  fi
              }

              cleanup_existing() {
                  if sudo docker ps -a | grep -q dvwa; then
                      sudo docker stop dvwa 2>/dev/null || true
                      sudo docker rm dvwa 2>/dev/null || true
                  fi
              }

              start_dvwa() {
                  if ! sudo docker images | grep -q "vulnerables/web-dvwa"; then
                      sudo docker pull vulnerables/web-dvwa
                  fi

                  PORT=80
                  if sudo netstat -tlnp 2>/dev/null | grep -q ":80 " || sudo ss -tlnp 2>/dev/null | grep -q ":80 "; then
                      PORT=8080
                  fi

                  sudo docker run -d \
                      --name dvwa \
                      --restart unless-stopped \
                      -p ${PORT}:80 \
                      -e MYSQL_PASS="password" \
                      vulnerables/web-dvwa
              }

              get_public_ip() {
                  PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "")
                  if [ -z "$PUBLIC_IP" ]; then
                      PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "unknown")
                  fi
                  echo "$PUBLIC_IP"
              }

              check_service() {
                  sleep 5

                  if sudo docker ps | grep -q dvwa; then
                      PORT=$(sudo docker port dvwa 80 | cut -d':' -f2)
                      PUBLIC_IP=$(get_public_ip)

                      echo -e "\nhttp://localhost:${PORT}"
                      [ "$PUBLIC_IP" != "unknown" ] && echo "http://${PUBLIC_IP}:${PORT}"
                      echo -e "admin / password\n"
                  else
                      echo "시작 실패"
                      exit 1
                  fi
              }

              main() {
                  check_dependencies
                  configure_firewall
                  cleanup_existing
                  start_dvwa
                  check_service
              }

              trap 'exit 1' INT TERM

              main
              EOF

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_size
    encrypted   = true

    tags = merge(
      var.common_tags,
      {
        Name = "${local.name_prefix}-web-root-volume"
      }
    )
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_prefix}-dvwa-web-server"
      Role = "WebServer"
      App  = "DVWA"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}
