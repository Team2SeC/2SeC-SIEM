# Amazon Linux 2023 AMI (고정값)
# AMI: Amazon Linux 2023 AMI 2023.9.20251208.0 x86_64 HVM kernel-6.1
# Region: ap-northeast-2 (Seoul)
locals {
  name_prefix = "${var.project_name}-${var.environment}"
  ami_id      = "ami-0b818a04bc9c2133c"
}

# Web Server 보안그룹
resource "aws_security_group" "web" {
  name        = "${local.name_prefix}-web-sg"
  description = "Security group for DVWA Web Server"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
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
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = var.iam_instance_profile_name

  user_data = <<-EOF
              #!/bin/bash
              set -e

              # Docker 설치
              install_docker() {
                  if ! command -v docker &> /dev/null; then
                      sudo yum update -y
                      sudo yum install docker -y
                      sudo systemctl start docker
                      sudo systemctl enable docker
                      sudo usermod -aG docker ec2-user
                  fi
              }

              # CloudWatch Agent 설치 및 설정
              install_cloudwatch_agent() {
                  if ! command -v amazon-cloudwatch-agent-ctl &> /dev/null; then
                      sudo yum install -y amazon-cloudwatch-agent
                  fi

                  # rsyslog 설치 (Amazon Linux 2023에서 /var/log/messages 생성용)
                  sudo yum install -y rsyslog
                  sudo systemctl enable rsyslog
                  sudo systemctl start rsyslog

                  # CloudWatch Agent 설정 파일 생성 (rsyslog 사용)
                  sudo tee /tmp/cloudwatch-config.json > /dev/null <<'CWCONFIG'
              {
                "logs": {
                  "logs_collected": {
                    "files": {
                      "collect_list": [
                        {
                          "file_path": "/var/log/docker-dvwa.log",
                          "log_group_name": "/aws/ec2/dvwa-web-server",
                          "log_stream_name": "{instance_id}/dvwa-app",
                          "timezone": "UTC"
                        },
                        {
                          "file_path": "/var/log/messages",
                          "log_group_name": "/aws/ec2/dvwa-web-server",
                          "log_stream_name": "{instance_id}/syslog",
                          "timezone": "UTC"
                        }
                      ]
                    }
                  }
                }
              }
              CWCONFIG

                  # CloudWatch Agent 시작
                  sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
                      -a fetch-config \
                      -m ec2 \
                      -s \
                      -c file:/tmp/cloudwatch-config.json
              }

              # 의존성 확인
              check_dependencies() {
                  if ! command -v docker &> /dev/null; then
                      install_docker
                  fi
                  if ! sudo docker info &> /dev/null; then
                      sudo systemctl start docker
                      sleep 2
                  fi
              }

              # 기존 DVWA 컨테이너 정리
              cleanup_existing() {
                  if sudo docker ps -a | grep -q dvwa; then
                      sudo docker stop dvwa 2>/dev/null || true
                      sudo docker rm dvwa 2>/dev/null || true
                  fi
              }

              # DVWA 컨테이너 시작
              start_dvwa() {
                  # DVWA 이미지 Pull
                  if ! sudo docker images | grep -q "vulnerables/web-dvwa"; then
                      sudo docker pull vulnerables/web-dvwa
                  fi

                  # 포트 충돌 확인
                  PORT=80
                  if sudo netstat -tlnp 2>/dev/null | grep -q ":80 " || sudo ss -tlnp 2>/dev/null | grep -q ":80 "; then
                      PORT=8080
                  fi

                  # Docker 로그 파일 준비
                  sudo touch /var/log/docker-dvwa.log
                  sudo chmod 666 /var/log/docker-dvwa.log

                  # DVWA 컨테이너 실행
                  sudo docker run -d \
                      --name dvwa \
                      --restart unless-stopped \
                      --log-driver json-file \
                      --log-opt max-size=10m \
                      --log-opt max-file=3 \
                      -p $${PORT}:80 \
                      -e MYSQL_PASS="password" \
                      vulnerables/web-dvwa

                  # Docker 로그를 파일로 스트리밍 (백그라운드)
                  nohup sudo docker logs -f dvwa >> /var/log/docker-dvwa.log 2>&1 &
              }

              # Public IP 조회
              get_public_ip() {
                  PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "")
                  if [ -z "$PUBLIC_IP" ]; then
                      PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "unknown")
                  fi
                  echo "$PUBLIC_IP"
              }

              # 서비스 상태 확인
              check_service() {
                  sleep 5
                  if sudo docker ps | grep -q dvwa; then
                      PORT=$(sudo docker port dvwa 80 | cut -d':' -f2)
                      PUBLIC_IP=$(get_public_ip)
                      echo -e "\nDVWA URL: http://localhost:$${PORT}"
                      [ "$PUBLIC_IP" != "unknown" ] && echo "Public URL: http://$${PUBLIC_IP}:$${PORT}"
                      echo -e "Credentials: admin / password\n"
                  else
                      echo "DVWA 시작 실패"
                      exit 1
                  fi
              }

              # 메인 실행
              main() {
                  check_dependencies
                  install_cloudwatch_agent
                  cleanup_existing
                  start_dvwa
                  check_service
              }

              # 시그널 트랩
              trap 'exit 1' INT TERM

              # 실행
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
