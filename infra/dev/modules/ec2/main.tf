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
set -euo pipefail

exec > >(tee /var/log/user-data.log) 2>&1
echo "=== User-Data Script Started at $(date) ==="

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
    fi
    # Docker 데몬이 완전히 준비될 때까지 대기 (최대 30초)
    for i in {1..15}; do
        if sudo docker info &> /dev/null; then
            echo "Docker daemon ready after $((i*2)) seconds"
            break
        fi
        sleep 2
    done
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
    # DVWA 이미지 Pull (재시도 로직 추가)
    echo "Pulling DVWA image..."
    for attempt in 1 2 3; do
        if sudo docker pull vulnerables/web-dvwa; then
            echo "Image pull successful on attempt $attempt"
            break
        fi
        echo "Image pull failed, attempt $attempt/3"
        sleep 5
    done

    # 포트 충돌 확인
    PORT=80
    if sudo ss -tlnp 2>/dev/null | grep -q ":80 "; then
        PORT=8080
    fi

    # Docker 로그 파일 준비
    sudo touch /var/log/docker-dvwa.log
    sudo chmod 666 /var/log/docker-dvwa.log

    # DVWA 컨테이너 실행
    echo "Starting DVWA container on port $PORT..."
    if ! sudo docker run -d \
        --name dvwa \
        --restart unless-stopped \
        --log-driver json-file \
        --log-opt max-size=10m \
        --log-opt max-file=3 \
        -p "$PORT:80" \
        -e MYSQL_PASS="password" \
        vulnerables/web-dvwa; then
        echo "ERROR: docker run failed with exit code $?"
        sudo docker logs dvwa 2>/dev/null || true
        return 1
    fi

    # DVWA 로그 스트리밍 systemd 서비스 등록
    sudo tee /etc/systemd/system/dvwa-log-stream.service > /dev/null <<'SVC'
[Unit]
Description=Docker Logs Streaming Service for DVWA
After=docker.service
Requires=docker.service

[Service]
ExecStartPre=/usr/bin/touch /var/log/docker-dvwa.log
ExecStartPre=/usr/bin/chmod 666 /var/log/docker-dvwa.log
ExecStart=/usr/bin/docker logs -f dvwa
StandardOutput=append:/var/log/docker-dvwa.log
StandardError=inherit
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC

    # 서비스 활성화 및 시작
    sudo systemctl daemon-reload
    sudo systemctl enable dvwa-log-stream
    sudo systemctl start dvwa-log-stream
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
        DVWA_PORT=$(sudo docker port dvwa 80 | cut -d':' -f2)
        PUBLIC_IP=$(get_public_ip)
        echo ""
        echo "DVWA URL: http://localhost:$DVWA_PORT"
        [ "$PUBLIC_IP" != "unknown" ] && echo "Public URL: http://$PUBLIC_IP:$DVWA_PORT"
        echo "Credentials: admin / password"
        echo ""
    else
        echo "DVWA 시작 실패"
        exit 1
    fi
}

# 메인 실행
main() {
    echo ""
    echo "============================================"
    echo "[STEP 1/5] Docker 설치 및 의존성 확인"
    echo "============================================"
    check_dependencies

    echo ""
    echo "============================================"
    echo "[STEP 2/5] CloudWatch Agent 및 rsyslog 설치"
    echo "============================================"
    install_cloudwatch_agent

    echo ""
    echo "============================================"
    echo "[STEP 3/5] 기존 DVWA 컨테이너 정리"
    echo "============================================"
    cleanup_existing

    echo ""
    echo "============================================"
    echo "[STEP 4/5] DVWA 컨테이너 시작"
    echo "============================================"
    start_dvwa

    echo ""
    echo "============================================"
    echo "[STEP 5/5] 서비스 상태 확인"
    echo "============================================"
    check_service

    echo ""
    echo "============================================"
    echo "=== User-Data 스크립트 완료: $(date) ==="
    echo "============================================"
}

# 시그널 트랩
trap 'echo "ERROR: Script failed at line $LINENO with exit code $?" >&2; exit 1' ERR
trap 'echo "Script interrupted" >&2; exit 1' INT TERM

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