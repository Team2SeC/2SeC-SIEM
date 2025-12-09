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
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = var.iam_instance_profile_name

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
