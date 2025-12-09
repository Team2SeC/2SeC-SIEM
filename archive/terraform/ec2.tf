#--------------------------------------------------------------
# 2SeC SIEM Infrastructure - EC2 Web Server
#--------------------------------------------------------------

#--------------------------------------------------------------
# Amazon Linux 2023 AMI 조회
#--------------------------------------------------------------
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

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

#--------------------------------------------------------------
# EC2 Web/App Server
#--------------------------------------------------------------
resource "aws_instance" "web" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.ec2_instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]
  key_name               = var.key_name
  iam_instance_profile   = aws_iam_instance_profile.ec2.name

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }

  user_data = <<-EOF
              #!/bin/bash
              set -ex

              # System update
              dnf update -y

              # Install nginx
              dnf install -y nginx
              systemctl start nginx
              systemctl enable nginx

              # Install CloudWatch Agent
              dnf install -y amazon-cloudwatch-agent

              # Create CloudWatch Agent configuration
              cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'CONFIG'
              {
                "agent": {
                  "metrics_collection_interval": 60,
                  "run_as_user": "cwagent"
                },
                "logs": {
                  "logs_collected": {
                    "files": {
                      "collect_list": [
                        {
                          "file_path": "/var/log/nginx/access.log",
                          "log_group_name": "/aws/ec2/web-server",
                          "log_stream_name": "{instance_id}/nginx-access",
                          "retention_in_days": 7
                        },
                        {
                          "file_path": "/var/log/nginx/error.log",
                          "log_group_name": "/aws/ec2/web-server",
                          "log_stream_name": "{instance_id}/nginx-error",
                          "retention_in_days": 7
                        },
                        {
                          "file_path": "/var/log/messages",
                          "log_group_name": "/aws/ec2/web-server",
                          "log_stream_name": "{instance_id}/syslog",
                          "retention_in_days": 7
                        }
                      ]
                    }
                  }
                }
              }
              CONFIG

              # Start CloudWatch Agent
              /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
                -a fetch-config \
                -m ec2 \
                -s \
                -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

              # Create sample app log directory
              mkdir -p /var/log/app
              chown nginx:nginx /var/log/app

              echo "Setup completed at $(date)" >> /var/log/setup.log
              EOF

  tags = {
    Name = "${var.project_name}-web-server"
    Role = "WebServer"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}
