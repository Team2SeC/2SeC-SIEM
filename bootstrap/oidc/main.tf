data "aws_caller_identity" "current" {}

resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com",
  ]
}

locals {
  github_subs = [
    "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/main",
    "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/dev",
  ]
}

data "aws_iam_policy_document" "github_actions_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.github_subs
    }
  }
}

resource "aws_iam_role" "github_actions" {
  name               = var.oidc_role_name
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume_role.json
}

# GitHub Actions용 Terraform Role에 인프라(VPC/EC2 등) 관련 권한을 부여
resource "aws_iam_role_policy_attachment" "github_actions_vpc" {
  role       = aws_iam_role.github_actions.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonVPCFullAccess"
}

resource "aws_iam_role_policy_attachment" "github_actions_ec2" {
  role       = aws_iam_role.github_actions.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

# Terraform backend(S3 + DynamoDB) 접근을 위한 최소 권한 부여
data "aws_iam_policy_document" "github_actions_tf_backend" {
  # S3 버킷 메타데이터/리스트 조회
  statement {
    effect = "Allow"

    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]

    # tfstate-${lower(project_name)}-${environment}-${account_id} 패턴의 dev/prod 버킷 모두 허용
    resources = [
      "arn:aws:s3:::tfstate-${lower(var.project_name)}-*-${data.aws_caller_identity.current.account_id}",
    ]
  }

  # S3 객체(tfstate) 읽기/쓰기/삭제
  statement {
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]

    resources = [
      "arn:aws:s3:::tfstate-${lower(var.project_name)}-*-${data.aws_caller_identity.current.account_id}/*",
    ]
  }

  # DynamoDB Lock 테이블 접근
  statement {
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
    ]

    # ${project_name}-${environment}-tf-lock 패턴의 dev/prod 테이블 모두 허용
    resources = [
      "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.project_name}-*-tf-lock",
    ]
  }
}

resource "aws_iam_policy" "github_actions_tf_backend" {
  name        = "${var.project_name}-tf-backend"
  description = "Terraform S3 backend 및 DynamoDB lock 테이블 접근용 최소 권한 정책"
  policy      = data.aws_iam_policy_document.github_actions_tf_backend.json
}

resource "aws_iam_role_policy_attachment" "github_actions_tf_backend" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.github_actions_tf_backend.arn
}

# IAM(EC2 Role/Instance Profile) 및 CloudWatch Logs(DVWA 로그 그룹) 관리를 위한 최소 권한 부여
data "aws_iam_policy_document" "github_actions_iam_cloudwatch" {
  # EC2용 IAM Role 및 Instance Profile 생성/관리
  statement {
    effect = "Allow"

    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:CreateInstanceProfile",
      "iam:DeleteInstanceProfile",
      "iam:AddRoleToInstanceProfile",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:GetRole",
      "iam:TagRole",
      "iam:PassRole",
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-${var.environment}-ec2-role",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/${var.project_name}-${var.environment}-ec2-profile",
    ]
  }

  # DVWA용 CloudWatch Logs 그룹(/aws/ec2/dvwa-web-server) 관리
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
      "logs:TagResource",
      "logs:PutRetentionPolicy",
    ]

    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/dvwa-web-server",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/dvwa-web-server:*",
    ]
  }

  # 로그 그룹 리스트 조회(DescribeLogGroups)는 리소스 레벨 제어가 어려우므로 계정 전체에 대해 허용
  statement {
    effect = "Allow"

    actions = [
      "logs:DescribeLogGroups",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_policy" "github_actions_iam_cloudwatch" {
  name        = "${var.project_name}-github-actions-iam-cloudwatch"
  description = "infra/dev EC2 IAM Role/InstanceProfile 및 DVWA CloudWatch Logs 그룹 관리를 위한 최소 권한 정책"
  policy      = data.aws_iam_policy_document.github_actions_iam_cloudwatch.json
}

resource "aws_iam_role_policy_attachment" "github_actions_iam_cloudwatch" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.github_actions_iam_cloudwatch.arn
}

# CI Role이 자기 자신(github-actions-terraform-role)에 대한 IAM 변경을 하지 못하도록 명시적 Deny 정책 추가
resource "aws_iam_role_policy" "github_actions_deny_self" {
  name = "${var.project_name}-github-actions-deny-self"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyChangeSelf"
        Effect = "Deny"
        Action = [
          "iam:*"
        ]
        Resource = aws_iam_role.github_actions.arn
      }
    ]
  })
}



