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
    "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/dev"
    #"repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/feature/*",
    #"repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/feat/*"
    #"repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/fix/*",
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

# IAM(EC2/ECS/OpenSearch Role) 및 CloudWatch Logs 관리를 위한 최소 권한 부여
data "aws_iam_policy_document" "github_actions_iam_cloudwatch" {
  # EC2, ECS, OpenSearch용 IAM Role 및 Instance Profile 생성/관리
  statement {
    effect = "Allow"

    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:CreateInstanceProfile",
      "iam:DeleteInstanceProfile",
      "iam:AddRoleToInstanceProfile",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:ListInstanceProfilesForRole",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:GetInstanceProfile",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:TagInstanceProfile",
      "iam:PassRole",
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-${var.environment}-ec2-role",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/${var.project_name}-${var.environment}-ec2-profile",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-${var.environment}-cw-to-kinesis",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-${var.environment}-logstash-*-role",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-${var.environment}-opensearch-admin-role",
    ]
  }

  # 프로젝트 관련 CloudWatch Logs 그룹 관리 (DVWA, Logstash, OpenSearch)
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
      "logs:DescribeSubscriptionFilters",
      "logs:TagResource",
      "logs:PutRetentionPolicy",
      "logs:PutSubscriptionFilter",
      "logs:DeleteSubscriptionFilter",
      "logs:ListTagsForResource",
    ]

    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/dvwa-web-server",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/dvwa-web-server:*",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/${var.project_name}/${var.environment}/logstash",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/${var.project_name}/${var.environment}/logstash:*",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/opensearch/*",
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

# Kinesis Data Stream(웹 로그용) 관리를 위한 최소 권한 정책
data "aws_iam_policy_document" "github_actions_kinesis" {
  statement {
    effect = "Allow"

    actions = [
      "kinesis:CreateStream",
      "kinesis:DeleteStream",
      "kinesis:DescribeStream",
      "kinesis:DescribeStreamSummary",
      "kinesis:ListShards",
      "kinesis:AddTagsToStream",
      "kinesis:IncreaseStreamRetentionPeriod",
      "kinesis:DecreaseStreamRetentionPeriod",
      "kinesis:ListTagsForStream",
      "kinesis:StartStreamEncryption",
      "kinesis:StopStreamEncryption",
      "kinesis:UpdateShardCount",
    ]

    resources = [
      "arn:aws:kinesis:${var.aws_region}:${data.aws_caller_identity.current.account_id}:stream/${var.project_name}-${var.environment}-web-logs",
    ]
  }
}

resource "aws_iam_policy" "github_actions_kinesis" {
  name        = "${var.project_name}-github-actions-kinesis"
  description = "infra/dev Kinesis Data Stream(web logs) 관리를 위한 최소 권한 정책"
  policy      = data.aws_iam_policy_document.github_actions_kinesis.json
}

resource "aws_iam_role_policy_attachment" "github_actions_kinesis" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.github_actions_kinesis.arn
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

# ECR(ECS Logstash 이미지) 및 ECS(Fargate 서비스) 관리를 위한 권한 정책
data "aws_iam_policy_document" "github_actions_ecr_ecs" {
  # ECR 로그인 토큰 발급은 리소스 수준 제어가 불가능하므로 계정 전체에 대해 허용
  statement {
    effect = "Allow"

    actions = [
      "ecr:GetAuthorizationToken",
    ]

    resources = ["*"]
  }

  # 특정 ECR 리포지토리(로그스태시용)에 대한 이미지 Push/관리 권한
  statement {
    effect = "Allow"

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:ListImages",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]

    resources = [
      "arn:aws:ecr:${var.aws_region}:${data.aws_caller_identity.current.account_id}:repository/${lower(var.project_name)}-${var.environment}-logstash",
    ]
  }

  # ECS 클러스터/서비스/태스크 정의 관리에 필요한 권한
  # - Terraform에서 infra/dev ECS 리소스를 생성/수정
  # - (선택) GitHub Actions에서 update-service로 롤링 배포 트리거
  statement {
    effect = "Allow"

    actions = [
      "ecs:CreateCluster",
      "ecs:DescribeClusters",
      "ecs:ListClusters",
      "ecs:DeleteCluster",
      "ecs:RegisterTaskDefinition",
      "ecs:DeregisterTaskDefinition",
      "ecs:DescribeTaskDefinition",
      "ecs:ListTaskDefinitions",
      "ecs:CreateService",
      "ecs:UpdateService",
      "ecs:DeleteService",
      "ecs:DescribeServices",
      "ecs:ListServices",
      "ecs:UpdateServicePrimaryTaskSet",
      "ecs:TagResource",
      "ecs:UntagResource"
    ]

    resources = ["*"]
  }

  # ECS 태스크/서비스에서 사용할 Logstash 실행/태스크 Role에 대한 PassRole 허용
  statement {
    effect = "Allow"

    actions = [
      "iam:PassRole",
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-*-logstash-*-role",
    ]
  }
}

resource "aws_iam_policy" "github_actions_ecr_ecs" {
  name        = "${var.project_name}-github-actions-ecr-ecs"
  description = "infra/dev Logstash용 ECR 및 ECS(Fargate) 관리를 위한 권한 정책"
  policy      = data.aws_iam_policy_document.github_actions_ecr_ecs.json
}

resource "aws_iam_role_policy_attachment" "github_actions_ecr_ecs" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.github_actions_ecr_ecs.arn
}

# OpenSearch 도메인 관리를 위한 최소 권한 정책
data "aws_iam_policy_document" "github_actions_opensearch" {
  # OpenSearch 도메인 생성/수정/삭제/조회
  statement {
    effect = "Allow"
    actions = [
      "es:CreateDomain",
      "es:DeleteDomain",
      "es:DescribeDomain",
      "es:UpdateDomain",
      "es:UpdateDomainConfig",
      "es:AddTags",
      "es:RemoveTags",
      "es:ListTags",
      "es:ListDomainNames",
      "es:DescribeElasticsearchDomainConfig",
      "es:ESHttpGet",
      "es:ESHttpPost",
      "es:ESHttpPut"
    ]
    resources = [
      "arn:aws:es:${var.aws_region}:${data.aws_caller_identity.current.account_id}:domain/siem-*"
    ]
  }

  # Service Linked Role 조회 (OpenSearch가 내부적으로 사용, 계정당 1회만 생성되므로 별도 관리)
  # 첫 OpenSearch 도메인 생성 시 AWS가 자동으로 생성하거나, 수동으로 생성 필요:
  # aws iam create-service-linked-role --aws-service-name opensearchservice.amazonaws.com
  statement {
    effect = "Allow"
    actions = [
      "iam:GetRole"
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/opensearchservice.amazonaws.com/*"
    ]
  }

  # CloudWatch Logs Resource Policy (OpenSearch가 로그를 게시하기 위해 필요)
  statement {
    effect = "Allow"
    actions = [
      "logs:PutResourcePolicy",
      "logs:DeleteResourcePolicy",
      "logs:DescribeResourcePolicies"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "github_actions_opensearch" {
  name        = "${var.project_name}-github-actions-opensearch"
  description = "infra/dev OpenSearch 도메인 관리를 위한 권한 정책"
  policy      = data.aws_iam_policy_document.github_actions_opensearch.json
}

resource "aws_iam_role_policy_attachment" "github_actions_opensearch" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.github_actions_opensearch.arn
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



