data "aws_caller_identity" "current" {}

locals {
  # S3 버킷 이름은 글로벌 유니크여야 하므로 계정 ID를 포함해서 충돌 방지
  tfstate_bucket_name = "tfstate-${lower(var.project_name)}-${var.environment}-${data.aws_caller_identity.current.account_id}"
  tfstate_lock_table  = "${var.project_name}-${var.environment}-tf-lock"
}

resource "aws_s3_bucket" "tfstate" {
  bucket = local.tfstate_bucket_name

  tags = {
    Name        = local.tfstate_bucket_name
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "tfstate_bucket" {
  statement {
    sid    = "AllowAccountAccess"
    effect = "Allow"

    principals {
      type = "AWS"
      # 이 계정(Account ID)의 root를 principal로 지정
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]

    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/*",
    ]
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_bucket.json
}

resource "aws_dynamodb_table" "tf_lock" {
  name         = local.tfstate_lock_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name        = local.tfstate_lock_table
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}


