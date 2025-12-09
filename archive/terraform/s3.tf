#--------------------------------------------------------------
# 2SeC SIEM Infrastructure - S3 Buckets
#--------------------------------------------------------------

#--------------------------------------------------------------
# Random ID for unique bucket names
#--------------------------------------------------------------
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

#--------------------------------------------------------------
# OpenSearch Snapshot Bucket
#--------------------------------------------------------------
resource "aws_s3_bucket" "snapshot" {
  bucket = "${var.project_name}-opensearch-snapshot-${random_id.bucket_suffix.hex}"

  tags = {
    Name    = "${var.project_name}-opensearch-snapshot"
    Purpose = "OpenSearch Snapshot Repository"
  }
}

# 버전 관리 활성화
resource "aws_s3_bucket_versioning" "snapshot" {
  bucket = aws_s3_bucket.snapshot.id

  versioning_configuration {
    status = "Enabled"
  }
}

# 암호화 설정
resource "aws_s3_bucket_server_side_encryption_configuration" "snapshot" {
  bucket = aws_s3_bucket.snapshot.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 퍼블릭 액세스 차단
resource "aws_s3_bucket_public_access_block" "snapshot" {
  bucket = aws_s3_bucket.snapshot.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 라이프사이클 정책 (1년 보관 후 삭제)
resource "aws_s3_bucket_lifecycle_configuration" "snapshot" {
  bucket = aws_s3_bucket.snapshot.id

  rule {
    id     = "delete-after-1-year"
    status = "Enabled"

    expiration {
      days = var.snapshot_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

#--------------------------------------------------------------
# OpenSearch Snapshot IAM Role
#--------------------------------------------------------------
resource "aws_iam_role" "opensearch_snapshot" {
  name = "${var.project_name}-opensearch-snapshot-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "es.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-opensearch-snapshot-role"
  }
}

resource "aws_iam_role_policy" "opensearch_snapshot" {
  name = "${var.project_name}-opensearch-snapshot-policy"
  role = aws_iam_role.opensearch_snapshot.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.snapshot.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.snapshot.arn}/*"
      }
    ]
  })
}
