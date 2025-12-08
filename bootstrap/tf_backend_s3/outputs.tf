output "tfstate_bucket" {
  description = "Terraform state를 저장할 S3 버킷 이름"
  value       = aws_s3_bucket.tfstate.bucket
}

output "tfstate_lock_table" {
  description = "Terraform state lock을 위한 DynamoDB 테이블 이름"
  value       = aws_dynamodb_table.tf_lock.name
}


