#!/bin/bash
#==============================================================================
# 2SeC SIEM - ECR Push Only Script (빌드 없이 푸시만)
#==============================================================================

set -e

PROJECT_NAME="2sec"
AWS_REGION="ap-northeast-2"
ECR_REPOSITORY="${PROJECT_NAME}-logstash-custom"
IMAGE_TAG="${1:-latest}"

echo "⬆️ Pushing existing image to ECR..."

# ECR Repository URL 가져오기
ECR_URL=$(aws ecr describe-repositories --repository-names $ECR_REPOSITORY --region $AWS_REGION --query 'repositories[0].repositoryUri' --output text)

# ECR 로그인
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR_URL

# 태깅 및 푸시
docker tag $ECR_REPOSITORY:$IMAGE_TAG $ECR_URL:$IMAGE_TAG
docker push $ECR_URL:$IMAGE_TAG

echo "✅ Push completed: $ECR_URL:$IMAGE_TAG"