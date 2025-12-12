#!/bin/bash
#==============================================================================
# 2SeC SIEM - Logstash Docker Build Script
#==============================================================================

set -e

# 변수 설정
PROJECT_NAME="2sec"
AWS_REGION="ap-northeast-2"
ECR_REPOSITORY="${PROJECT_NAME}-logstash-custom"
IMAGE_TAG="${1:-latest}"

echo "🚀 Starting Logstash Docker build..."

# AWS CLI 설치 확인
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found. Please install AWS CLI."
    exit 1
fi

# Docker 설치 확인
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker."
    exit 1
fi

# ECR 로그인
echo "🔐 Logging in to Amazon ECR..."
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $(aws sts get-caller-identity --query Account --output text).dkr.ecr.$AWS_REGION.amazonaws.com

# ECR Repository URL 가져오기
ECR_URL=$(aws ecr describe-repositories --repository-names $ECR_REPOSITORY --region $AWS_REGION --query 'repositories[0].repositoryUri' --output text 2>/dev/null || echo "")

if [ -z "$ECR_URL" ]; then
    echo "❌ ECR repository not found. Please run 'terraform apply' first."
    exit 1
fi

echo "📦 Building Docker image..."
docker build -t $ECR_REPOSITORY:$IMAGE_TAG .

echo "🏷️ Tagging image for ECR..."
docker tag $ECR_REPOSITORY:$IMAGE_TAG $ECR_URL:$IMAGE_TAG

echo "⬆️ Pushing to ECR..."
docker push $ECR_URL:$IMAGE_TAG

echo "✅ Build and push completed successfully!"
echo "📋 Image URI: $ECR_URL:$IMAGE_TAG"
echo ""
echo "🔧 Next steps:"
echo "1. Update ECS task definition to use: $ECR_URL:$IMAGE_TAG"
echo "2. Deploy ECS service: aws ecs update-service --cluster 2sec-cluster --service 2sec-logstash-service --force-new-deployment"