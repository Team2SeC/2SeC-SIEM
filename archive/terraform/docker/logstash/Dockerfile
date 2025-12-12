#==============================================================================
# 2SeC SIEM - Custom Logstash Docker Image
# Base: Official Logstash 8.11.0 + Kinesis Plugin + Custom Configs
#==============================================================================

FROM docker.elastic.co/logstash/logstash:8.11.0

# 메타데이터
LABEL maintainer="2SeC SIEM Team"
LABEL version="1.0.0"
LABEL description="Custom Logstash for SIEM pipeline with Kinesis support"

# root로 전환하여 플러그인 설치
USER root

# 필요한 패키지 설치 및 업데이트
RUN yum update -y && \
    yum install -y curl && \
    yum clean all

# logstash 사용자로 전환
USER logstash

# Kinesis 플러그인 설치
RUN logstash-plugin install logstash-input-kinesis && \
    logstash-plugin install logstash-output-opensearch && \
    logstash-plugin install logstash-output-cloudwatch_logs

# 플러그인 리스트 확인 (디버깅용)
RUN logstash-plugin list --verbose | grep -E "(kinesis|opensearch|cloudwatch)"

# 기본 설정 파일들 제거
RUN rm -f /usr/share/logstash/pipeline/logstash.conf

# 커스텀 설정 파일들 복사
COPY --chown=logstash:logstash config/logstash.conf /usr/share/logstash/pipeline/logstash.conf
COPY --chown=logstash:logstash config/logstash.yml /usr/share/logstash/config/logstash.yml
COPY --chown=logstash:logstash config/pipelines.yml /usr/share/logstash/config/pipelines.yml

# 설정 파일 권한 설정
RUN chmod 644 /usr/share/logstash/pipeline/logstash.conf && \
    chmod 644 /usr/share/logstash/config/logstash.yml && \
    chmod 644 /usr/share/logstash/config/pipelines.yml

# 헬스체크 설정
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:9600/_node/stats || exit 1

# 포트 노출
EXPOSE 9600

# 작업 디렉토리 설정
WORKDIR /usr/share/logstash

# 시작 명령어 (환경변수 대체 활성화)
CMD ["logstash", "-f", "/usr/share/logstash/pipeline/logstash.conf", "--config.reload.automatic"]