#==============================================================================
# 2SeC SIEM - Custom Logstash Docker Image
# Base: Official Logstash 8.11.0 + Kinesis Plugin + Custom Configs
#==============================================================================

FROM docker.elastic.co/logstash/logstash:8.11.0

# 메타데이터
LABEL maintainer="2SeC SIEM Team"
LABEL version="1.0.1"
LABEL description="Custom Logstash for SIEM pipeline with Kinesis support"

# root로 전환하여 패키지 설치
USER root

# 필수 패키지 설치 (재현성 보장을 위해 yum update 제거)
RUN yum clean all && \
    rm -rf /var/cache/yum

# logstash 사용자로 전환
USER logstash

# Kinesis 플러그인 설치 (버전 고정으로 재현성 보장)
RUN logstash-plugin install --version 6.0.4 logstash-input-kinesis && \
    logstash-plugin install --version 2.0.2 logstash-output-opensearch && \
    logstash-plugin install --version 3.0.8 logstash-output-cloudwatch_logs

# 기본 설정 파일들 제거
RUN rm -f /usr/share/logstash/pipeline/logstash.conf

# 커스텀 설정 파일들 복사
COPY --chown=logstash:logstash config/logstash.config /usr/share/logstash/pipeline/logstash.config
COPY --chown=logstash:logstash config/logstash.yml /usr/share/logstash/config/logstash.yml
COPY --chown=logstash:logstash config/pipelines.yml /usr/share/logstash/config/pipelines.yml

# 설정 파일 권한 설정
RUN chmod 644 /usr/share/logstash/pipeline/logstash.config && \
    chmod 644 /usr/share/logstash/config/logstash.yml && \
    chmod 644 /usr/share/logstash/config/pipelines.yml

# 포트 노출
EXPOSE 9600

# 작업 디렉토리 설정
WORKDIR /usr/share/logstash

# pipelines.yml을 사용하도록 수정 (-f 옵션 제거)
CMD ["logstash", "--config.reload.automatic"]