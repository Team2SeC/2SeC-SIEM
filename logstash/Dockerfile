#==============================================================================
# 2SeC SIEM - Custom Logstash Docker Image
# Base: Official Logstash 8.11.0 + Kinesis Plugin + Custom Configs
#==============================================================================

FROM docker.elastic.co/logstash/logstash:8.11.0

# 메타데이터 (표준 준수로 자동화 도구들이 인식하기 편하게 수정)
LABEL org.opencontainers.image.authors="2SeC SIEM Team"
LABEL org.opencontainers.image.version="1.0.1"
LABEL org.opencontainers.image.description="SIEM pipeline with Kinesis support"

# Kinesis 플러그인 설치 (버전 고정으로 재현성 보장)
RUN logstash-plugin install --version 2.3.0 logstash-input-kinesis

# 기본 설정 파일들 제거
RUN rm -f /usr/share/logstash/pipeline/logstash.conf

# 설정 파일 복사 (권한 통합 - 합쳐서 쓸 수 있어서 하나로 통합)
COPY --chown=logstash:logstash --chmod=644 config/logstash.config /usr/share/logstash/pipeline/
COPY --chown=logstash:logstash --chmod=644 config/logstash.yml /usr/share/logstash/config/
COPY --chown=logstash:logstash --chmod=644 config/pipelines.yml /usr/share/logstash/config/

# 작업 디렉토리 설정
WORKDIR /usr/share/logstash

# 
CMD ["logstash", "--config.reload.automatic"]