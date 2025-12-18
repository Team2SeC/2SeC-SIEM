#==============================================================================
# 2SeC SIEM - Logstash (OpenSearch native)
#==============================================================================

FROM opensearchproject/logstash-oss-with-opensearch-output-plugin:7.16.3

LABEL org.opencontainers.image.authors="2SeC SIEM Team"
LABEL org.opencontainers.image.version="1.0.2"
LABEL org.opencontainers.image.description="SIEM pipeline with Kinesis + OpenSearch"

# 필요한 것만 추가 (kinesis input)
RUN logstash-plugin install -J-Xmx2048m --version 2.3.0 logstash-input-kinesis

# 기본 pipeline 제거
RUN rm -f /usr/share/logstash/pipeline/logstash.conf

# 설정 복사
COPY --chown=logstash:logstash --chmod=644 config/logstash.config /usr/share/logstash/pipeline/
COPY --chown=logstash:logstash --chmod=644 config/logstash.yml /usr/share/logstash/config/
COPY --chown=logstash:logstash --chmod=644 config/pipelines.yml /usr/share/logstash/config/

WORKDIR /usr/share/logstash

CMD ["logstash", "--config.reload.automatic"]