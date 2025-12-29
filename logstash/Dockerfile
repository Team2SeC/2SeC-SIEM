FROM docker.elastic.co/logstash/logstash:9.2.3

LABEL org.opencontainers.image.authors="2SeC SIEM Team"
LABEL org.opencontainers.image.description="Minimal Logstash: Kinesis to OpenSearch"

USER root

#ENV LS_JAVA_OPTS="-Xms256m -Xmx512m"

RUN /usr/share/logstash/bin/logstash-plugin install logstash-output-opensearch

RUN /usr/share/logstash/bin/logstash-plugin install --version 2.3.0 logstash-input-kinesis

RUN /usr/share/logstash/bin/logstash-plugin install logstash-codec-gzip

# 기본 pipeline 제거
RUN rm -f /usr/share/logstash/pipeline/logstash.conf

# 설정 파일 복사
COPY --chown=logstash:logstash --chmod=644 config/logstash.config /usr/share/logstash/pipeline/
COPY --chown=logstash:logstash --chmod=644 config/logstash.yml /usr/share/logstash/config/
COPY --chown=logstash:logstash --chmod=644 config/pipelines.yml /usr/share/logstash/config/

USER logstash

WORKDIR /usr/share/logstash
