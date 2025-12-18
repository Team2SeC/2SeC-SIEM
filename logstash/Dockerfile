#==============================================================================
# 2SeC SIEM - Logstash (OpenSearch native)
#==============================================================================

FROM opensearchproject/logstash-oss-with-opensearch-output-plugin:7.16.3

LABEL org.opencontainers.image.authors="2SeC SIEM Team"
LABEL org.opencontainers.image.version="1.0.2"
LABEL org.opencontainers.image.description="SIEM pipeline with Kinesis + OpenSearch"

# 플러그인 설치는 쓰기 권한 때문에 root로 수행하는 편이 안전
USER root

# Logstash 7.x에서는 -J 옵션 대신 환경변수로 JVM 힙을 올림
# (plugin install에서도 적용되도록 LS_JAVA_OPTS + JAVA_OPTS 둘 다 설정)
ENV LS_JAVA_OPTS="-Xms1g -Xmx2g"
ENV JAVA_OPTS="-Xms1g -Xmx2g"

# 필요한 것만 추가 (kinesis input)
RUN /usr/share/logstash/bin/logstash-plugin install --version 2.1.2 logstash-input-kinesis

# 기본 pipeline 제거
RUN rm -f /usr/share/logstash/pipeline/logstash.conf

# 설정 복사
COPY --chown=logstash:logstash --chmod=644 config/logstash.config /usr/share/logstash/pipeline/
COPY --chown=logstash:logstash --chmod=644 config/logstash.yml /usr/share/logstash/config/
COPY --chown=logstash:logstash --chmod=644 config/pipelines.yml /usr/share/logstash/config/

# 런타임은 logstash 유저로
USER logstash

WORKDIR /usr/share/logstash
CMD ["logstash", "--config.reload.automatic"]