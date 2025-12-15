FROM docker.elastic.co/logstash/logstash:8.11.2

# 필요한 플러그인 설치: Kinesis 입력, OpenSearch 출력
RUN logstash-plugin install --no-verify logstash-input-kinesis logstash-output-opensearch

# 파이프라인 복사
COPY pipeline/ /usr/share/logstash/pipeline/

# 기본 설정은 그대로 두고 파이프라인만 사용
