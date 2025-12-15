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
# 이전에는 오픈서치, 클라우드워치 설치가 있었는데 클라우드워치는 내장되어있어서 오류나서 제거했고, 오픈서치는 무한로딩 걸려서 우선 제거하고 필요한 키네시스만 포함했습니다.
# 버전 고정에서 에러가 계속 떴어서 조금 수정했습니다. 
# 근데 하드코딩으로 안 하고 환경변수로 하는거도 되긴 하는데 어차피 버전이 바뀐다면 문법 오류나는거를 고치는거에서 굳이 고정한 의미가 사라져서 이전 피드백이 반영 안 되는거라 판단되어 이렇게 썼습니다.

# 기본 설정 파일들 제거
RUN rm -f /usr/share/logstash/pipeline/logstash.conf

# 설정 파일 복사 (권한 통합 - 합쳐서 쓸 수 있어서 하나로 통합)
COPY --chown=logstash:logstash --chmod=644 config/logstash.config /usr/share/logstash/pipeline/
COPY --chown=logstash:logstash --chmod=644 config/logstash.yml /usr/share/logstash/config/
COPY --chown=logstash:logstash --chmod=644 config/pipelines.yml /usr/share/logstash/config/

# 포트 노출
EXPOSE 9600

# 작업 디렉토리 설정
WORKDIR /usr/share/logstash

# pipelines.yml을 사용하도록 수정 (-f 옵션 제거)
CMD ["logstash", "--config.reload.automatic"]