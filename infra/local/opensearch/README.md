# Local OpenSearch (lightweight)

단일 노드 OpenSearch + Dashboards를 로컬에서 빠르게 올려 엔드포인트만 확보하기 위한 구성입니다. 보안 플러그인은 비활성화되어 있어 개발/테스트 전용으로만 사용하세요.

## 요구 사항
- Docker + Docker Compose
- 포트 9200(OpenSearch), 5601(Dashboards)이 비어 있어야 합니다.

## 실행
```bash
cd infra/local/opensearch
# 백그라운드 실행
docker compose up -d
# 상태 확인
curl http://localhost:9200
```

## 중지/정리
```bash
cd infra/local/opensearch
# 컨테이너만 중지/삭제
docker compose down
# 볼륨까지 삭제하고 초기화할 때
docker compose down -v
```

- OpenSearch REST 엔드포인트: http://localhost:9200
- OpenSearch Dashboards: http://localhost:5601
- 데이터는 `infra/local/opensearch/data`에 저장되며, `docker compose down -v` 시 삭제됩니다.

## 설정 참고
- 메모리: `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m`
- 보안 플러그인 비활성화: `plugins.security.disabled=true`
- 단일 노드 모드: `discovery.type=single-node`
