#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

: "${OPENSEARCH_URL:?Set OPENSEARCH_URL, e.g. https://your-domain.region.es.amazonaws.com}"

curl_json() {
  local method="$1"
  local url="$2"
  local file="$3"
  if [ -n "${OPENSEARCH_USER:-}" ]; then
    : "${OPENSEARCH_PASS:?Set OPENSEARCH_PASS with OPENSEARCH_USER}"
    curl -sS -X "${method}" "${url}" \
      -H 'Content-Type: application/json' \
      -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" \
      --data-binary "@${file}"
    return
  fi

  if [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ] && [ -n "${AWS_REGION:-}" ]; then
    if [ -n "${AWS_SESSION_TOKEN:-}" ]; then
      curl -sS -X "${method}" "${url}" \
        -H 'Content-Type: application/json' \
        --aws-sigv4 "aws:amz:${AWS_REGION}" -u "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
        -H "x-amz-security-token: ${AWS_SESSION_TOKEN}" \
        --data-binary "@${file}"
    else
      curl -sS -X "${method}" "${url}" \
        -H 'Content-Type: application/json' \
        --aws-sigv4 "aws:amz:${AWS_REGION}" -u "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
        --data-binary "@${file}"
    fi
    return
  fi

  curl -sS -X "${method}" "${url}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${file}"
}

echo "[1/3] Applying ingest pipeline..."
curl_json PUT "${OPENSEARCH_URL}/_ingest/pipeline/2sec-siem-classification-v1" \
  "${ROOT_DIR}/detection-rules/opensearch-ingest-classification-pipeline.json"

echo "[2/3] Applying index template..."
curl_json PUT "${OPENSEARCH_URL}/_index_template/2sec-siem-template-v1" \
  "${ROOT_DIR}/detection-rules/opensearch-index-template.json"

echo "[3/3] Creating alerting monitors..."
for monitor in "${ROOT_DIR}/detection-rules/monitors"/*.json; do
  echo "- ${monitor}"
  curl_json POST "${OPENSEARCH_URL}/_plugins/_alerting/monitors" "${monitor}"
done

echo "Done."
