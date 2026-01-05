# Sigma Rules for OpenSearch Security Analytics

This folder contains custom Sigma rules derived from `detection-rules/docs`.

Import steps (Dashboards):
1) Security Analytics > Rules > Import Rules
2) Select all YAML files under `detection-rules/sigma/`
3) Assign Log Type: Apache Access
4) Create or attach to a detector and enable it

Notes:
- These rules are event-based (no threshold aggregation).
- Behavior thresholds should be handled by Alerting monitors or Security Analytics detectors.
