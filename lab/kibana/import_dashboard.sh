#!/bin/sh
set -eu

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
FILE="${FILE:-lab/kibana/neh-dashboard.ndjson}"

curl -sS \
  -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -F "file=@${FILE}"

echo
