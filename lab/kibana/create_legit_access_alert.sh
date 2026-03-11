#!/bin/sh
set -eu

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"

curl -sS \
  -X POST "${KIBANA_URL}/api/alerting/rule" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "name": "NEH: легитимный доступ",
    "rule_type_id": ".index-threshold",
    "consumer": "stackAlerts",
    "schedule": { "interval": "1m" },
    "tags": ["neh", "legit", "demo"],
    "notify_when": "onActionGroupChange",
    "actions": [],
    "params": {
      "index": ["neh-events-*"],
      "timeField": "ts",
      "aggType": "count",
      "groupBy": "all",
      "thresholdComparator": ">",
      "threshold": [0],
      "timeWindowSize": 5,
      "timeWindowUnit": "m",
      "filterKuery": "event: \"knock_success\" or event: \"protected_allowed\""
    }
  }'

echo
