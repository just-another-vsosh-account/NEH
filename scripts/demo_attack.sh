#!/bin/sh
set -eu

BASE_URL="${BASE_URL:-http://localhost:8080}"

for path in /phpmyadmin /backup /verify /manager /console; do
  echo "[*] запрашиваем ${path}"
  curl -sS -A "neh-demo-attacker" "${BASE_URL}${path}" >/dev/null || true
done

echo "симуляция атаки завершена"
