#!/bin/sh
set -eu

BASE_URL="${BASE_URL:-http://localhost:8080}"

echo "[*] прямой запрос /admin"
curl -sS "${BASE_URL}/admin"
echo
echo

echo "[*] knock-последовательность"
curl -sS -o /dev/null -w "start: %{http_code}\n" "${BASE_URL}/start"
curl -sS -o /dev/null -w "verify: %{http_code}\n" "${BASE_URL}/verify"
curl -sS -o /dev/null -w "grant: %{http_code}\n" "${BASE_URL}/grant"

echo
echo "[*] /admin после разблокировки"
curl -sS "${BASE_URL}/admin"
echo

echo
echo "[*] пример последних строк лога honeypot"
docker compose exec -T gateway sh -lc "tail -n 10 /var/log/neh/nginx-events.jsonl || true"
