#!/bin/sh
set -eu

BASE_URL="${BASE_URL:-http://localhost:8080}"

echo "[1] прямой доступ без knock-последовательности"
curl -sS "${BASE_URL}/admin"
echo
echo

echo "[2] выполняем knock-последовательность"
curl -i -sS "${BASE_URL}/start" >/dev/null
curl -i -sS "${BASE_URL}/verify" >/dev/null
curl -i -sS "${BASE_URL}/grant" >/dev/null

echo "[3] доступ к защищённому ресурсу после успешной последовательности"
curl -sS "${BASE_URL}/admin"
echo
