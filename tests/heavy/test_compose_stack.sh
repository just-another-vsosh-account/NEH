#!/bin/sh
set -eu

wait_http() {
  url="$1"
  tries="${2:-60}"
  i=0
  while [ "$i" -lt "$tries" ]; do
    if curl -fsS "$url" >/tmp/neh_http.out 2>/dev/null; then
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  echo "service did not become ready: $url" >&2
  return 1
}

cleanup() {
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT

docker compose up --build -d gateway honeypot protected-app
wait_http "http://localhost:8080/"

curl -fsS http://localhost:8080/admin >/tmp/neh_admin_honeypot.html
grep -q "Административная консоль" /tmp/neh_admin_honeypot.html

curl -fsS -o /dev/null -w "%{http_code}" http://localhost:8080/start | grep -q '^204$'
curl -fsS -o /dev/null -w "%{http_code}" http://localhost:8080/verify | grep -q '^204$'
curl -fsS -o /dev/null -w "%{http_code}" http://localhost:8080/grant | grep -q '^204$'
curl -fsS http://localhost:8080/admin >/tmp/neh_admin_protected.html
grep -q "Рабочая область администратора" /tmp/neh_admin_protected.html

docker compose exec -T gateway sh -lc "test -s /var/log/neh/nginx-events.jsonl"
docker compose exec -T honeypot sh -lc "test -s /var/log/neh/honeypot.jsonl"

docker compose --profile nginx-module up --build -d nginx honeypot protected-app
wait_http "http://localhost:8081/"

curl -fsS http://localhost:8081/admin >/tmp/neh_nginx_admin_honeypot.html
grep -q "Административная консоль" /tmp/neh_nginx_admin_honeypot.html

curl -fsS -o /dev/null -w "%{http_code}" http://localhost:8081/start | grep -q '^204$'
curl -fsS -o /dev/null -w "%{http_code}" http://localhost:8081/verify | grep -q '^204$'
curl -fsS -o /dev/null -w "%{http_code}" http://localhost:8081/grant | grep -q '^204$'
curl -fsS http://localhost:8081/admin >/tmp/neh_nginx_admin_protected.html
grep -q "Рабочая область администратора" /tmp/neh_nginx_admin_protected.html
