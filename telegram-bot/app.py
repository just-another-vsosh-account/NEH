import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone


BOT_TOKEN = os.environ["TG_BOT_TOKEN"]
ALLOWED_USER_IDS_RAW = os.environ["TG_ALLOWED_USER_ID"]
BOT_NAME = os.environ.get("TG_BOT_NAME", "NEH Watcher")
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
KIBANA_PUBLIC_URL = os.environ.get("KIBANA_PUBLIC_URL", "http://localhost:5601")
POLL_TIMEOUT = int(os.environ.get("TG_POLL_TIMEOUT", "30"))
SLEEP_SECS = float(os.environ.get("TG_LOOP_SLEEP", "1.5"))
RECENT_LIMIT = int(os.environ.get("TG_RECENT_LIMIT", "5"))
ALERT_THRESHOLD = int(os.environ.get("TG_ALERT_THRESHOLD", "10"))
ALERT_WINDOW_SECONDS = int(os.environ.get("TG_ALERT_WINDOW_SECONDS", "300"))
ALERT_COOLDOWN_SECONDS = int(os.environ.get("TG_ALERT_COOLDOWN_SECONDS", "900"))
API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"


def parse_id_list(raw: str) -> set[int]:
    return {int(item.strip()) for item in raw.split(",") if item.strip()}


ALLOWED_USER_IDS = parse_id_list(ALLOWED_USER_IDS_RAW)
DEFAULT_ALERT_CHAT_ID = min(ALLOWED_USER_IDS) if ALLOWED_USER_IDS else 0
ALERT_CHAT_ID = int(os.environ.get("TG_ALERT_CHAT_ID", str(DEFAULT_ALERT_CHAT_ID)))


def tg_request(method: str, payload: dict | None = None) -> dict:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        f"{API_BASE}/{method}",
        data=data,
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=POLL_TIMEOUT + 10) as response:
        return json.loads(response.read().decode("utf-8"))


def es_request(path: str, payload: dict) -> dict:
    request = urllib.request.Request(
        f"{ELASTICSEARCH_URL}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def send_message(chat_id: int, text: str) -> None:
    tg_request(
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": True,
        },
    )


def format_status() -> str:
    now = datetime.now(timezone.utc)
    recent_window = (now - timedelta(minutes=15)).isoformat()

    payload = {
        "size": 0,
        "query": {
            "range": {
                "ts": {
                    "gte": recent_window,
                }
            }
        },
        "aggs": {
            "by_decision": {"terms": {"field": "decision.keyword", "size": 10}},
            "top_ip": {"terms": {"field": "remote_addr.keyword", "size": 1}},
        },
    }
    data = es_request("/neh-events-*/_search", payload)
    total = data["hits"]["total"]["value"]
    decision_buckets = data["aggregations"]["by_decision"]["buckets"]
    top_ip_buckets = data["aggregations"]["top_ip"]["buckets"]

    decision_lines = [
        f"- {bucket['key']}: {bucket['doc_count']}" for bucket in decision_buckets
    ] or ["- в этом окне решений нет"]
    top_ip = top_ip_buckets[0]["key"] if top_ip_buckets else "н/д"

    return "\n".join(
        [
            f"{BOT_NAME}",
            "",
            "Сводка за последние 15 минут:",
            f"- всего событий: {total}",
            f"- самый активный IP: {top_ip}",
            *decision_lines,
            "",
            f"Kibana: {KIBANA_PUBLIC_URL}",
        ]
    )


def format_recent_events() -> str:
    payload = {
        "size": RECENT_LIMIT,
        "sort": [{"ts": {"order": "desc"}}],
        "_source": ["ts", "remote_addr", "path", "uri", "event", "decision", "service"],
    }
    data = es_request("/neh-events-*/_search", payload)
    hits = data["hits"]["hits"]
    if not hits:
        return "В Elasticsearch пока нет событий."

    lines = ["Последние события:"]
    for hit in hits:
        src = hit["_source"]
        path = src.get("path") or src.get("uri") or "/"
        lines.append(
            f"- {src.get('ts', '?')} | {src.get('remote_addr', '?')} | "
            f"{src.get('event', src.get('service', 'event'))} | {src.get('decision', 'н/д')} | {path}"
        )
    return "\n".join(lines)


def format_alert_config() -> str:
    return "\n".join(
        [
            "Настройки алертов honeypot:",
            f"- порог: {ALERT_THRESHOLD} запросов",
            f"- окно: {ALERT_WINDOW_SECONDS} секунд",
            f"- cooldown: {ALERT_COOLDOWN_SECONDS} секунд",
            f"- чат назначения: {ALERT_CHAT_ID}",
        ]
    )


def check_honeypot_alerts(last_alerts: dict[str, float]) -> dict[str, float]:
    now = datetime.now(timezone.utc)
    recent_window = (now - timedelta(seconds=ALERT_WINDOW_SECONDS)).isoformat()

    payload = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"ts": {"gte": recent_window}}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"decision.keyword": "honeypot"}},
                                {"term": {"decision.keyword": "blocked"}},
                                {"term": {"service.keyword": "honeypot"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {
                    "field": "remote_addr.keyword",
                    "size": 20,
                    "min_doc_count": ALERT_THRESHOLD,
                },
                "aggs": {
                    "top_path": {"terms": {"field": "path.keyword", "size": 1}},
                    "top_uri": {"terms": {"field": "uri.keyword", "size": 1}},
                },
            }
        },
    }
    data = es_request("/neh-events-*/_search", payload)
    buckets = data["aggregations"]["by_ip"]["buckets"]
    now_ts = time.time()

    for bucket in buckets:
        ip = bucket["key"]
        if now_ts - last_alerts.get(ip, 0) < ALERT_COOLDOWN_SECONDS:
            continue

        path_bucket = bucket["top_path"]["buckets"]
        uri_bucket = bucket["top_uri"]["buckets"]
        target = "/"
        if path_bucket:
            target = path_bucket[0]["key"]
        elif uri_bucket:
            target = uri_bucket[0]["key"]

        send_message(
            ALERT_CHAT_ID,
            "\n".join(
                [
                    "Алерт honeypot",
                    f"- ip: {ip}",
                    f"- запросов: {bucket['doc_count']}",
                    f"- окно: последние {ALERT_WINDOW_SECONDS} секунд",
                    f"- основная цель: {target}",
                    f"- дашборд: {KIBANA_PUBLIC_URL}",
                ]
            ),
        )
        last_alerts[ip] = now_ts

    cutoff = now_ts - ALERT_COOLDOWN_SECONDS
    return {ip: ts for ip, ts in last_alerts.items() if ts >= cutoff}


def handle_command(chat_id: int, text: str) -> None:
    command = text.strip().split()[0].lower()

    if command in {"/start", "/help"}:
        send_message(
            chat_id,
            "\n".join(
                [
                    f"{BOT_NAME} подключён.",
                    "",
                    "Команды:",
                    "/status - сводка по последним SIEM-событиям",
                    "/recent - последние проиндексированные события",
                    "/alerts - текущие настройки алертов honeypot",
                    "/dashboard - URL Kibana",
                    "/help - эта справка",
                ]
            ),
        )
        return

    if command == "/status":
        send_message(chat_id, format_status())
        return

    if command == "/recent":
        send_message(chat_id, format_recent_events())
        return

    if command == "/dashboard":
        send_message(chat_id, f"Дашборд Kibana: {KIBANA_PUBLIC_URL}")
        return

    if command == "/alerts":
        send_message(chat_id, format_alert_config())
        return

    send_message(chat_id, "Неизвестная команда. Используйте /help.")


def main() -> None:
    offset = 0
    last_alerts: dict[str, float] = {}
    while True:
        try:
            response = tg_request(
                "getUpdates",
                {
                    "offset": offset,
                    "timeout": POLL_TIMEOUT,
                    "allowed_updates": ["message"],
                },
            )
            for update in response.get("result", []):
                offset = update["update_id"] + 1
                message = update.get("message") or {}
                chat = message.get("chat") or {}
                user = message.get("from") or {}
                text = message.get("text", "")

                if not text:
                    continue

                chat_id = int(chat.get("id", 0))
                user_id = int(user.get("id", 0))

                if user_id not in ALLOWED_USER_IDS:
                    send_message(chat_id, "Доступ запрещён.")
                    continue

                try:
                    handle_command(chat_id, text)
                except Exception as exc:
                    send_message(chat_id, f"Ошибка выполнения команды: {exc}")

            try:
                last_alerts = check_honeypot_alerts(last_alerts)
            except Exception as exc:
                print(f"alert check failed: {exc}", flush=True)
        except urllib.error.HTTPError as exc:
            print(f"telegram http error: {exc}", flush=True)
            time.sleep(SLEEP_SECS)
        except urllib.error.URLError as exc:
            print(f"network error: {exc}", flush=True)
            time.sleep(SLEEP_SECS)
        except Exception as exc:
            print(f"unexpected error: {exc}", flush=True)
            time.sleep(SLEEP_SECS)


if __name__ == "__main__":
    main()
