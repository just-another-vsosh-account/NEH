#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = Path(__file__).resolve().parent / "templates"


DEFAULTS = {
    "gateway_http_port": "8080",
    "nginx_http_port": "8081",
    "nginx_knock_ports": "18081,18082,18083",
    "honeypot_port": "5000",
    "protected_app_port": "5001",
    "elasticsearch_port": "9200",
    "kibana_port": "5601",
    "elastic_version": "8.13.4",
    "curl_image_version": "8.11.1",
    "kibana_encryption_key": "neh-demo-kibana-encryption-key-32c",
    "neh_knock_type": "uri",
    "neh_sequence": "/start,/verify,/grant",
    "neh_port_sequence": "18081,18082,18083",
    "neh_protected_uri": "/admin",
    "neh_honeypot_uri": "/__neh_honeypot__",
    "neh_cookie_name": "neh_access",
    "neh_bind_host": "on",
    "neh_timeout": "30s",
    "neh_access_window": "60s",
    "neh_block_threshold": "4",
    "neh_block_duration": "120s",
    "neh_randomize_sequence": "off",
    "neh_random_secret": "neh-demo-seed",
    "neh_sequence_count": "3",
    "neh_path_prefix": "knock",
    "tg_bot_token": "",
    "tg_allowed_user_id": "",
    "tg_bot_name": "Наблюдатель NEH",
    "kibana_public_url": "http://localhost:5601",
    "tg_alert_chat_id": "",
    "tg_alert_threshold": "3",
    "tg_alert_window_seconds": "10",
    "tg_alert_cooldown_seconds": "15",
    "tg_loop_sleep": "0.5",
    "tg_poll_timeout": "5",
}


QUESTIONS = [
    ("gateway_http_port", "Публичный порт gateway"),
    ("nginx_http_port", "Публичный порт модуля Nginx"),
    ("nginx_knock_ports", "Дополнительные открытые knock-порты Nginx (через запятую)"),
    ("honeypot_port", "Внутренний порт honeypot"),
    ("protected_app_port", "Внутренний порт protected app"),
    ("elasticsearch_port", "Публичный порт Elasticsearch"),
    ("kibana_port", "Публичный порт Kibana"),
    ("elastic_version", "Версия Elastic Stack"),
    ("curl_image_version", "Версия curlimages/curl"),
    ("kibana_encryption_key", "Ключ шифрования Kibana"),
    ("neh_knock_type", "Тип knock-механизма NEH (uri|port)"),
    ("neh_sequence", "URI knock-последовательность (через запятую)"),
    ("neh_port_sequence", "Port knock-последовательность (через запятую)"),
    ("neh_protected_uri", "Защищённый URI"),
    ("neh_honeypot_uri", "Внутренний URI honeypot"),
    ("neh_cookie_name", "Имя access-cookie"),
    ("neh_bind_host", "Привязывать cookie к одному host (on|off)"),
    ("neh_timeout", "Таймаут knock-последовательности"),
    ("neh_access_window", "Окно доступа"),
    ("neh_block_threshold", "Порог блокировки"),
    ("neh_block_duration", "Длительность блокировки"),
    ("neh_randomize_sequence", "Рандомизировать URI-последовательность (on|off)"),
    ("neh_random_secret", "Секрет для случайных путей"),
    ("neh_sequence_count", "Количество шагов в случайной последовательности"),
    ("neh_path_prefix", "Префикс случайного пути"),
    ("tg_bot_token", "Токен Telegram-бота"),
    ("tg_allowed_user_id", "Разрешённые Telegram ID (через запятую)"),
    ("tg_bot_name", "Отображаемое имя Telegram-бота"),
    ("kibana_public_url", "Публичный URL Kibana"),
    ("tg_alert_chat_id", "Telegram chat ID для алертов"),
    ("tg_alert_threshold", "Порог Telegram-алерта"),
    ("tg_alert_window_seconds", "Окно Telegram-алерта в секундах"),
    ("tg_alert_cooldown_seconds", "Cooldown Telegram-алерта в секундах"),
    ("tg_loop_sleep", "Пауза цикла Telegram-бота"),
    ("tg_poll_timeout", "Таймаут polling Telegram"),
]


def normalize_list(raw: str, prefix: str = "") -> list[str]:
    items = [item.strip() for item in raw.split(",") if item.strip()]
    if prefix:
        return [f"{prefix}{item}" for item in items]
    return items


def prompt(name: str, label: str, current: str) -> str:
    entered = input(f"{label} [{current}]: ").strip()
    return entered or current


def backup(path: Path) -> None:
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))


def render_template(name: str, context: dict[str, str]) -> str:
    template = (TEMPLATES / name).read_text(encoding="utf-8")
    return template.format(**context)


def build_context(values: dict[str, str]) -> dict[str, str]:
    knock_ports = normalize_list(values["nginx_knock_ports"])
    uri_sequence = normalize_list(values["neh_sequence"])
    port_sequence = normalize_list(values["neh_port_sequence"])

    if not values["tg_alert_chat_id"]:
        values["tg_alert_chat_id"] = values["tg_allowed_user_id"]

    context = dict(values)
    context["nginx_port_bindings"] = "".join(f'      - "{port}:{port}"\n' for port in knock_ports)
    context["nginx_listens"] = "".join(f"        listen {port};\n" for port in knock_ports)
    context["neh_sequence"] = " ".join(uri_sequence) if uri_sequence else "/start /verify /grant"
    context["neh_port_sequence"] = " ".join(port_sequence) if port_sequence else "18081 18082 18083"
    return context


def write_configs(context: dict[str, str]) -> None:
    targets = {
        ROOT / "docker-compose.yml": render_template("docker-compose.yml.tpl", context),
        ROOT / "nginx" / "nginx.conf": render_template("nginx.conf.tpl", context),
        ROOT / ".env": render_template("env.tpl", context),
    }
    for path, content in targets.items():
        backup(path)
        path.write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Настройка файлов стека NEH.")
    parser.add_argument("--non-interactive", action="store_true", help="Использовать значения по умолчанию и CLI-переопределения без интерактивных вопросов.")
    for key in DEFAULTS:
        parser.add_argument(f"--{key.replace('_', '-')}", dest=key)

    args = parser.parse_args()
    values = DEFAULTS.copy()
    for key in values:
        override = getattr(args, key)
        if override is not None:
            values[key] = override

    if not args.non_interactive:
        print("Конфигуратор стека NEH")
        print("Нажмите Enter, чтобы оставить текущее значение или значение по умолчанию.\n")
        for name, label in QUESTIONS:
            values[name] = prompt(name, label, values[name])

    context = build_context(values)
    write_configs(context)

    print("Обновлены файлы:")
    print(f"- {ROOT / 'docker-compose.yml'}")
    print(f"- {ROOT / 'nginx' / 'nginx.conf'}")
    print(f"- {ROOT / '.env'}")
    print("Резервные копии сохранены как *.bak")


if __name__ == "__main__":
    main()
