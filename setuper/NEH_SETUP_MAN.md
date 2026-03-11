# NEH-SETUP(1)

## ИМЯ

`setup_neh.py` - генерация конфигурации проекта NEH для Docker Compose, NEH-модуля Nginx и Telegram-бота.

## СИНТАКСИС

```bash
cd /home/ilyastarcek/vsosh
python3 setuper/setup_neh.py
python3 setuper/setup_neh.py --non-interactive --neh-knock-type port --neh-port-sequence 18081,18082,18083
```

## ОПИСАНИЕ

`setup_neh.py` генерирует и перезаписывает:

- `docker-compose.yml`
- `nginx/nginx.conf`
- `.env`

Перед записью создаются резервные копии:

- `docker-compose.yml.bak`
- `nginx/nginx.conf.bak`
- `.env.bak`

Скрипт использует шаблоны из `setuper/templates/`.

## ГЕНЕРИРУЕМЫЕ ЧАСТИ

### Docker Compose

- публикуемый порт gateway
- публикуемый порт модуля Nginx
- дополнительные открытые порты для port knocking в NEH
- внутренние порты honeypot / protected-app
- порты и версии Elastic / Kibana

### Модуль NEH

- `neh_knock_type`
- `neh_sequence`
- `neh_port_sequence`
- `neh_protected_uri`
- `neh_honeypot_uri`
- `neh_cookie_name`
- `neh_bind_host`
- `neh_timeout`
- `neh_access_window`
- `neh_block_threshold`
- `neh_block_duration`
- `neh_randomize_sequence`
- `neh_random_secret`
- `neh_sequence_count`
- `neh_path_prefix`

### Telegram-бот

- токен бота
- список разрешённых Telegram ID
- отображаемое имя бота
- публичный URL Kibana
- chat ID для алертов
- порог алерта
- окно алерта в секундах
- cooldown алерта в секундах
- тайминги polling

## ИНТЕРАКТИВНЫЙ РЕЖИМ

Запускайте без `--non-interactive`, чтобы ответить на вопросы по каждому полю.

```bash
python3 setuper/setup_neh.py
```

## НЕИНТЕРАКТИВНЫЙ РЕЖИМ

Запуск со значениями по умолчанию:

```bash
python3 setuper/setup_neh.py --non-interactive
```

Переопределение отдельных полей:

```bash
python3 setuper/setup_neh.py \
  --non-interactive \
  --gateway-http-port 8080 \
  --nginx-http-port 8081 \
  --neh-knock-type port \
  --neh-port-sequence 18081,18082,18083 \
  --tg-bot-token 123:abc \
  --tg-allowed-user-id 123456789,987654321
```

## РЕЖИМ PORT KNOCK

Чтобы включить port knocking в сгенерированной конфигурации Nginx:

```bash
python3 setuper/setup_neh.py \
  --non-interactive \
  --neh-knock-type port \
  --neh-port-sequence 18081,18082,18083 \
  --nginx-knock-ports 18081,18082,18083
```

Пример последовательности запросов:

1. `http://localhost:18081/`
2. `http://localhost:18082/`
3. `http://localhost:18083/`
4. `http://localhost:8081/admin`

## РЕЖИМ URI KNOCK

```bash
python3 setuper/setup_neh.py \
  --non-interactive \
  --neh-knock-type uri \
  --neh-sequence /start,/verify,/grant
```

## ФАЙЛЫ

- `setuper/setup_neh.py`
- `setuper/NEH_MODULE_MAN.md`
- `setuper/templates/docker-compose.yml.tpl`
- `setuper/templates/nginx.conf.tpl`
- `setuper/templates/env.tpl`

## КОД ЗАВЕРШЕНИЯ

- `0` успех
- ненулевой код при ошибке Python/выполнения

## ПРИМЕЧАНИЯ

- Скрипт записывает только текстовые конфигурационные файлы.
- Он не запускает Docker-команды автоматически.
- После генерации примените конфигурацию командой:

```bash
docker compose up --build -d
```
