# Пакет дашборда Kibana

В этой папке находится импортируемый пакет saved objects для демонстрации NEH:

- [neh-dashboard.ndjson](/home/ilyastarcek/vsosh/lab/kibana/neh-dashboard.ndjson)
- [import_dashboard.sh](/home/ilyastarcek/vsosh/lab/kibana/import_dashboard.sh)
- [create_honeypot_alert.sh](/home/ilyastarcek/vsosh/lab/kibana/create_honeypot_alert.sh)
- [create_legit_access_alert.sh](/home/ilyastarcek/vsosh/lab/kibana/create_legit_access_alert.sh)
- [NEH_HONEYPOT_ALERT.md](/home/ilyastarcek/vsosh/lab/kibana/NEH_HONEYPOT_ALERT.md)

## Что создаётся

- data view: `neh-events-*`
- дашборд: `Демо-дашборд NEH`
- обзорная markdown-панель
- панель поиска по всем событиям
- панель поиска по событиям honeypot
- панель поиска по событиям успешного доступа

## Импорт через интерфейс Kibana

1. Откройте `Stack Management -> Saved Objects`
2. Нажмите `Import`
3. Выберите `lab/kibana/neh-dashboard.ndjson`
4. При необходимости подтвердите перезапись существующих объектов

## Импорт через API

```bash
./lab/kibana/import_dashboard.sh
```

Адрес Kibana по умолчанию:

- `http://localhost:5601`

Переопределение при необходимости:

```bash
KIBANA_URL=http://your-host:5601 ./lab/kibana/import_dashboard.sh
```

## Поведение compose по умолчанию

`docker compose up -d` запускает вспомогательный сервис `kibana-bootstrap`, который ждёт готовности Kibana и автоматически импортирует этот дашборд.

## Примечания

- В этом пакете используются saved search, потому что их формат проще и стабильнее для вручную подготовленного импортируемого файла, чем внутренние структуры Lens.
- После импорта вы можете расширить дашборд графиками Lens, используя тот же data view `neh-events-*`.
