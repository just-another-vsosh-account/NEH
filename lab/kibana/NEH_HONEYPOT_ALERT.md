# Алерт NEH Honeypot

Это правило обнаруживает всплеск перенаправлений в honeypot в демонстрационных данных NEH.

## Условие

- index: `neh-events-*`
- filter: `decision: "honeypot"`
- aggregation: `count`
- threshold: `> 3`
- window: `5m`
- check interval: `1m`

## Создание через API

```bash
./lab/kibana/create_honeypot_alert.sh
```

## Для чего использовать

- обнаруживает перебор директорий и probing путей
- демонстрирует автоматическое обнаружение на стороне SIEM на основе телеметрии NEH
