# Демонстрационные представления Kibana

Создайте data view для:

```text
neh-events-*
```

Рекомендуемые панели Lens:

1. Запросы во времени
   - Ось X: `ts`
   - Разбиение: `service`

2. IP-адреса с наибольшим числом запросов
   - Top values по `remote_addr`

3. Наиболее запрашиваемые URI
   - Top values по `uri`

4. Перенаправления в honeypot
   - Фильтр: `decision: "honeypot"`
   - Визуализация: линия или столбцы во времени

5. Успешные разблокировки
   - Фильтр: `event: "knock_success" or event: "protected_allowed"`

Рекомендуемый алерт:

- Условие: более 10 документов с `decision: "honeypot"` от одного `remote_addr` за 5 минут
- Действие: email, webhook или мост в Telegram
