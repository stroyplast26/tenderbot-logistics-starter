# Сайт → Lead Factory: запуск приёмника

Сайт больше не обращается к Bitrix напрямую. Обработчик `send.php` сначала
сохраняет заявку и файлы на российском хостинге, отправляет fallback-письмо и,
если настроен новый endpoint, передаёт только подписанный typed-delivery в Lead
Factory. Файлы не скачиваются в приёмник и не передаются в CRM или AI.

## Что уже подготовлено

- Endpoint: `POST /v1/site-deliveries`.
- Проверяются HMAC-SHA256, SHA-256 тела, лимит 128 KiB, дата и idempotency.
- Успешная заявка фиксируется локально как raw delivery, Source Lab record,
  review и `SITE_QUALIFICATION` task. CRM/outbound action не создаются.
- Endpoint выключен по умолчанию (`LEAD_FACTORY_SITE_INGRESS_ENABLED=0`).

## Единственная операция публикации

На постоянном HTTPS-сервере Lead Factory задать, вне репозитория:

```text
LEAD_FACTORY_SITE_INGRESS_SECRET=<новый случайный секрет, 32+ символов>
LEAD_FACTORY_SITE_INGRESS_ENABLED=1
```

Запустить сервис за reverse proxy с TLS:

```text
python -m lead_factory.cli serve-site-deliveries --host 127.0.0.1 --port 8088
```

На PHP-хостинге сайта создать `send.config.php` по
`public/send.config.php.example`, вставив тот же секрет и HTTPS-адрес reverse
proxy. Старый `bitrix_webhook` из этого файла удалить. Затем загрузить новый
`send.php` и проверить одну тестовую заявку: ответ должен содержать
`"lead_factory": true`, а локальная очередь — одну `SITE_QUALIFICATION` task.

Не включать внешний CRM writer, Unisender или OpenRouter этим действием: их
контуры имеют отдельные авторизации и бюджеты.
