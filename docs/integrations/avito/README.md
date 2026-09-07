# Авито Business API — спецификации

В этой папке сохранены исходные OpenAPI 3.0-спецификации, выгруженные из официального каталога API Авито. Они не исполняются ботом сами по себе: это справочники для безопасной разработки интеграции и генерации API-клиента.

## Минимальный набор для TenderBot

- `openapi/03-auth.openapi.json` — получение и обновление токена доступа.
- `openapi/10-items.openapi.json` — управление объявлениями.
- `openapi/12-messenger.openapi.json` — чаты и сообщения покупателей.
- `openapi/14-promotion.openapi.json` — продвижение объявлений.
- `openapi/20-ads.openapi.json` — кабинет «Авито Реклама»: кампании, группы, креативы, бюджеты и статистика.
- `openapi/04-autoload.openapi.json` — массовая загрузка и обновление объявлений.

## Остальные разделы

| Файл | Раздел API |
| --- | --- |
| `01-account-hierarchy.openapi.json` | Иерархия аккаунтов |
| `02-cpa-auction.openapi.json` | CPA-аукцион |
| `05-autostrategy.openapi.json` | Автостратегия |
| `06-calltracking.openapi.json` | Коллтрекинг |
| `07-cpa.openapi.json` | CPA Авито |
| `08-target-action-pricing.openapi.json` | Цена целевого действия |
| `09-delivery.openapi.json` | Доставка |
| `11-jobs.openapi.json` | Авито Работа |
| `13-order-management.openapi.json` | Управление заказами |
| `15-ratings-reviews.openapi.json` | Рейтинги и отзывы |
| `16-special-offers-beta.openapi.json` | Спецпредложения в мессенджере, beta |
| `17-stock-management.openapi.json` | Управление остатками |
| `18-trx-promo.openapi.json` | TrxPromo |
| `19-user-info.openapi.json` | Информация о пользователе |

## Правило подключения

Ключи `client_id` и `client_secret` хранятся только в `.env` и никогда не добавляются в эти файлы или в Git. До появления ключей и согласованного лимита расходов интеграция работает исключительно в режиме чтения статистики и подготовки рекомендаций.

