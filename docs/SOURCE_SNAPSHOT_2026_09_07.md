# TenderBot: исходники на 7 сентября 2026 года

Снимок содержит исходники локальной версии `a4d48c3` и сохранённые изменения
рабочей копии: настраиваемого оператора commercial handoff, локальный machine
runtime, пакет MDOS 7.2.0-rc.2 и утилиту `scripts/live_inbound_local_ops.py` для
проверки и резервного копирования локальных данных observer. В публичном
репозитории он опубликован одним новым корневым коммитом: локальная история
восстановления и прежняя история логистической копии в ветку `main` не входят.

Это сохранение исходников. Оно не является установкой защищённого сервиса,
ратификацией MDOS 7.2 или разрешением на новые внешние операции. Действующая
MDOS authority остаётся 7.1.0-rc.1; нативный Bitrix Mail observer использует
отдельную authority. В пакете 7.2 все live gates остаются выключенными.

## Исправление при подготовке

Локальный reader `lead_factory/mdos_v7/successor_release.py` согласован с уже
существовавшим пакетом: версия 7.2.0-rc.2, 45 артефактов, SHA256 release pin
`9810b720e1db6d9ebf54d7de603dadc978ae5e261cec3c875574f7383d867701`.
Байты manifest, release pin и нормативных артефактов сохранены. Проверки подмены
manifest/pin и безусловного запрета live-действий проходят. Ограничение rc1 в
валидаторе ratification намеренно сохранено: тест пакета требует отклонять rc2.

## Известные ограничения проверки

Полный зелёный regression для чистого checkout не заявляется. Проверки
подготовленных наборов зависят от файлов, отсутствующих в исходниках:

- `test_manual_egress_evidence_is_exact_non_authoritative_and_privacy_safe`
  требует локальный `state/mdos_v7_external_freeze.json`.
- `test_four_real_owner_signatures_still_require_verified_artifact_bytes` и
  `test_package_and_target_profile_binding_are_inside_signed_content` в наборе
  ratification preflight также не проходят без этого локального freeze-файла.
- `test_mdos_v72_trace_digests_are_artifact_bytes_and_cover_acceptance`
  проверяет сохранённые ссылки на девять исторических evidence-файлов в
  игнорируемом `reports/market_demand_os_v7/`: `g0-suppression-evidence.json`,
  `g1-shadow-evidence.json`, `g2-outbox-evidence.json`,
  `g1-split-payment-shadow-evidence.json`, `g2-manual-egress-evidence.json`,
  `g2-owner-preflight-evidence.json`, `test-summary.json`,
  `g2-inbound-attribution-shadow-evidence.json`,
  `g2-motion-preflight-evidence.json`.

Отсутствующие доказательства не заменены фиктивными данными. Эти ограничения
нужно закрыть отдельной проверкой до заявления о полной воспроизводимости и
приёмке пакета; загрузка исходников в GitHub их не закрывает.

При публичной загрузке GitHub распознал искусственный Slack-пример в
`tests/test_mdos_v7_ratification_preflight.py` как токен. Пример заменён явным
синтетическим значением, сохраняющим проверку запрета и отсутствия утечки в
сообщениях об ошибках. Защита GitHub от секретов остаётся включённой.
25 исторических ссылок traceability на этот тестовый файл сохраняют SHA его
прежней редакции и не подтверждают новую. Нормативный пакет не переписывался;
для полной воспроизводимости эти ссылки требуют новой проверки и фиксации.

## Локальные файлы

Секреты, базы, MIME писем, журналы, резервные копии и материалы восстановления
CRM не входят в этот снимок. Также исключены два одноразовых локальных
инструмента: `RUN_OBSERVER_INSTALL.cmd` с путём конкретного компьютера и
`scripts/recover_live_email_filter_bug_20260901.py`, меняющий runtime ledger.
Оригинальные рабочие копии и защищённый сервис при подготовке не изменялись.

Контрольные суммы пакетов вычисляются по точным байтам. При клонировании для
проверки используйте `git -c core.autocrlf=false clone <repository-url>`.
