# APP-LF-SAFETY-KERNEL-IMPORT — точное наследование v5.2

**Application ID:** `APP-LF-SAFETY-KERNEL-IMPORT`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`  
**Imported artifact:** `docs/LEAD_FACTORY_CONTRACT.md`, SHA-256
`84b61a956bae970d0d7baf61985256ae15d1775474512d71f5c2d74d64974afb`

## 1. Правило импорта

**LF-IMP-001.** Импорт действует только для exact hash выше. Любое изменение файла
v5.2 требует новой карты/версии и не подхватывается автоматически.

**LF-IMP-002.** Статусы:

- `IMPORTED_NORMATIVE` — действует без ослабления;
- `IMPORTED_SPECIALIZED` — safety invariant действует, business/data semantics
  уточняется v6.1;
- `SUPERSEDED` — не используется для v6.1 decisions/acceptance;
- `HISTORICAL_EVIDENCE` — описывает прежнее состояние/технический checkpoint.

**LF-IMP-003.** Если imported safety invariant конфликтует с v6.1, применяется
более безопасный fail-closed вариант и открывается C3 change. Business semantics
v5.2 не может отменить v6.1 dealer-first/Gold Gate/GCO10.

## 2. Import map

| Раздел v5.2 | Статус | Что действует в v6.1 |
|---|---|---|
| §1 Нормативные слова | `IMPORTED_NORMATIVE` | ОБЯЗАН/ЗАПРЕЩЕНО, evidence-first. |
| §§2–8 Mission/scope/success/architecture/engines | `SUPERSEDED` | Заменены CONTRACT, FUNNELS, G10, PLATFORM. |
| §9 Source contract | `IMPORTED_SPECIALIZED` | Passport/legal/dedupe/stop; schema v2 имеет приоритет. |
| §10 Data model/provenance | `IMPORTED_SPECIALIZED` | Identity/evidence invariants; новые FunnelCase/Dealer/DIE types v6.1. |
| §11 Generic opportunity states | `SUPERSEDED` до Gold; `IMPORTED_SPECIALIZED` после Gold | Funnel states v6.1, общая commercial spine сохраняется. |
| §12 AI constitution | `IMPORTED_NORMATIVE` | Claims-not-facts, typed output, data boundary, injection safety. |
| §13 Generic scoring/routing | `SUPERSEDED` | DIE axes, hard gates, Network Routing. |
| §14 Promise Registry | `IMPORTED_NORMATIVE` | Дополнен Offer Engine v6.1. |
| §§15–16 Human SLO/capacity | `IMPORTED_SPECIALIZED` | WIP/backpressure; роли и Digital Twin v6.1 имеют приоритет. |
| §§17–18 Contact/legal gate | `IMPORTED_NORMATIVE` | Suppression/legal fail-closed; v6.1 privacy registry дополняет. |
| §§19–21 Experiments/economics/feedback | `SUPERSEDED` для gates; safety principles imported | Заменены Method Lab и Decision Science. |
| §§22–24 Authority/reliability/security | `IMPORTED_NORMATIVE` | Дополнены Control Plane/Governance/RBAC. |
| §25 Reporting | `SUPERSEDED` | v6.1 scorecards/traceability. |
| §§26–29 Stages/DoD/backlog/parameters | `SUPERSEDED` | Development Program/GCO10. |
| §§30–31 Change/final commitment | `IMPORTED_SPECIALIZED` | Governance/Release v6.1 строже и имеет приоритет. |
| §32 Policy Engine/permits | `IMPORTED_NORMATIVE` | Дополнен policy-as-code/command model. |
| §33 Event/ownership/attribution | `IMPORTED_NORMATIVE` | Дополнен CQRS/authority matrix. |
| §34 Bitrix technical integration | `IMPORTED_SPECIALIZED` | Outbox/idempotency/read-back/security/cutover imported; dealer projection v6.1. |
| §35 Advertising | `SUPERSEDED` для priority/success; safety imported | Supplier-intent/CRM outcomes/experiments v6.1. |
| §36 Metrics/economics | `SUPERSEDED` | G10/Decision Science. |
| §37 AI Data Boundary | `IMPORTED_NORMATIVE` | Дополнен Model Risk/DIE. |
| §38 Reliability/environments/cutover | `IMPORTED_NORMATIVE` | Дополнен Platform/Release. |
| §39 Acceptance plan | `HISTORICAL_EVIDENCE` | Старые tests могут доказать imported invariant, но v6.1 AT обязательны. |
| §40 Source purchase/legal references | `IMPORTED_SPECIALIZED` | Capability-before-purchase imported; source passport/privacy v6.1. |
| §41 Construction Demand Radar | `IMPORTED_SPECIALIZED` | `LF-RADAR-*`/`AT-RADAR-*` остаются для existing kernel; DIE расширяет, не ослабляет. |
| §42 Wave/readiness/dates | `HISTORICAL_EVIDENCE` | Не является v6.1 roadmap/DoD; evidence может переиспользоваться до expiry. |

## 3. Non-waivable imported controls

**LF-IMP-004.** Не допускают waiver/owner override:

- suppression и явный запрет контакта;
- tampered/forged evidence и audit integrity;
- secret exposure/minimum authority;
- missing legal/source permission;
- external effect без exact permit;
- identity conflict при критическом действии;
- destructive migration без backup/restore/cutover gate;
- payment/order truth без authoritative evidence;
- prompt injection расширяющий authority/purpose;
- restore/replay старого external permit.

## 4. Evidence reuse

**LF-IMP-005.** Evidence v5.2 может закрыть v6.1 requirement только если registry
имеет typed trace edge, смысл/fixture/environment совпадают, artifact hash доступен,
evidence не истёкло и изменение v6.1 не затронуло доказанный invariant.

**LF-IMP-006.** Технический green checkpoint не закрывает business outcome,
dealer semantics, DIE quality, Method/Decision Science или GCO10 proof автоматически.

## 5. Acceptance

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-IMP-01` | Hash v5.2 изменился. | Import invalid, package не ratifiable. |
| `AT-IMP-02` | Старый generic Q используется как AGCO. | Reject по supersession map. |
| `AT-IMP-03` | Старое Bitrix idempotency evidence exact и fresh. | Может закрыть linked technical invariant. |
| `AT-IMP-04` | Старый TECH_READY используется как GCO10. | Reject. |
| `AT-IMP-05` | V6 правило пытается ослабить suppression/permit/audit. | Fail-closed, C3 change blocked. |

