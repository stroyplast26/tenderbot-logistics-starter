# APP-LF-GOVERNANCE-RELEASE — управление, безопасность и выпуск

**Application ID:** `APP-LF-GOVERNANCE-RELEASE`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Contract as Code

**LF-GOV-001.** Контракт является versioned build input. Runtime/release не может
заявлять соответствие v6 без valid manifest, exact hashes, schema validation и
requirement traceability.

**LF-GOV-002.** Нормативный package состоит из root contract, imported safety
kernel, приложений, JSON Schemas, requirement registry и acceptance manifest.
README/ADR/runbook не могут переопределить норму.

**LF-GOV-003.** Любое нормативное изменение создаёт version/change record с:

- reason/owner/author;
- affected requirements/schemas/tests;
- compatibility/migration impact;
- safety/commercial impact;
- evidence and approvals;
- effective/sunset time;
- old/new hashes.

## 2. Traceability

**LF-GOV-TRC-001.** Каждый `LF-*` связан:

```text
requirement
→ bounded context/design decision
→ implementation component
→ verification method/test
→ expected evidence schema
→ release evidence artifact
→ production observation/expiry
```

**LF-GOV-TRC-002.** Статусы requirement:

- `DEFINED`;
- `DESIGNED`;
- `IMPLEMENTED`;
- `VERIFIED_OFFLINE`;
- `VERIFIED_CANARY`;
- `PROVEN_PRODUCTION`;
- `BLOCKED`;
- `SUPERSEDED`.

Ручной статус без evidence не принимается.

**LF-GOV-TRC-003.** Каждый `AT-*` имеет owner, environment, executable/manual
procedure, fixtures/preconditions, expected result, evidence type, TTL и related
requirements. Placeholder test не закрывает requirement.

**LF-GOV-TRC-004.** Coverage gates:

- 100% normative LF IDs присутствуют в registry;
- 100% release-scope LF IDs имеют хотя бы один AT;
- 100% P0/P1 и external-effect requirements имеют executable negative test;
- 100% production claims имеют non-expired evidence.

## 3. Roles, RBAC и SoD

**LF-GOV-RBAC-001.** Логические роли:

- `BusinessOwner` — target, products, regions, commercial limits;
- `ContractAuthority` — normative versions/semantics;
- `LegalDataAuthority` — source/contact/privacy/licence decisions;
- `SourceAuthority` — passport/capability/runtime owner;
- `MethodOwner` — hypothesis/protocol/outcome;
- `ModelRiskOwner` — model/eval/data boundary;
- `ReleaseManager` — immutable release/cutover;
- `Operator` — run/monitor/reconcile без policy change;
- `SalesOwner` / `EstimatorOwner` / `ProductionOwner`;
- `SecurityIncidentOwner`;
- `IndependentAuditor`.

Один человек может исполнять несколько low-risk ролей, но authority записывается
раздельно и не расширяется неявно.

**LF-GOV-RBAC-002.** Два разных principal обязательны для high-risk:

- включение live external writer/source beyond canary;
- новый массовый контактный сценарий;
- large-budget/price/margin override;
- production model promotion, влияющий на routing/qualification;
- secret/credential issuance с write scope;
- destructive migration/retention deletion;
- снятие P0/P1 safety block.

Если второго principal нет, действие блокируется до назначения независимого reviewer;
«владелец сам всё одобрил» не создаёт SoD.

**LF-GOV-RBAC-003.** Reviewer/approver не может единолично принять собственный
high-risk implementation/experiment/evidence.

**LF-GOV-RBAC-004.** Break-glass narrow, time-bound, logged, не разрешает массовые
коммерческие действия и автоматически открывает incident/post-review.

## 4. Change classification

**LF-GOV-CHG-001.** Классы:

- `C0` — editorial, semantics unchanged;
- `C1` — implementation conforming to existing contract;
- `C2` — source/model/policy/method/field behavior change;
- `C3` — target/Gold Gate/legal/data/authority/security/architecture invariant.

**LF-GOV-CHG-002.** C0 требует hash/change record. C1 — tests/release evidence.
C2 — impact/replay/shadow/canary. C3 — новая contract version, owner + required
authorities и повтор затронутых commercial proof windows.

**LF-GOV-CHG-003.** Emergency fix не меняет смысл requirement. Если меняет — это
C3 даже при срочности.

## 5. Release manifest

**LF-GOV-REL-001.** Immutable release bundle фиксирует:

- source revision/tree digest;
- contract/requirements/acceptance manifests;
- DB target schema/migrations;
- command/event/data schemas;
- policy/qualification/promise/method versions;
- model/provider/prompt/eval-set versions;
- source passports/mappings/licences;
- dependency lock/SBOM and build environment;
- config/feature flags без секретов;
- tests/evidence hashes;
- deployment target/scale tier;
- rollback/recovery instructions.

**LF-GOV-REL-002.** При отсутствии git используется reproducible source-tree digest
и immutable artifact store. Mutable folder/date/name не являются release identity.

**LF-GOV-REL-003.** Неподписанный/неполный bundle не разворачивается. Runtime
публикует active release digest; drift от manifest переводит external authority в 0.

## 6. Release gates

**LF-GOV-REL-004.** Последовательные gates:

1. contract/schema/traceability integrity;
2. lint/static/type/dependency/secret scan;
3. unit/property/adversarial policy tests;
4. integration/contract/E2E fixtures;
5. AI eval/prompt-injection/data-boundary/red-team;
6. migration/rollback/backup/restore/replay;
7. performance/capacity/failure injection;
8. stage reconciliation on production-shaped data;
9. bounded canary with exact permit;
10. post-canary read-back/economics/safety review;
11. controlled promotion and continuous SLO/drift monitor.

Failure более раннего hard gate блокирует последующие external gates.

**LF-GOV-REL-005.** Full suite не повторяется на unchanged relevant state без причины;
targeted preflight выполняется раньше дорогих gates, финальный required regression
остаётся обязательным.

## 7. Model Risk Management

**LF-GOV-AI-001.** Model registry фиксирует provider/model exact ID, release/date,
role, input/output schema, prompt/template, tools=none/allowlist, data classes,
purpose, cost/latency limits, eval set, calibration и rollback model.

**LF-GOV-AI-002.** Alias `latest`, silently changing model и provider auto-upgrade
не допускаются в production decision path без new evaluation/release.

**LF-GOV-AI-003.** Model promotion проходит:

- representative/out-of-time slices;
- schema validity and refusal handling;
- evidence faithfulness;
- prompt injection/data exfiltration;
- demographic/region/source/product disparity where relevant;
- false-hot/missed-opportunity/cost/latency;
- outage/fallback;
- champion/challenger shadow;
- independent ModelRiskOwner sign-off.

**LF-GOV-AI-004.** Human override является label только после adjudication; feedback
не используется для training автоматически. Training dataset имеет lineage,
point-in-time cutoff, consent/licence/purpose и deletion handling.

**LF-GOV-AI-005.** Drift или provider incident может автоматически downgrade/pause
model role. При AI outage deterministic/manual flow продолжает critical intake.

## 8. Legal, privacy и retention

**LF-GOV-DATA-001.** Для каждой data class/source/purpose фиксируются:

- legal/licence decision and authority;
- collection/acquisition mode;
- allowed use/funnel/model provider;
- data minimization;
- retention/expiry/deletion;
- access roles and export restrictions;
- consent/objection/suppression handling;
- evidence and review date.

**LF-GOV-DATA-002.** Source Terms/robots/API/contract и применимое право проверяются
до live acquisition. Техническая возможность scraping не является разрешением.

**LF-GOV-DATA-003.** Retention deletion создаёт tombstone/audit proof и не удаляет
необходимую минимальную suppression/financial/legal запись, если это разрешено/обязательно.

**LF-GOV-DATA-004.** Personal data, commercial documents и recordings имеют
минимальный purpose-specific view. Model vendor не получает raw payload, если роль
может работать с redacted/structured representation.

## 9. Threat model и security

**LF-GOV-SEC-001.** Threat registry включает:

- credential theft/over-scope;
- prompt injection/model data exfiltration;
- malicious/poisoned source document;
- forged/tampered evidence;
- replay/idempotency abuse;
- SSRF/path/traversal/unsafe file parsing;
- supply-chain/model/dependency compromise;
- CRM/source spoofing;
- insider role abuse/metric gaming;
- destructive migration/backup poisoning;
- privacy/retention breach and log leakage.

**LF-GOV-SEC-002.** Каждый P0/P1 threat имеет prevention, detection, response,
recovery, owner и tested scenario. Risk acceptance time-bound и owner+security approved.

**LF-GOV-SEC-003.** Secrets хранятся в approved secret store/OS protected boundary,
не в source, manifest, logs, prompts, evidence или CRM. Rotation/revocation tested.

## 10. Incident management

**LF-GOV-INC-001.** Severity:

- `P0` — unauthorized external effect, data loss/exfiltration, unsafe mass contact,
  corrupted canonical state, financial/security incident;
- `P1` — lost inbound/live reply, duplicate order/CRM effect, broken attribution,
  material model/policy false-hot, capacity/promise breach;
- `P2/P3` — degraded noncritical function/quality.

**LF-GOV-INC-002.** P0 автоматически: STOP affected authority, preserve evidence,
revoke/rotate where needed, reconcile scope, notify owner/security, start runbook.
Restore service только после containment/evidence/new permit.

**LF-GOV-INC-003.** Post-incident review без blame фиксирует timeline, root cause,
control failure, customer/commercial impact, corrective LF/AT/change и expiry.

## 11. Независимый аудит

**LF-GOV-AUD-001.** Перед `PROVEN_GCO10` независимый auditor проверяет:

- definitions/counting/anti-gaming;
- sample evidence/quality;
- source/method attribution;
- capacity/load/backlog;
- paid/repeat/economics maturity;
- manifest/release/traceability;
- unresolved incidents/exceptions;
- reproducibility from Event Store.

**LF-GOV-AUD-002.** Auditor не может быть единственным автором inspected data,
model, method и release. Findings имеют severity, owner, due date и closure evidence.

## 12. Acceptance

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-GOV-01` | Normative file изменён без manifest/version. | Contract integrity fails. |
| `AT-GOV-02` | LF requirement без AT/owner/evidence type. | Release-scope gate fails. |
| `AT-GOV-03` | Автор сам одобряет high-risk release. | SoD reject. |
| `AT-GOV-04` | Runtime digest расходится с release. | External authority=0. |
| `AT-GOV-05` | Model alias silently changed. | Model/release gate fails. |
| `AT-GOV-06` | Prompt injection пытается раскрыть secret. | No disclosure/effect; incident/eval record. |
| `AT-GOV-07` | Expired legal/source decision. | Read/contact blocked. |
| `AT-GOV-08` | Retention deletion replayed. | Idempotent tombstone/audit, no over-delete. |
| `AT-GOV-09` | P0 unauthorized effect. | STOP/revoke/evidence/runbook verified. |
| `AT-GOV-10` | Git отсутствует. | Reproducible tree/artifact digest identifies release. |
| `AT-GOV-11` | Production claim evidence expired. | Claim/tier revoked or revalidated. |
| `AT-GOV-12` | Auditor authored same outcome/model/release. | Independence gate fails. |

