# APP-LF-QUALITY-ARBITRATION — истина, конфликты и апелляции

**Application ID:** `APP-LF-QUALITY-ARBITRATION`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Authoritative Fact Matrix

**LF-QA-001.** Канонический authority определяется по классу факта:

| Fact class | Авторитет | Не является авторитетом |
|---|---|---|
| Cleared Payment/refund | bank/accounting approved event | CRM stage, письмо, AI |
| Order/contract | approved ERP/accounting/contract event | verbal promise, invoice alone |
| Consent/Suppression | dedicated consent/suppression ledger | AI, salesperson note alone |
| Raw source observation | hashed raw capture/source receipt | normalized/model claim |
| Identity merge | identity resolution decision + evidence | name/address/embedding alone |
| ICP/external buyer | versioned qualification decision | ОКВЭД/email/AI alone |
| AGCO | Gold Gate + human acceptance + evidence | score/form/reply alone |
| Capacity | signed fresh Capacity Snapshot | historical plan/AI estimate alone |
| Commercial promise | active Promise Registry | generated text/model memory |
| Human next action/disposition | authorized CRM/human command | stale projection/AI guess |
| Attribution | immutable event/correlation chain | last-touch overwrite |

**LF-QA-002.** CRM остаётся авторитетом только для явно назначенных sales fields;
он не становится авторитетом факта из-за последнего timestamp.

## 2. Universal ConflictCase

**LF-QA-003.** Несовместимые claims создают immutable `QualityConflict`:

```text
OPEN → QUARANTINED → RESOLVED / OVERRIDDEN
                         ↘ APPEALED → RESOLVED
```

Сохраняются обе версии, evidence, authority classes, dependent actions,
created/resolve times, owner, arbiter и reason.

**LF-QA-004.** Critical conflict автоматически карантинирует зависимые Gold,
payment/KPI, routing, contact, promise, CRM write или model label. Независимые
части graph/workflow могут продолжаться.

**LF-QA-005.** Conflict не разрешается averaging, highest AI confidence,
latest timestamp или silent overwrite.

## 3. Resolution и override

**LF-QA-006.** Resolution требует authority matrix, sufficient evidence,
независимого QualityArbiter для critical class и immutable decision.

**LF-QA-007.** Override не меняет факт; это scoped/time-bound разрешение действовать
при известной неопределённости. Оно содержит scope, TTL, risk, approvers и запрещено
для non-waivable controls из `APP-LF-SAFETY-KERNEL-IMPORT`.

**LF-QA-008.** Expired override автоматически блокирует последующие действия и
открывает повторный review, если case ещё активен.

## 4. Appeal и SLA

**LF-QA-009.** Appeal создаёт новую запись и не удаляет prior resolution. Appellant,
arbiter и evidence producer не могут быть одним sole principal для critical case.

**LF-QA-010.** Conflict SLA зависит от риска/срока закупки. Просроченный critical
conflict не снимается автоматически; dependent action остаётся paused/escalated.

## 5. Label integrity

**LF-QA-011.** Model/training label создаётся только из resolved/adjudicated fact.
Позднее решение создаёт correction/retraction event и invalidates affected dataset,
evaluation, forecast и promotion evidence через traceability graph.

**LF-QA-012.** Self-reported dealer/sales disposition является claim до проверки,
если влияет на bonus, routing rank, AGCO truth или коммерческий proof.

## 6. Acceptance

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-QA-01` | CRM says Paid, bank/accounting says no. | KPI/payment quarantined. |
| `AT-QA-02` | AI и raw evidence расходятся. | No LWW; critic/conflict review. |
| `AT-QA-03` | Identity conflict unresolved past SLA. | Dependent contact/Gold blocked. |
| `AT-QA-04` | Override без scope/TTL/independent role. | Reject. |
| `AT-QA-05` | Appeal изменил решение. | Prior immutable; correction event propagated. |
| `AT-QA-06` | Resolved label был в model dataset. | Dataset/model evidence invalidated/rebuilt. |
| `AT-QA-07` | Salesperson меняет свой bonus outcome. | Independent evidence/adjudication required. |

