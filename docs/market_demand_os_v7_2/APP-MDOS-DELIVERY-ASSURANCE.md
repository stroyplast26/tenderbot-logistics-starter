# APP-MDOS-DELIVERY-ASSURANCE — реализация, контроль и приёмка

**Application ID:** `APP-MDOS-DELIVERY-ASSURANCE`  
**Версия:** `1.2.0`

## 1. Непереступаемые invariants

**MDOS-ASR-001.** Default deny, least privilege, RBAC/SoD, secret isolation,
suppression, purpose limitation, immutable audit, content-addressed evidence,
idempotency, reconciliation, WIP/backpressure, backup/restore и rollback обязательны
для всех motions и sources.

**MDOS-ASR-002.** Unknown actor/writer/model/source/schema/policy/release denied.
Developer не может быть единственным verifier/releaser; model builder — единственным
validator/promoter; content author — собственным send/spend approver; case originator
— final arbiter.

**MDOS-ASR-003.** Break-glass требует двух лиц, scope/TTL/reason, immutable audit,
incident и post-review. Он не обходит law, suppression, payment truth или audit
integrity.

**MDOS-ASR-004.** PII хранится минимально по purpose/data class; retention/deletion,
legal hold, DSAR и provider/transfer policy охватывают raw, graph, features, training
datasets, prompts/logs/evidence. После erasure допускается отдельно защищённый
минимальный suppression tombstone, если это юридически обосновано.

## 2. Traceability и machine contract

**MDOS-TRC-001.** Каждый requirement имеет owner, criticality, applicable tier,
text digest и links `SATISFIED_BY design`, `IMPLEMENTED_BY code`, `VERIFIED_BY test`,
`PRODUCED_EVIDENCE`. Изменение upstream digest инвалидирует dependent evidence.

**MDOS-TRC-002.** P0/P1 requirement без test binding/evidence не имеет status
IMPLEMENTED/VERIFIED. Количество Markdown acceptance rows не является proof.

**MDOS-TRC-003.** Schemas используют JSON Schema 2020-12, `$id`, schema version,
`additionalProperties:false`, RFC3339 UTC и explicit version/migration.

**MDOS-TRC-004.** Package/release digest строится по canonical sorted artifact
digests; ratification/signature находится вне self-hashed payload и связывает exact
root digest.

**MDOS-TRC-005.** Typed `TraceEdge` registry хранит requirement/design/code/test/
evidence digests и status. Specified acceptance case не равен executed test; пустой
code/evidence binding сохраняется явно и fail-closed. Изменение upstream digest
отзывает downstream edge до повторной проверки.

## 3. Программа реализации по gate, а не по календарю

**MDOS-PRG-001.** `G0 — Truth and authority foundation`:

- reconcile Account/Contact/Deal с bank/payment evidence, локальными OrderRegistry
  и FulfilmentLedger;
- восстановить source/original/influence/action attribution;
- consent/suppression/legal review текущего outreach;
- capability/promise/capacity evidence;
- source passports и event/claim/DemandUnit schemas;
- freeze unauthorized live actions.

Exit: один `PaymentProof → OrderRecord → FulfilmentRecord` и один suppression case
воспроизводятся end-to-end; unknown writer blocked; backup/restore доказаны.

**MDOS-PRG-002.** `G1 — One executable vertical slice`:

```text
existing/known account trigger
→ raw event → claim → identity → DemandUnit
→ immutable human GoldAcceptance → exact PermitDecision → Bitrix task/deal
→ bank/payment proof → Order/Fulfilment ledgers → outcome reconciliation
```

Exit: test bindings/evidence для P0 path, replay digest, no duplicate/illegal effect.

**MDOS-PRG-003.** `G2 — Three near-money motions`:

1. existing account/reorder/win-back;
2. dealer/installer Benchmark RFQ;
3. high-intent inbound/RFQ.

Exit: sealed cohorts, motion-specific precision/capacity, first paid outcomes and
offer experiments. Массовый scrape/outreach не является entry criterion.

**MDOS-PRG-009.** G1/G2 canary не запускается до `RATIFIED BeachheadProfile`.
Технический vertical slice сначала исполняется на fixture/shadow данных; live switch
требует отдельной ratification exact profile, source/action permits и rollback proof.

**MDOS-PRG-010.** До G1 добавляется fail-closed mail-observer cutover gate: legacy
V4 writer authority/schedule revoked, exact 5 `OPERATOR_TODO` + 5 `TIMELINE_MAIL`
operations durably quarantined без dispatch, read-only boundary доказана, а 5m
singleton и 90m local-review сценарии выполнены offline. Gate не включает live read.

**MDOS-PRG-004.** `G3 — External high-intent portfolio`: Yandex closed loop,
Avito B360/RFQ contractual pilot, 2GIS inbound, permitted RFQ platforms/referrals.
Exit: incremental Paid/contribution or stopped evidence for each method.

**MDOS-PRG-005.** `G4 — Triggered market expansion`: dealer discovery, commercial
openings/refit, installed-base/service. Exit: signal-family lift, buyer resolution,
region×product economics and lawful action proof.

**MDOS-PRG-006.** `G5 — Project/specification ecosystem`: ДОМ.РФ/permits/GISOGD/
EGRZ, architects/design assist, buyer transition. Exit: SpecifiedProject→InvitedRFQ
cohort and lead-time advantage; no premature GDO counting.

**MDOS-PRG-007.** `G6 — Procurement/tender lane`: ЕИС/ЭТП/vendor feeds with separate
payment-risk/economics. Exit: incremental profitable orders, not bids/calculations.

**MDOS-PRG-008.** `G7 — Portfolio intelligence`: calibrated time-to-event, EVI,
causal optimizer, champion/challenger, GDO10 evaluation. Advanced ML cannot skip
G0–G2 truth/evidence gates.

## 4. Current baseline implications

**MDOS-BAS-001.** Existing cold campaign baseline (40,680 records, 24 replies,
3 lead statuses, 1,162 bounces on snapshot 25.08.2026) demonstrates a volume/data-
quality problem; it does not prove customers or legality. Scale remains disabled
until consent/legal, ICP, current-need and outcome reconciliation.

**MDOS-BAS-002.** Existing assets — 88 warm records and 1,793 retail-fit records —
are pilot cohorts, not leads. Cohort membership, actual buyer status, contact right,
current need and payment history must be re-adjudicated.

**MDOS-BAS-003.** Current v6 package has 346 requirements and 118 specified acceptance
cases, but all 118 have no test bindings/evidence refs. First delivery priority is
executable closed-loop proof, not another large unimplemented source list.

**MDOS-BAS-004.** Legacy V4 outbox является migration input, а не утверждённой
операторской работой: cutover принимает только exact cohort из десяти недоставленных
delivery operations, по пять `OPERATOR_TODO` и `TIMELINE_MAIL`. Любое расхождение
count/kind или non-quarantined executable row блокирует observer startup. Quarantine
сохраняет phase/error audit и receipt, а legacy initialize не может вернуть executable
Todo/Timeline.

## 5. Weekly operating review

**MDOS-REV-001.** Weekly review shows outcome tree, bottleneck, GDO/Paid/Repeat by
motion, source/offer experiments, calibration/drift, capacity/WIP, legal/incidents,
stopped methods and next critical-path decisions.

**MDOS-REV-002.** Backlog priority follows bottleneck and expected incremental
contribution per scarce hour. Новый scraper не выше RFQ→estimate/payment bottleneck,
если raw candidates уже избыточны.

**MDOS-REV-003.** Для каждого method status: `PROPOSED → OFFLINE → SHADOW → CANARY
→ PROVEN/SCALE` либо `REVISE/STOPPED`; negative result сохраняется и не повторяется
без нового evidence/assumption.

## 6. Release gates

**MDOS-REL-001.** Gate order:

1. manifest/schema/ratification;
2. traceability/orphan scan;
3. source/legal/privacy/retention;
4. RBAC/SoD/security/secrets;
5. migration/backup/restore;
6. data/ER/document/model eval;
7. conflict arbitration;
8. replay/property/load/adversarial tests;
9. audit/evidence freshness;
10. bounded canary, capacity/reconciliation/rollback;
11. signed production release and post-deploy verification.

**MDOS-REL-002.** Failed P0, critical open risk, expired permit/evidence/waiver,
unknown deployment digest or unresolved payment/consent conflict blocks affected
production scope.

**MDOS-REL-003.** После mail-observer design действует обязательный STOP перед MANGO,
TenderPlan, UniSender/SMTP, outbound contact и любым CRM repair/write. Каждый такой
контур требует нового normative diff, permit, preflight/evidence, rollback и отдельного
owner release; RC2 и observer schedule не могут неявно расширить scope.

## 7. Acceptance

| ID | Сценарий | Ожидаемый результат |
|---|---|---|
| `AT-ASR-01` | Requirement P0 не имеет test/evidence. | Release blocked; статус не VERIFIED. |
| `AT-ASR-02` | Developer пытается единолично проверить и выпустить свой код. | SoD reject. |
| `AT-ASR-03` | Cold-contact action не имеет consent/legal permit. | 0 send/call; immutable denial. |
| `AT-ASR-04` | Erasure затрагивает training dataset и graph. | PII удалена по lineage; scoped suppression tombstone отделён. |
| `AT-ASR-05` | Raw→Paid vertical slice replay. | Exact events/claims/decision/action/payment воспроизводимы. |
| `AT-ASR-06` | Backlog предлагает новый parser при очереди расчётов. | Bottleneck/capacity rule снижает приоритет parser. |
| `AT-ASR-07` | Negative pilot повторно запускается без новой гипотезы. | Change gate blocks. |
| `AT-ASR-08` | Canary теряет события/создаёт duplicates. | Auto-pause/rollback + incident. |
| `AT-ASR-09` | Contract package изменён без нового digest/version. | Manifest test fails; release invalid. |
| `AT-ASR-10` | Owner просит включить PC10 без payment/capacity proof. | Отдельная ratification blocked pending evidence. |
| `AT-ASR-11` | ActionAssignment содержит только произвольную строку permit_id. | Schema/policy deny; внешний эффект отсутствует. |
| `AT-ASR-12` | PermitDecision просрочен или относится к другому channel/scope. | Just-in-time denial + immutable audit. |
| `AT-ASR-13` | P0 requirement имеет acceptance row, но нет code/test/evidence binding. | Status не выше DESIGNED; production release blocked. |
| `AT-ASR-14` | G1 пытается использовать нератифицированный beachhead. | Canary blocked; shadow/fixture path разрешён. |
