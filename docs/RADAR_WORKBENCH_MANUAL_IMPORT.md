# Public project import

`radar_workbench_import_example.json` is a schema-only template with placeholders.
It is not a real object, licensed dataset, source approval, or demonstration seed.
Replace every placeholder and every date/confidence with checked public facts.
The importer accepts one JSON object, at most 262,144 UTF-8 bytes. It does not fetch
the source link, interpret a PDF, verify that the website states these facts, or
manufacture a buyer response. The source URL remains clickable provenance for the
operator to verify; use HTTPS without credentials, a query string, or a fragment.

The existing `SourcePassport` must already authorize `MANUAL_IMPORT`, the
`BUSINESS_PUBLIC` data class and `construction-radar-observation-v1`. It must be the
latest version, `APPROVED`, capability `PASS`, licence `ALLOWED`, current at import
and observation time, and bound to its registration event. Supply its ID and the
operator separately through the local CLI; JSON cannot grant its own authority.
`rights_basis_ref` must equal this passport's `terms_ref` or `licence_ref`.

This version only accepts public business reference facts suitable for indefinite
local retention (`PUBLIC_REFERENCE_NO_EXPIRY`). The existing Radar evidence ledger
is immutable and has no deletion/expiry implementation. Do not use this path for
personal contacts, credentials, private documents, or licence-limited datasets.
Names/contact details have no fields; participant INNs must identify legal
entities (10 digits), not individual entrepreneurs. Check free-text fields too.

Required fields are shown in the template. `source_revision` is a decimal string;
increment it for a changed source observation. An identical replay returns the
same signal and evidence IDs. Different bytes under the same passport/object/
revision are a conflict. The raw JSON bytes, their SHA-256, rights basis, source
link and resulting signal are bound in a single transaction. A failed import
leaves no evidence or signal behind. The result normally needs research `REVIEW`;
negative evidence may instead produce `EXCLUDED` or `NURTURE`. The import creates
no sales opportunity, task, CRM record, message or source access grant.

Optional arrays/objects use these fields (each claim is bound to the same uploaded
JSON evidence; do not supply `evidence_ref` or method/authority metadata):

- `participants`: array of `company_inn`, `role`, `valid_from_utc`, `valid_until_utc`,
  `source_date_utc`, `confidence`. Roles include `DEVELOPER`, `GENERAL_CONTRACTOR`,
  `ARCHITECT`, `FACADE_CONTRACTOR`, `WINDOW_CONTRACTOR`, `GLAZING_BUYER`.
- `demand`: `aluminium_system`, `quantity_band`, `source_date_utc`, `confidence`,
  optional `building_type`. Omit it when the source does not establish demand.
- `prediction`: `bucket` (`D14`/`D30`/`D60`), `window_start_utc`, `window_end_utc`,
  `likely_buyer_inn`, `source_date_utc`, `confidence`. A manually supplied forecast
  is still a forecast, not a purchase commitment.
- `negative_evidence`: array of `kind`, `source_date_utc`, `confidence`, optional
  `valid_until_utc`. Supported kinds are those in `NegativeEvidenceKind`.

Application API:

```python
result = RadarWorkbenchImporter(store).import_bytes(
    supplied_bytes, passport_id=approved_passport_id, actor=operator_id
)
# result.ingest: object_id, project_id, signal_id, created, decision, review_reason
# result.evidence_id: use RadarEvidenceVault(store).verify(...) for integrity
```

Only the CLI reads the explicitly selected local file. Browser requests do not
supply a filesystem path. The new module uses the existing Radar and evidence
APIs; it does not unlock the sensitive manual-upload pipeline or the fixture-only
Wave1 provider contracts.
