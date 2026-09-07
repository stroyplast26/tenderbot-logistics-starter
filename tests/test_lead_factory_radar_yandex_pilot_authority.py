"""Explicitly synthetic authority receipts; no real activation or network."""

from dataclasses import asdict, replace
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lead_factory.mdos_v7.authority import ExternalAuthorityError, assert_external_allowed
from lead_factory.radar_yandex_journal import DispatchGrant, PilotPolicy, YandexPilotJournal
from lead_factory import radar_yandex_pilot_authority as authority
from lead_factory.radar_yandex_search import SearchRequest, build_yandex_pilot_plan


NOW = "2026-09-08T12:00:00Z"
EXPIRY = "2026-09-09T12:00:00Z"
FOLDER = "synthetic-folder"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def make_bundle(root: Path, *, now: str = NOW):
    """Return bundle_path, policy, pin_path, folder_id; all receipts are synthetic.

    Callers patch only authority._ACTIVATION_PIN and authority._now_utc to this
    temporary fixture. Code hashes reference the actual implementation under test.
    """
    root.mkdir(parents=True, exist_ok=True)
    expires = (authority._utc(now) + authority.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    requests = tuple(SearchRequest(r["query_text"], r["region_label"], r["page"])
                     for r in build_yandex_pilot_plan(year=2026)["requests"])
    policy = PilotPolicy("synthetic-owner-pilot", hashlib.sha256(FOLDER.encode()).hexdigest(), requests, expires)
    journal_path = root / "pilot.sqlite"
    journal = YandexPilotJournal.create(journal_path, policy=policy, now=now)
    journal.close()
    identity = {"st_dev": journal_path.stat().st_dev, "st_ino": journal_path.stat().st_ino}
    claims = root / "dispatch-claims"
    claims.mkdir()
    claims_identity = {"st_dev": claims.stat().st_dev, "st_ino": claims.stat().st_ino}
    code = authority._source_hashes()
    scope = {"policy_sha256": policy.sha256, "journal_path": str(journal_path.resolve()),
             "journal_identity": identity, "claims_identity": claims_identity,
             "workspace_root": str(authority._WORKSPACE_ROOT)}
    bundle = {
        "version": "radar-yandex-pilot-authority-v1", "created_at_utc": now, "expires_at_utc": expires,
        "action": "radar.yandex.search.read", "endpoint": "https://searchapi.api.cloud.yandex.net/v2/web/search",
        "mdos_ratification": False,
        "forbidden_effects": ["OTHER_SOURCES", "CRM_WRITES", "OUTGOING_CONTACT", "MESSAGES", "PUBLICATION", "SCHEDULER"],
        "workspace_root": str(authority._WORKSPACE_ROOT), "journal_path": str(journal_path.resolve()),
        "journal_identity": identity, "claims_identity": claims_identity,
        "policy": asdict(policy), "policy_sha256": policy.sha256, "code_sha256": code,
        "owner_receipt": {"kind": "CAPTURED_OWNER_INSTRUCTION", "owner_id": "synthetic-owner",
                          "source_thread_id": "synthetic-thread", "instruction_sha256": hashlib.sha256(b"SYNTHETIC ONLY OWNER").hexdigest(),
                          "captured_at_utc": now, "scope_sha256": hashlib.sha256(canonical(scope)).hexdigest()},
        "independent_acceptance": {"kind": "INDEPENDENT_CODE_ACCEPTANCE", "reviewer_id": "synthetic-independent-reviewer",
                                   "implementation_author_ids": ["synthetic-writer"],
                                   "reviewed_at_utc": now, "verdict": "ACCEPT", "code_sha256": code,
                                   "evidence_sha256": hashlib.sha256(b"SYNTHETIC ONLY REVIEW").hexdigest()},
        "readiness": {"kind": "BILLING_API_READINESS", "observed_at_utc": now, "billing_status": "ACTIVE",
                      "search_api_status": "CONFIGURATION_VERIFIED", "credential_status": "AVAILABLE",
                      "folder_id_sha256": policy.folder_id_sha256,
                      "evidence_sha256": hashlib.sha256(b"SYNTHETIC ONLY READINESS").hexdigest()},
    }
    bundle_path, pin_path = root / "bundle.json", root / "activation.json"
    bundle_path.write_bytes(canonical(bundle))
    pin_path.write_bytes(canonical({"version": "radar-yandex-pilot-activation-v1", "status": "ACTIVE",
                                   "bundle_path": str(bundle_path.resolve()),
                                   "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                                   "policy_sha256": policy.sha256, "activated_at_utc": now, "expires_at_utc": expires}))
    return bundle_path, policy, pin_path, FOLDER


def claim_worker(bundle_path, pin_path, intent_values, body, ready, start, results):
    with patch.object(authority, "_ACTIVATION_PIN", Path(pin_path)), patch.object(authority, "_now_utc", return_value=NOW):
        verified = authority.verify_pilot_grant(bundle_path, now=NOW)
        journal = verified.open_journal()
        ready.put(True)
        start.wait(10)
        try:
            verified.mint_dispatch_capability(journal, DispatchGrant(*intent_values), body, now=NOW)
            results.put("MINTED")
        except authority.PilotAuthorityError as exc:
            results.put(exc.code)
        finally:
            journal.close()


def clock_verify_worker(bundle_path, pin_path, now, results):
    with patch.object(authority, "_ACTIVATION_PIN", Path(pin_path)):
        try:
            authority.verify_pilot_grant(bundle_path, now=now)
            results.put("VERIFIED")
        except authority.PilotAuthorityError as exc:
            results.put(exc.code)


class YandexPilotAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle, self.policy, self.pin, self.folder = make_bundle(self.root)
        pin_patch = patch.object(authority, "_ACTIVATION_PIN", self.pin)
        clock_patch = patch.object(authority, "_now_utc", return_value=NOW)
        pin_patch.start()
        clock_patch.start()
        self.addCleanup(pin_patch.stop)
        self.addCleanup(clock_patch.stop)

    def fail(self, code, fn, *args, **kwargs):
        with self.assertRaises(authority.PilotAuthorityError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def verified(self):
        return authority.verify_pilot_grant(self.bundle, now=NOW)

    def opened(self, verified=None):
        verified = verified or self.verified()
        journal = verified.open_journal()
        self.addCleanup(journal.close)
        return verified, journal

    def ready_intent(self):
        verified, journal = self.opened()
        request = self.policy.requests[0]
        verified.authorize_request(journal, request, self.folder, now=NOW)
        intent = journal.mark_dispatch_intent(journal.reserve(request, now=NOW), now=NOW)
        body = canonical(request.body(self.folder))
        return verified, journal, intent, body

    def change_bundle(self, mutate, *, repin=True):
        bundle = json.loads(self.bundle.read_text(encoding="utf-8"))
        mutate(bundle)
        self.bundle.write_bytes(canonical(bundle))
        if repin:
            pin = json.loads(self.pin.read_text(encoding="utf-8"))
            pin["bundle_sha256"] = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
            self.pin.write_bytes(canonical(pin))

    def test_real_verifier_and_single_use_capability(self):
        verified, journal, intent, body = self.ready_intent()
        self.assertEqual(verified.policy_sha256, self.policy.sha256)
        self.assertEqual(verified.journal_path, self.root / "pilot.sqlite")
        capability = verified.mint_dispatch_capability(journal, intent, body, now=NOW)
        authority.consume_capability(capability, body, intent.request_id)
        self.fail("CAPABILITY_NOT_ISSUED", authority.consume_capability, capability, body, intent.request_id)
        self.assertEqual(journal.status()["attempts_reserved"], 1)
        with self.assertRaises(ExternalAuthorityError):
            assert_external_allowed("synthetic-old-guard-still-closed")

    def test_forged_public_types_never_issue_authority(self):
        self.fail("GRANT_NOT_ISSUED", authority.VerifiedPilotGrant)
        self.fail("CAPABILITY_NOT_ISSUED", authority.DispatchCapability)
        forged = object.__new__(authority.VerifiedPilotGrant)
        self.fail("GRANT_NOT_ISSUED", forged.open_journal)
        fake_cap = object.__new__(authority.DispatchCapability)
        self.fail("CAPABILITY_NOT_ISSUED", authority.consume_capability, fake_cap, b"{}", "fake-request")
        self.fail("CAPABILITY_NOT_ISSUED", authority.consume_capability, True, b"{}", "fake-request")

    def test_missing_pin_and_wrong_bundle_hash_fail_closed(self):
        self.pin.unlink()
        self.fail("PATH_BINDING_INVALID", self.verified)
        # A caller-provided bundle hash cannot replace the separate fixed pin.
        with self.assertRaises(TypeError):
            authority.verify_pilot_grant(self.bundle, now=NOW, expected_hash="a" * 64)

    def test_bundle_tamper_is_rejected_without_pin_change(self):
        self.change_bundle(lambda b: b.update(mdos_ratification=True), repin=False)
        self.fail("BUNDLE_HASH_MISMATCH", self.verified)

    def test_malformed_receipt_values_are_log_safe(self):
        self.change_bundle(lambda b: b["readiness"].update(billing_status=["PRIVATE_UNTRUSTED"] ))
        self.fail("MANIFEST_INVALID", self.verified)

    def test_wrong_code_hash_fails_even_with_matching_pin(self):
        self.change_bundle(lambda b: b["code_sha256"].update({authority._CODE_FILES[0]: "a" * 64}))
        self.fail("CODE_HASH_MISMATCH", self.verified)

    def test_missing_owner_and_review_or_same_reviewer_are_rejected(self):
        original = self.bundle.read_bytes()
        for field in ("owner_receipt", "independent_acceptance"):
            self.bundle.write_bytes(original)
            self.change_bundle(lambda b: b.pop(field))
            self.fail("MANIFEST_INVALID", self.verified)
        self.bundle.write_bytes(original)
        self.change_bundle(lambda b: b["independent_acceptance"].update(reviewer_id="synthetic-owner"))
        self.fail("ACCEPTANCE_REQUIRED", self.verified)

    def test_trial_configuration_receipt_is_allowed_without_claiming_live_fetch(self):
        self.change_bundle(lambda b: b["readiness"].update(billing_status="TRIAL_ACTIVE"))
        self.assertEqual(self.verified().policy_sha256, self.policy.sha256)

    def test_copied_or_replaced_journal_is_not_canonical(self):
        copied = self.root / "copy.sqlite"
        shutil.copy2(self.root / "pilot.sqlite", copied)
        self.change_bundle(lambda b: b.update(journal_path=str(copied)))
        self.fail("JOURNAL_PATH_MISMATCH", self.verified)

    def test_replaced_file_same_canonical_name_fails_identity(self):
        canonical_path = self.root / "pilot.sqlite"
        replacement = self.root / "replacement.sqlite"
        shutil.copy2(canonical_path, replacement)
        canonical_path.unlink()
        replacement.rename(canonical_path)
        self.fail("JOURNAL_IDENTITY_MISMATCH", self.verified)

    def test_open_connection_path_and_registration_are_checked(self):
        verified, journal = self.opened()
        unbound = YandexPilotJournal.open(self.root / "pilot.sqlite", expected_policy_sha256=self.policy.sha256)
        self.addCleanup(unbound.close)
        self.fail("JOURNAL_NOT_BOUND", verified.authorize_request, unbound, self.policy.requests[0], self.folder, now=NOW)
        self.fail("FOLDER_MISMATCH", verified.authorize_request, journal, self.policy.requests[0], "wrong-folder", now=NOW)
        self.fail("REQUEST_NOT_AUTHORIZED", verified.authorize_request, journal,
                  SearchRequest("unplanned", "synthetic"), self.folder, now=NOW)

    def test_wrong_body_cannot_mint_and_invalid_consume_burns_token(self):
        verified, journal, intent, body = self.ready_intent()
        other = canonical(self.policy.requests[1].body(self.folder))
        self.fail("BODY_MISMATCH", verified.mint_dispatch_capability, journal, intent, other, now=NOW)
        capability = verified.mint_dispatch_capability(journal, intent, body, now=NOW)
        self.fail("CAPABILITY_BINDING_INVALID", authority.consume_capability, capability, other, intent.request_id)
        self.fail("CAPABILITY_NOT_ISSUED", authority.consume_capability, capability, body, intent.request_id)

    def test_second_verified_grant_cannot_mint_same_intent(self):
        first, journal, intent, body = self.ready_intent()
        first.mint_dispatch_capability(journal, intent, body, now=NOW)
        second, reopened = self.opened()
        self.fail("CAPABILITY_ALREADY_ISSUED", second.mint_dispatch_capability, reopened, intent, body, now=NOW)

    def test_pin_revocation_and_expiry_are_checked_again_at_consume(self):
        verified, journal, intent, body = self.ready_intent()
        capability = verified.mint_dispatch_capability(journal, intent, body, now=NOW)
        pin = json.loads(self.pin.read_text(encoding="utf-8"))
        pin["status"] = "REVOKED"
        self.pin.write_bytes(canonical(pin))
        self.fail("ACTIVATION_INACTIVE", authority.consume_capability, capability, body, intent.request_id)
        pin["status"] = "ACTIVE"
        self.pin.write_bytes(canonical(pin))
        self.fail("ACTIVATION_EXPIRED", authority.verify_pilot_grant, self.bundle, now=EXPIRY)

    def test_expired_consume_burns_capability_and_cannot_backdate(self):
        verified, journal, intent, body = self.ready_intent()
        capability = verified.mint_dispatch_capability(journal, intent, body, now=NOW)
        with patch.object(authority, "_now_utc", return_value=EXPIRY):
            self.fail("ACTIVATION_EXPIRED", authority.consume_capability, capability, body, intent.request_id)
        self.fail("CLOCK_BACKWARDS", verified.authorize_request, journal, self.policy.requests[0], self.folder, now=NOW)
        # A newly verified grant has no in-memory history of the consumed
        # capability, but still sees its committed expiry observation.
        self.fail("CLOCK_BACKWARDS", self.verified)
        self.fail("CAPABILITY_NOT_ISSUED", authority.consume_capability, capability, body, intent.request_id)

    def test_expiry_seen_by_verifier_is_durable_before_open_even_across_processes(self):
        context = multiprocessing.get_context("spawn")
        results = context.Queue()
        for when, expected in ((EXPIRY, "ACTIVATION_EXPIRED"), (NOW, "CLOCK_BACKWARDS")):
            process = context.Process(target=clock_verify_worker,
                                      args=(str(self.bundle), str(self.pin), when, results))
            try:
                process.start()
                self.assertEqual(results.get(timeout=15), expected)
                process.join(timeout=15)
                self.assertEqual(process.exitcode, 0)
            finally:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
        self.fail("CLOCK_BACKWARDS", self.verified)
        journal = YandexPilotJournal.open(self.root / "pilot.sqlite", expected_policy_sha256=self.policy.sha256)
        self.addCleanup(journal.close)
        self.assertEqual(journal.status()["attempts_reserved"], 0)

    def test_stop_prevents_new_capability_but_issued_one_is_single_inflight(self):
        verified, journal, intent, body = self.ready_intent()
        journal.stop(now=NOW)
        self.fail("PILOT_STOPPED", verified.mint_dispatch_capability, journal, intent, body, now=NOW)
        self.fail("PILOT_STOPPED", verified.authorize_request, journal, self.policy.requests[0], self.folder, now=NOW)

    def test_forged_intent_or_completed_state_cannot_mint(self):
        verified, journal, intent, body = self.ready_intent()
        self.fail("DISPATCH_BINDING_INVALID", verified.mint_dispatch_capability, journal,
                  replace(intent, request_id="forged"), body, now=NOW)
        journal.finish_uncertain(intent, reason_code="SYNTHETIC_UNCERTAIN", now=NOW)
        self.fail("DISPATCH_BINDING_INVALID", verified.mint_dispatch_capability, journal, intent, body, now=NOW)

    def test_os_profile_is_independent_of_environment_overrides(self):
        expected = authority._trusted_profile()
        with patch.dict(os.environ, {"HOME": str(self.root), "USERPROFILE": str(self.root)}):
            self.assertEqual(authority._trusted_profile(), expected)

    def test_review_cannot_be_signed_off_by_implementation_author(self):
        self.change_bundle(lambda b: b["independent_acceptance"].update(
            implementation_author_ids=["synthetic-independent-reviewer"]))
        self.fail("ACCEPTANCE_REQUIRED", self.verified)

    def test_claim_directory_replacement_and_other_checkout_are_rejected(self):
        claims = self.root / "dispatch-claims"
        claims.rename(self.root / "original-claims")
        claims.mkdir()
        self.fail("CLAIMS_IDENTITY_INVALID", self.verified)
        self.change_bundle(lambda b: b.update(workspace_root=str(self.root)))
        self.fail("WORKSPACE_MISMATCH", self.verified)

    def test_claim_failure_after_exclusive_create_never_mints_or_retries(self):
        verified, journal, intent, body = self.ready_intent()
        with patch.object(authority.os, "fsync", side_effect=OSError("synthetic secret error")):
            self.fail("CLAIM_PERSISTENCE_FAILED", verified.mint_dispatch_capability, journal, intent, body, now=NOW)
        self.fail("CAPABILITY_ALREADY_ISSUED", verified.mint_dispatch_capability, journal, intent, body, now=NOW)
        self.assertEqual(len(list((self.root / "dispatch-claims").iterdir())), 1)
        self.assertEqual(journal.status()["reserved_cost_minor"], 49)

    def test_stop_after_issued_capability_allows_only_existing_inflight(self):
        verified, journal, intent, body = self.ready_intent()
        capability = verified.mint_dispatch_capability(journal, intent, body, now=NOW)
        journal.stop(now=NOW)
        authority.consume_capability(capability, body, intent.request_id)
        self.fail("CAPABILITY_NOT_ISSUED", authority.consume_capability, capability, body, intent.request_id)

    def test_two_processes_cannot_mint_same_persisted_intent_and_restart_cannot_retry(self):
        verified, journal, intent, body = self.ready_intent()
        journal.close()
        context = multiprocessing.get_context("spawn")
        ready, results, start = context.Queue(), context.Queue(), context.Event()
        values = (intent.operation_key, intent.reservation_id, intent.request_id)
        processes = [context.Process(target=claim_worker,
                     args=(str(self.bundle), str(self.pin), values, body, ready, start, results)) for _ in range(2)]
        try:
            for process in processes:
                process.start()
            for _ in processes:
                self.assertTrue(ready.get(timeout=15))
            start.set()
            self.assertEqual(sorted(results.get(timeout=15) for _ in processes),
                             ["CAPABILITY_ALREADY_ISSUED", "MINTED"])
            for process in processes:
                process.join(timeout=15)
                self.assertEqual(process.exitcode, 0)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
        # The winner exited before using its token; a new process cannot
        # reconstruct another token from the public durable grant fields.
        fresh, reopened = self.opened()
        self.fail("CAPABILITY_ALREADY_ISSUED", fresh.mint_dispatch_capability, reopened, intent, body, now=NOW)
        self.assertEqual(len(list((self.root / "dispatch-claims").iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
