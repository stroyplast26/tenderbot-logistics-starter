"""Offline-testable Bitrix universal-Activity adapter.

No HTTP client, webhook, environment lookup, CLI registration, or worker is
created here.  A future cutover must inject the narrow ``BitrixRest`` boundary
and a shared cross-process rate gate.

Official REST contracts used:
* ``crm.activity.todo.add`` accepts ownerTypeId, ownerId, deadline, title,
  description, responsibleId, pingOffsets and colorId, and returns ``result.id``:
  https://apidocs.bitrix24.ru/api-reference/crm/timeline/activities/todo/crm-activity-todo-add.html
* ``crm.activity.get`` returns ID, OWNER_ID and OWNER_TYPE_ID for readback:
  https://apidocs.bitrix24.ru/api-reference/crm/timeline/activities/activity-base/crm-activity-get.html
* CRM entity type 1 is Lead:
  https://apidocs.bitrix24.ru/api-reference/crm/data-types.html
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .bitrix_canary import BitrixRest, RateGate
from .crm_outbox import (
    ActivityOutcomeUncertain,
    AmbiguousRemoteError,
    CrmActivityReceipt,
    PermanentRemoteError,
    RetryableRemoteError,
)
from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed


_RETRYABLE_CODES = {"QUERY_LIMIT_EXCEEDED", "OPERATION_TIME_LIMIT"}
_PERMANENT_PREEXECUTION_CODES = {
    "100",
    "ACCESS_DENIED",
    "ERROR_ARGUMENT",
    "ERROR_ARGUMENT_TYPE",
    "ERROR_EMPTY_PARAM",
    "ERROR_REQUIRED_PARAMETER",
    "EXPIRED_TOKEN",
    "INSUFFICIENT_SCOPE",
    "INVALID_CREDENTIALS",
    "INVALID_REQUEST",
    "NO_AUTH_FOUND",
    "NOT_FOUND",
    "OWNER_NOT_FOUND",
    "USER_ACCESS_ERROR",
    "WRONG_DATETIME_FORMAT",
}
_ALLOWED_ACTIVITY_FIELDS = {
    "deadline",
    "title",
    "description",
    "responsibleId",
    "pingOffsets",
    "colorId",
}
_LOCAL_ACTIVITY_METADATA = {"_lf_activity_correlation_token", "_lf_task_id"}


class BitrixActivityAdapter:
    """Create one Lead-owned todo and return a typed, exact readback receipt.

    The operation has no Bitrix-documented immutable external idempotency key.
    Therefore after an add result contains an Activity ID, *every* get failure
    is converted to ``ActivityOutcomeUncertain(remote_id)``.  The outbox can
    preserve that ID for review but must never retry the add automatically.
    """

    OWNER_TYPE_ID_LEAD = 1

    def __init__(self, rest: BitrixRest, rate_gate: RateGate):
        self.rest = rest
        self.rate_gate = rate_gate

    def _call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        assert_external_allowed(f"bitrix.activity.rest:{method}")
        self.rate_gate.reserve()
        try:
            assert_external_allowed(f"bitrix.activity.rest:{method}")
            response = self.rest.call(method, payload)
        except ExternalAuthorityError:
            raise
        except RetryableRemoteError:
            raise RetryableRemoteError("Bitrix Activity request was rate-limited") from None
        except PermanentRemoteError:
            raise PermanentRemoteError(
                "Bitrix Activity validation or access rejected request"
            ) from None
        except AmbiguousRemoteError:
            raise AmbiguousRemoteError("Bitrix Activity call outcome is ambiguous") from None
        except Exception:
            raise AmbiguousRemoteError("Bitrix Activity call outcome is ambiguous") from None
        if not isinstance(response, dict):
            raise AmbiguousRemoteError("Bitrix Activity returned an invalid response shape")
        code = str(response.get("error", "") or "").strip().upper()
        if code:
            if code in _RETRYABLE_CODES:
                raise RetryableRemoteError("Bitrix Activity rate limit rejected request")
            if code in _PERMANENT_PREEXECUTION_CODES:
                raise PermanentRemoteError("Bitrix Activity validation or access rejected request")
            raise AmbiguousRemoteError("Bitrix Activity returned an unclassified error")
        if "result" not in response:
            raise AmbiguousRemoteError("Bitrix Activity response has no result")
        return response

    @staticmethod
    def _numeric_id(value: Any) -> str:
        if isinstance(value, bool):
            return ""
        remote_id = str(value or "").strip()
        return remote_id if remote_id.isdigit() and int(remote_id) > 0 else ""

    @staticmethod
    def _positive_integer(value: Any) -> int | None:
        remote_id = BitrixActivityAdapter._numeric_id(value)
        return int(remote_id) if remote_id else None

    def _todo_fields(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise PermanentRemoteError("Activity payload must be an object")
        fields: dict[str, Any] = {}
        for key, value in payload.items():
            if key in _LOCAL_ACTIVITY_METADATA:
                continue
            if key not in _ALLOWED_ACTIVITY_FIELDS:
                raise PermanentRemoteError("Activity payload contains a non-whitelisted field")
            fields[key] = value
        deadline = fields.get("deadline")
        if not isinstance(deadline, str) or not deadline.strip():
            raise PermanentRemoteError("Activity deadline is required")
        normalized_deadline = deadline.strip()
        # Bitrix documents ``deadline`` as datetime.  ``fromisoformat`` alone
        # accepts a date-only value, so require an explicit time component too.
        if "T" not in normalized_deadline.upper():
            raise PermanentRemoteError("Activity deadline must be an ISO datetime")
        try:
            datetime.fromisoformat(normalized_deadline.replace("Z", "+00:00"))
        except ValueError:
            raise PermanentRemoteError("Activity deadline must be an ISO datetime") from None
        fields["deadline"] = normalized_deadline
        for text_field in ("title", "description"):
            if text_field in fields and not isinstance(fields[text_field], str):
                raise PermanentRemoteError(f"Activity {text_field} must be a string")
        if "responsibleId" in fields:
            responsible = self._positive_integer(fields["responsibleId"])
            if responsible is None:
                raise PermanentRemoteError("Activity responsibleId must be numeric")
            fields["responsibleId"] = responsible
        if "pingOffsets" in fields:
            offsets = fields["pingOffsets"]
            if (
                not isinstance(offsets, list)
                or any(
                    isinstance(item, bool) or not isinstance(item, int) or item < 0
                    for item in offsets
                )
            ):
                raise PermanentRemoteError(
                    "Activity pingOffsets must be a non-negative integer list"
                )
        if "colorId" in fields:
            color = str(fields["colorId"] or "").strip()
            if color not in {"1", "2", "3", "4", "5", "6", "7"}:
                raise PermanentRemoteError("Activity colorId must be in the range 1..7")
            fields["colorId"] = color
        return fields

    def create_activity(self, lead_remote_id: str, payload: dict[str, Any]) -> CrmActivityReceipt:
        """Add one todo and prove the returned Activity belongs to this Lead."""
        owner_id = self._positive_integer(lead_remote_id)
        if owner_id is None:
            raise PermanentRemoteError("Lead owner id must be numeric")
        fields = self._todo_fields(payload)
        response = self._call(
            "crm.activity.todo.add",
            {
                "ownerTypeId": self.OWNER_TYPE_ID_LEAD,
                "ownerId": owner_id,
                **fields,
            },
        )
        result = response.get("result")
        if not isinstance(result, dict):
            raise AmbiguousRemoteError("Bitrix Activity add returned an invalid result")
        remote_id = self._numeric_id(result.get("id"))
        if not remote_id:
            raise AmbiguousRemoteError("Bitrix Activity add returned no valid id")
        try:
            readback = self._call("crm.activity.get", {"id": remote_id}).get("result")
        except Exception:
            # Once an ID was returned, even a permanent get error cannot prove
            # that the remote todo is absent.  Keep the ID for manual review.
            raise ActivityOutcomeUncertain(remote_id) from None
        if not isinstance(readback, dict):
            raise ActivityOutcomeUncertain(remote_id)
        if (
            self._numeric_id(readback.get("ID")) != remote_id
            or self._numeric_id(readback.get("OWNER_ID")) != str(owner_id)
            or self._numeric_id(readback.get("OWNER_TYPE_ID"))
            != str(self.OWNER_TYPE_ID_LEAD)
        ):
            raise ActivityOutcomeUncertain(remote_id)
        return CrmActivityReceipt(
            remote_id=remote_id,
            owner_lead_id=str(owner_id),
            readback_verified=True,
        )


__all__ = ["BitrixActivityAdapter"]
