"""Loopback-only browser workspace for local Radar research and human reports.

This server has no provider, CRM or telephony transport. The operator identity
is fixed at launch; browser requests cannot choose the author of an action.
"""

from __future__ import annotations

import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .radar_workbench import RadarResearchWorkbench, RadarWorkbenchConflict
from .radar_workbench_demo import is_demo_workspace
from .store import FactoryStore
from .tenderplan_workbench_review import TenderPlanWorkbenchReview, TenderPlanWorkbenchReviewError


MAX_BODY_BYTES = 16_384
ASSET_ROOT = Path(__file__).with_name("radar_workbench_assets")


def create_radar_workbench_server(
    store: FactoryStore, *, actor: str, port: int = 8766, demo: bool = False,
    tenderplan_review_store: str | Path | None = None,
) -> ThreadingHTTPServer:
    """Bind one local operator session; writes require its same-origin token."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("invalid workspace port")
    if not isinstance(actor, str) or not actor.strip() or len(actor) > 128:
        raise ValueError("operator is required (maximum 128 characters)")
    workspace = RadarResearchWorkbench(store, actor=actor.strip())
    store.init()
    if store.schema_version() < 15:
        raise ValueError("Radar schema 15 or later is required; no automatic migration")
    demo = demo or is_demo_workspace(store)
    token = secrets.token_urlsafe(32)
    tenderplan_review = (
        TenderPlanWorkbenchReview(tenderplan_review_store)
        if tenderplan_review_store is not None else None
    )

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _send(self, status: int, payload: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'",
            )
            self.end_headers()
            self.wfile.write(payload)

        def _json(self, status: int, value: object) -> None:
            body = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def _local(self) -> bool:
            expected = f"127.0.0.1:{self.server.server_port}"
            if self.headers.get("Host") != expected:
                self._json(403, {"error": "Откройте рабочее место по адресу 127.0.0.1."})
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin != f"http://{expected}":
                self._json(403, {"error": "Запрос с другого сайта отклонён."})
                return False
            if self.headers.get("Sec-Fetch-Site", "same-origin") not in {
                "same-origin", "none"
            }:
                self._json(403, {"error": "Запрос с другого сайта отклонён."})
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            if not self._local():
                return
            parsed = urlsplit(self.path)
            assets = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/workspace.css": ("workspace.css", "text/css; charset=utf-8"),
                "/workspace.js": ("workspace.js", "text/javascript; charset=utf-8"),
                "/tenderplan-review.js": ("tenderplan-review.js", "text/javascript; charset=utf-8"),
            }
            if parsed.path in assets:
                filename, media_type = assets[parsed.path]
                self._send(200, (ASSET_ROOT / filename).read_bytes(), media_type)
                return
            try:
                if parsed.path == "/api/session":
                    self._json(200, {
                        "actor": actor.strip(), "token": token, "demo": demo,
                        "tenderplan_review_enabled": tenderplan_review is not None,
                    })
                elif parsed.path == "/api/tenderplan/reviews" or parsed.path.startswith("/api/tenderplan/reviews/"):
                    if tenderplan_review is None:
                        self._json(404, {"error": "Просмотр источника не включён."})
                        return
                    if not secrets.compare_digest(self.headers.get("X-Workspace-Token", ""), token):
                        self._json(403, {"error": "Обновите страницу рабочего места."})
                        return
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    if parsed.path == "/api/tenderplan/reviews":
                        if set(query) - {"limit", "offset"} or any(len(values) != 1 for values in query.values()):
                            raise TenderPlanWorkbenchReviewError("INVALID")
                        result = tenderplan_review.list_references(
                            limit=int(query.get("limit", ["50"])[0]),
                            offset=int(query.get("offset", ["0"])[0]),
                        )
                    else:
                        if set(query) != {"reference_id"} or len(query["reference_id"]) != 1:
                            raise TenderPlanWorkbenchReviewError("INVALID")
                        result = tenderplan_review.detail(
                            parsed.path.removeprefix("/api/tenderplan/reviews/"),
                            reference_id=query["reference_id"][0],
                        )
                    self._json(200, result)
                elif parsed.path == "/api/objects":
                    query = parse_qs(parsed.query)
                    limit = int(query.get("limit", ["100"])[0])
                    offset = int(query.get("offset", ["0"])[0])
                    self._json(200, workspace.list_objects(limit=limit, offset=offset))
                elif parsed.path.startswith("/api/objects/"):
                    object_id = parsed.path.removeprefix("/api/objects/")
                    self._json(200, workspace.dossier(object_id))
                else:
                    self._json(404, {"error": "Страница не найдена."})
            except TenderPlanWorkbenchReviewError as error:
                self._json(error.status, {"error": str(error), "code": error.code})
            except KeyError:
                self._json(404, {"error": "Объект не найден."})
            except (ValueError, TypeError):
                self._json(400, {"error": "Проверьте параметры запроса."})
            except Exception:
                self._json(409, {"error": "Не удалось прочитать досье. Проверьте локальную базу."})

        def do_POST(self) -> None:  # noqa: N802
            self.close_connection = True
            if not self._local():
                return
            if not secrets.compare_digest(self.headers.get("X-Workspace-Token", ""), token):
                self._json(403, {"error": "Обновите страницу рабочего места."})
                return
            if self.headers.get_content_type() != "application/json":
                self._json(415, {"error": "Ожидается JSON."})
                return
            if self.headers.get("Transfer-Encoding"):
                self._json(400, {"error": "Неподдерживаемый формат запроса."})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                length = 0
            if not 0 < length <= MAX_BODY_BYTES:
                self._json(413, {"error": "Слишком большой или пустой запрос."})
                return
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError("object required")
                path = urlsplit(self.path).path
                parts = path.strip("/").split("/")
                if len(parts) != 4 or parts[:2] != ["api", "objects"]:
                    self._json(404, {"error": "Действие не найдено."})
                    return
                object_id, action = parts[2:]
                common = {
                    "expected_version": body["expected_version"],
                    "idempotency_key": body["idempotency_key"],
                }
                if action in {"assign", "reassign"}:
                    result = getattr(workspace, action)(
                        object_id,
                        assignee=body["assignee"],
                        due_at_utc=body["due_at_utc"],
                        **common,
                    )
                elif action == "result":
                    result = workspace.record_result(
                        object_id,
                        result=body["result"],
                        reason=body["reason"],
                        evidence_ref=body["evidence_ref"],
                        next_action=body.get("next_action", "NONE"),
                        next_action_at_utc=body.get("next_action_at_utc", ""),
                        **common,
                    )
                else:
                    self._json(404, {"error": "Действие не найдено."})
                    return
                self._json(200, result)
            except RadarWorkbenchConflict:
                self._json(409, {"error": "Досье изменилось или действие недоступно этому исполнителю. Обновите досье и проверьте задачу."})
            except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                self._json(400, {"error": "Заполните обязательные поля и проверьте срок."})
            except Exception:
                # Never disclose SQL, paths, personal notes or provider data.
                self._json(409, {"error": "Изменение отклонено. Обновите досье и проверьте исполнителя, версию и состояние задачи."})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server
