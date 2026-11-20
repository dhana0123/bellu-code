"""HTTP/JSON server for /v1/plan, /v1/retrieve, /v1/rank, /v1/select, /v1/compile.

Listens on a Unix domain socket, or on loopback when no Unix socket exists.
Every request must carry the per-run token; a request without it is rejected
with 401 before any handler or database read runs (Requirement 20.19).
"""
import hmac
import http.server
import json
import os
import socket
import socketserver
import threading
from typing import Callable

from .db import Stores

ROUTES = ("/v1/plan", "/v1/retrieve", "/v1/rank", "/v1/select", "/v1/compile")
TOKEN_HEADER = "X-Bellu-Retrieval-Token"
MAX_BODY = 4 << 20

Handler = Callable[[dict, Stores], dict]


class Service:
    def __init__(self, token: str, stores: Stores, handlers: dict[str, Handler] | None = None):
        if not token:
            raise ValueError("a per-run token is required")
        self.token = token
        self.stores = stores
        # Stage implementations (S0 to S5) register here in later tasks.
        self.handlers: dict[str, Handler] = dict(handlers or {})

    def token_ok(self, presented: str | None) -> bool:
        return presented is not None and hmac.compare_digest(
            presented.encode(), self.token.encode())


class _Req(http.server.BaseHTTPRequestHandler):
    server_version = "bellu-retrieval"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # no request logging: bodies may hold user text
        pass

    def address_string(self):
        return "local"

    def _send(self, status: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _auth(self) -> bool:
        svc: Service = self.server.service
        if svc.token_ok(self.headers.get(TOKEN_HEADER)):
            return True
        self.close_connection = True
        self._send(401, {"error": "unauthorized", "message": "missing or invalid token"})
        return False

    def do_POST(self):
        if not self._auth():  # before routing, body read, and any db access
            return
        if self.path not in ROUTES:
            return self._send(404, {"error": "not_found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            return self._send(400, {"error": "bad_request", "message": "invalid body length"})
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(req, dict):
                raise ValueError("body must be a JSON object")
        except ValueError as e:
            return self._send(400, {"error": "bad_request", "message": str(e)})
        svc: Service = self.server.service
        fn = svc.handlers.get(self.path)
        if fn is None:
            return self._send(501, {"error": "not_implemented", "message": self.path})
        try:
            self._send(200, fn(req, svc.stores))
        except ValueError as e:  # invalid input from the caller, e.g. invalid_question
            self._send(400, {"error": getattr(e, "code", "bad_request"), "message": str(e)})
        except LookupError as e:
            self._send(500, {"error": "store_unavailable", "message": str(e)})
        except Exception:
            self._send(500, {"error": "internal"})

    def do_GET(self):
        if not self._auth():
            return
        self._send(404, {"error": "not_found"})


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        sock, _ = super().get_request()
        return sock, ("local", 0)


class _LoopbackServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(service: Service, unix_path: str | None = None, loopback_port: int = 0):
    """Return a bound server. Uses a Unix socket when available, else 127.0.0.1."""
    if unix_path and hasattr(socket, "AF_UNIX"):
        try:
            os.unlink(unix_path)
        except FileNotFoundError:
            pass
        old = os.umask(0o077)
        try:
            srv = _UnixServer(unix_path, _Req)
        finally:
            os.umask(old)
        os.chmod(unix_path, 0o600)
    else:
        srv = _LoopbackServer(("127.0.0.1", loopback_port), _Req)
    srv.service = service
    return srv


def serve_in_thread(srv) -> threading.Thread:
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t
