import http.client
import json
import os
import socket
import sqlite3
import tempfile
import unittest

from retrieval_service import netguard
from retrieval_service.db import Stores, open_read_only
from retrieval_service.server import ROUTES, TOKEN_HEADER, Service, make_server, serve_in_thread

TOKEN = "per-run-token"


class UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("local")
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)


def call(path, route, token=None, body=None):
    c = UnixConn(path)
    h = {"Content-Type": "application/json"}
    if token is not None:
        h[TOKEN_HEADER] = token
    c.request("POST", route, json.dumps(body or {}), h)
    r = c.getresponse()
    out = (r.status, json.loads(r.read()))
    c.close()
    return out


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "bellu.db")
        c = sqlite3.connect(self.db)
        c.execute("create table t(x)")
        c.commit()
        c.close()
        self.sock = os.path.join(self.dir, "r.sock")
        self.stores = Stores(self.db, None)
        self.svc = Service(TOKEN, self.stores, {
            "/v1/plan": lambda req, st: {"rows": st.get("bellu").execute("select count(*) from t").fetchone()[0]},
        })
        self.srv = make_server(self.svc, self.sock)
        serve_in_thread(self.srv)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.stores.close()

    def test_socket_is_owner_only(self):
        self.assertEqual(os.stat(self.sock).st_mode & 0o777, 0o600)

    def test_missing_or_wrong_token_rejected_without_read(self):
        for tok in (None, "", "wrong"):
            for route in ROUTES:
                status, body = call(self.sock, route, tok)
                self.assertEqual(status, 401)
                self.assertEqual(body["error"], "unauthorized")
        self.assertEqual(self.stores._conns, {})  # nothing was opened

    def test_valid_token_reads(self):
        self.assertEqual(call(self.sock, "/v1/plan", TOKEN), (200, {"rows": 0}))

    def test_unregistered_stage_501_and_unknown_route_404(self):
        self.assertEqual(call(self.sock, "/v1/rank", TOKEN)[0], 501)
        self.assertEqual(call(self.sock, "/v1/nope", TOKEN)[0], 404)

    def test_loopback_fallback_requires_token(self):
        srv = make_server(Service(TOKEN, Stores(None, None)), None, 0)
        serve_in_thread(srv)
        try:
            for tok, want in ((None, 401), (TOKEN, 501)):
                c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
                h = {TOKEN_HEADER: tok} if tok else {}
                c.request("POST", "/v1/rank", "{}", h)
                self.assertEqual(c.getresponse().status, want)
                c.close()
        finally:
            srv.shutdown()
            srv.server_close()


class ReadOnlyTest(unittest.TestCase):
    def test_writes_fail_and_missing_file_not_created(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "a.db")
        sqlite3.connect(p).execute("create table t(x)").connection.close()
        c = open_read_only(p)
        with self.assertRaises(sqlite3.OperationalError):
            c.execute("insert into t values(1)")
        c.close()
        with self.assertRaises(sqlite3.OperationalError):
            open_read_only(os.path.join(d, "missing.db"))
        self.assertFalse(os.path.exists(os.path.join(d, "missing.db")))


class NetGuardTest(unittest.TestCase):
    def test_ip_connect_blocked(self):
        netguard.install()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.assertRaises(netguard.OutboundNetworkBlocked):
            s.connect(("127.0.0.1", 9))
        s.close()
        netguard.uninstall()


if __name__ == "__main__":
    unittest.main()
