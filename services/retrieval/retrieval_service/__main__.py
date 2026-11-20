"""Entry point. bellud passes configuration through the environment only:

  BELLU_RETRIEVAL_TOKEN   per-run token (required)
  BELLU_RETRIEVAL_SOCKET  Unix socket path (preferred)
  BELLU_RETRIEVAL_PORT    loopback port when no socket path is given (0 = any)
  BELLU_DB, BELLU_GRAPH_DB  paths opened read-only

No vault path or credential is read here.
"""
import os
import sys

from . import netguard
from .db import Stores
from .planner import plan_handler
from .server import Service, make_server


def main() -> int:
    token = os.environ.get("BELLU_RETRIEVAL_TOKEN", "")
    if not token:
        print("BELLU_RETRIEVAL_TOKEN is required", file=sys.stderr)
        return 2
    netguard.install()
    stores = Stores(os.environ.get("BELLU_DB"), os.environ.get("BELLU_GRAPH_DB"))
    svc = Service(token, stores, {"/v1/plan": plan_handler})
    sock = os.environ.get("BELLU_RETRIEVAL_SOCKET")
    srv = make_server(svc, sock, int(os.environ.get("BELLU_RETRIEVAL_PORT", "0")))
    if not sock:
        print("LISTEN 127.0.0.1:%d" % srv.server_address[1], flush=True)
    else:
        print("LISTEN unix:" + sock, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        stores.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
