"""Read-only SQLite access (Requirement 20.10).

Both bellu.db and the installed graph.db are opened with
file:<path>?mode=ro and PRAGMA query_only = ON. The file is never created.
"""
import sqlite3
import urllib.parse


def open_read_only(path: str) -> sqlite3.Connection:
    uri = "file:" + urllib.parse.quote(path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.execute("PRAGMA query_only = ON")
    return conn


class Stores:
    """Lazily opened read-only connections. Nothing is opened before auth."""

    def __init__(self, bellu_db: str | None, graph_db: str | None):
        self._paths = {"bellu": bellu_db, "graph": graph_db}
        self._conns: dict[str, sqlite3.Connection] = {}

    def get(self, name: str) -> sqlite3.Connection:
        path = self._paths.get(name)
        if not path:
            raise LookupError(f"{name} database path not configured")
        if name not in self._conns:
            self._conns[name] = open_read_only(path)
        return self._conns[name]

    def close(self) -> None:
        for c in self._conns.values():
            c.close()
        self._conns.clear()
