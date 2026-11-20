# Retrieval service

Local Python subprocess started by bellud. Endpoints: `/v1/plan`, `/v1/retrieve`,
`/v1/rank`, `/v1/select`, `/v1/compile` (POST, JSON). Stage logic (S0 to S5) registers
in `Service.handlers` in later tasks; unregistered stages return 501.

- Listens on a Unix socket (mode 0600), or loopback when no socket path is set.
- Every request needs the `X-Bellu-Retrieval-Token` header (per-run token from
  `BELLU_RETRIEVAL_TOKEN`). Without it: 401 and no database read.
- `bellu.db` and `graph.db` open with `mode=ro` and `PRAGMA query_only = ON`.
- No vault access; outbound IP connections are blocked in-process.

Run tests: `python3 -m unittest discover -s tests` (stdlib only).
