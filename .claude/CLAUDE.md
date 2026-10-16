<!-- kru v0.148.0 · derived 2026-10-16 · /kru:setup to re-derive -->
## Team

Load **`kru:lead`** before building, reviewing, or dispatching a seat — it carries how the team works.

- **server** → `kru:python-developer` — `server.py`, `oauth.py` (mcp 2.1.1, httpx, uvicorn pinned in `requirements.txt`)
- **deploy** → `kru:fly-platform-engineer` — `Dockerfile`, `fly.toml`, `scripts/push-env.sh`
- **verify** — `uvx ruff check . && uvx ruff format --check .` (README); no test suite, no type checker

A slice reaching a stack no seat above covers is a question for the user, naming the seat it would need — never a nearby seat pressed into the gap.
