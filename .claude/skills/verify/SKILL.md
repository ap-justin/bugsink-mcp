---
name: verify
description: Typecheck and lint this repo before a commit. Written by /kru:setup from the sheet's `verify` line.
---

Run from the repo root: `uvx ruff check . && uvx ruff format --check .`. Red → fix it before the commit; the commit waits.
