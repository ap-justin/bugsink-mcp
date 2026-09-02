# bugsink-mcp

A remote [MCP](https://modelcontextprotocol.io) server for a self-hosted [Bugsink](https://www.bugsink.com) instance, so Claude Code and claude.ai can read your error tracking and triage issues.

One deploy runs on a single Fly.io machine, fronts one Bugsink instance with one API token, and lets connectors in through OAuth 2.1 gated by one shared password. It is read and triage only by design.

## Tools

Read:

| Tool | What it returns |
| --- | --- |
| `list_projects` | Projects with event counts |
| `list_issues` | A project's issues, newest-seen first; sortable, paginated |
| `get_issue` | One issue: type, value, counts, resolved/muted state |
| `list_events` | Stored occurrences of an issue |
| `get_event` | One event with its rendered stacktrace, optionally the raw payload |
| `get_event_stacktrace` | Frames, source context and locals as text |
| `get_latest_event_stacktrace` | The newest occurrence of an issue, rendered |

Triage:

| Tool | What it does |
| --- | --- |
| `resolve_issue` | Unconditionally, or until the next / latest release |
| `reopen_issue` | Reopen a resolved issue |
| `mute_issue` / `unmute_issue` | Indefinitely or for a fixed span |
| `comment_on_issue` | Leave a comment visible in the Bugsink UI |

Issues are addressable by UUID or by their short friendly id.

Every event payload is text an attacker chose: any error in a monitored app becomes a string the model reads, so the write surface stays as small as it is.

## Deploy your own

You need a Bugsink instance reachable over HTTPS, a Bugsink API token (Bugsink UI, **Tokens** menu), and [`flyctl`](https://fly.io/docs/flyctl/install/).

1. Clone this repo and edit the three values at the top of `fly.toml`: `app`, `BUGSINK_URL`, `PUBLIC_HOST`. `PUBLIC_HOST` is normally `<app>.fly.dev`. Pick a `primary_region` near your Bugsink instance.

2. Create the app and the volume that keeps OAuth grants alive across deploys:

   ```sh
   fly apps create <app>
   fly volumes create mcp_data --app <app> --region <region> --size 1
   ```

3. Set the two secrets:

   ```sh
   cp .env.example .env     # fill in BUGSINK_TOKEN and MCP_PASSWORD
   ./scripts/push-env.sh --stage
   ```

   `MCP_PASSWORD` must be at least 20 characters or the server refuses to start.

4. Deploy:

   ```sh
   fly deploy
   curl https://<PUBLIC_HOST>/health
   ```

## Connect from Claude Code

```sh
claude mcp add --transport http bugsink https://<PUBLIC_HOST>/mcp
```

Adding the server does not authenticate it. Run `/mcp` in a session and authenticate from there; the password is `MCP_PASSWORD`.

To share the connection with everyone working in a repo, add it at project scope instead. That writes a `.mcp.json` you can commit; committing it shares the URL, not access, so each person still needs the password.

```sh
claude mcp add --transport http --scope project bugsink https://<PUBLIC_HOST>/mcp
```

## Connect from claude.ai

Add `https://<PUBLIC_HOST>/mcp` as a custom connector.

## Access model

One deploy has one principal. Every token the server issues belongs to the same owner, whoever typed the password. Giving someone the password gives them everything the tools can do against your Bugsink instance. For separate access, run separate deploys.

- **Revoke everyone.** Open `https://<PUBLIC_HOST>/logout` and enter the password. Every issued token dies. Connectors reconnect by logging in again.
- **Rotate the password.** Change `MCP_PASSWORD` in `.env`, run `./scripts/push-env.sh`, then visit `/logout` with the new password. Changing the password alone does not sign out existing connectors.
- **Cut off the server.** Delete the API token in Bugsink. Every tool call fails immediately.
- **Locked out.** A 429 on the login or logout page means too many wrong guesses, from you or from anyone else. It clears on its own within 15 minutes.

## Run locally

```sh
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt

export BUGSINK_URL=https://bugsink.example.com
export BUGSINK_TOKEN=...
export MCP_PASSWORD=$(openssl rand -hex 16)
export PUBLIC_HOST=127.0.0.1
export PUBLIC_BASE=http://127.0.0.1:8000
export OAUTH_DB_PATH=./oauth.db
uvicorn server:app --port 8000
```

```sh
claude mcp add --transport http bugsink-local http://127.0.0.1:8000/mcp
```

## Configuration

| Variable | Where | Meaning |
| --- | --- | --- |
| `BUGSINK_URL` | `fly.toml` | Public URL of your Bugsink instance |
| `PUBLIC_HOST` | `fly.toml` | Hostname this server answers on; other `Host` headers are rejected |
| `BUGSINK_TOKEN` | secret | Bugsink API token |
| `MCP_PASSWORD` | secret | Login-page password, 20+ characters |
| `PUBLIC_BASE` | optional | OAuth issuer URL. Defaults to `https://<PUBLIC_HOST>`; set for local runs |
| `OAUTH_DB_PATH` | optional | SQLite file for clients and tokens. Defaults to `/data/oauth.db`, the Fly volume |

## How it works

- `server.py` is the tools and the transport.
- `oauth.py` is the authorization server and the login page.

Each module's docstring carries the design. Tested against Bugsink 2.5.

## Development

```sh
uvx ruff check . && uvx ruff format --check .
```

## License

MIT
