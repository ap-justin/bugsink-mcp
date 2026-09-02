"""OAuth 2.1 authorization server for this MCP server.

The claude.ai "Add custom connector" dialog takes a URL and nothing else, so a
static header token can never reach it — the only credential a connector can
carry is one it obtains itself. This mints those: the SDK supplies the
/authorize, /token, /register and /revoke handlers plus PKCE, and this module
supplies the storage behind them and the one human step in the middle, a login
page gated on a single shared password.

Everything persists to SQLite because Fly restarts the machine on deploy, and a
connector whose tokens lived in memory would silently need reconnecting each time.

The SDK owns the protocol checks — code expiry, redirect_uri equality between
/authorize and /token, PKCE verification, refresh scope subsets. What is left
here is storage, the password step, and the two things registration being
unauthenticated implies: a guess rate limit and a ceiling on stored clients.
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Sequence
from string import Template
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)

ACCESS_TOKEN_TTL = 3600  # 1 hour
REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30  # 30 days
AUTH_CODE_TTL = 300
PENDING_TTL = 600  # a login left open for 10 minutes is abandoned
CLIENT_TTL = 60 * 60 * 24 * 30  # a registration with no live token, unused this long, is gone
MAX_CLIENTS = 500
MIN_PASSWORD_LENGTH = 20
SCOPE = "bugsink"
SUBJECT = "owner"  # single-user server; every token belongs to the same principal

# /register is unauthenticated, so an attacker mints their own txns and guesses in
# parallel — a per-request sleep delays one attempt and limits nothing. The global
# counter is what caps the guess rate; the per-ip one just makes a single source hurt
# sooner. The trade the global counter buys is that an attacker can lock the owner out
# for LOCKOUT_MAX, which on a page used twice a year is the cheaper side.
IP_LOCKOUT_AFTER = 5
GLOBAL_LOCKOUT_AFTER = 20
GLOBAL_FAILURE_KEY = "global"
LOCKOUT_BASE = 5.0  # seconds, doubled per failure past the threshold
LOCKOUT_MAX = 900.0
FAILURE_WINDOW = 3600.0  # a counter untouched this long starts over

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending (
    txn TEXT PRIMARY KEY, client_id TEXT NOT NULL, params TEXT NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS codes (
    code_hash TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, data TEXT NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS login_failures (
    key TEXT PRIMARY KEY, count INTEGER NOT NULL, last_failure REAL NOT NULL, locked_until REAL NOT NULL);
"""


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def _migrate(db: sqlite3.Connection) -> None:
    """Bring a database file — fresh or already deployed — up to SCHEMA_VERSION.

    The deployed file predates user_version, so version 0 means either an empty file
    or the original four tables; every step below has to be safe for both.
    """
    version: int = db.execute("PRAGMA user_version").fetchone()[0]
    if version >= SCHEMA_VERSION:
        return

    db.executescript(_SCHEMA)
    now = time.time()

    if "last_seen" not in _columns(db, "clients"):
        db.execute("ALTER TABLE clients ADD COLUMN last_seen REAL NOT NULL DEFAULT 0")
        # an already-registered client starts its ttl now, not at the epoch, or the
        # first sweep after deploy takes every one of them
        db.execute("UPDATE clients SET last_seen = ?", (now,))

    token_columns = _columns(db, "tokens")
    if "client_id" not in token_columns:
        db.execute("ALTER TABLE tokens ADD COLUMN client_id TEXT NOT NULL DEFAULT ''")
    if "grant_id" not in token_columns:
        db.execute("ALTER TABLE tokens ADD COLUMN grant_id TEXT NOT NULL DEFAULT ''")

    # nothing records which pre-migration access token paired with which refresh token,
    # so each gets a grant of its own: revoking one then behaves as it did before rather
    # than taking every legacy token with it
    for token_hash, data in db.execute("SELECT token_hash, data FROM tokens WHERE grant_id = ''").fetchall():
        client_id = json.loads(data).get("client_id", "")
        db.execute(
            "UPDATE tokens SET grant_id = ?, client_id = ? WHERE token_hash = ?",
            (secrets.token_urlsafe(16), client_id, token_hash),
        )

    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    db.commit()


class Store:
    """SQLite-backed OAuth state. Tokens are stored hashed, never in the clear.

    Every statement runs on one connection under one lock: check_same_thread=False plus
    mutual exclusion, rather than thread affinity. busy_timeout is there for an external
    writer, since `fly ssh console` + sqlite3 is the documented way to sign every
    connector out.
    """

    def __init__(self, path: str) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        # NORMAL in WAL risks only the last commits to a power cut, and takes the fsync
        # off every token write — which on a network-backed volume is what blocks the loop
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        _migrate(self._db)

    def _write(self, sql: str, args: tuple[Any, ...] = ()) -> None:
        with self._lock:
            self._db.execute(sql, args)
            self._db.commit()

    def _read(self, sql: str, args: tuple[Any, ...] = ()) -> tuple[Any, ...] | None:
        with self._lock:
            return self._db.execute(sql, args).fetchone()

    # ---- clients -----------------------------------------------------------

    def get_client(self, client_id: str) -> str | None:
        row = self._read("SELECT data FROM clients WHERE client_id = ?", (client_id,))
        return row[0] if row else None

    def put_client(self, client_id: str, data: str) -> bool:
        """Store a registration. False when the table is full of clients worth keeping."""
        now = time.time()
        with self._lock:
            count = self._db.execute("SELECT count(*) FROM clients WHERE client_id <> ?", (client_id,)).fetchone()[0]
            if count >= MAX_CLIENTS:
                # evict least-recently-used registrations that never obtained a token:
                # that is what an unauthenticated /register fills the volume with, and a
                # paired client is protected by having rows in tokens
                self._db.execute(
                    "DELETE FROM clients WHERE client_id IN ("
                    "  SELECT client_id FROM clients"
                    "   WHERE client_id <> ? AND client_id NOT IN (SELECT client_id FROM tokens)"
                    "   ORDER BY last_seen ASC LIMIT ?)",
                    (client_id, count - MAX_CLIENTS + 1),
                )
                remaining = self._db.execute(
                    "SELECT count(*) FROM clients WHERE client_id <> ?", (client_id,)
                ).fetchone()[0]
                if remaining >= MAX_CLIENTS:
                    self._db.commit()
                    return False
            self._db.execute(
                "INSERT OR REPLACE INTO clients (client_id, data, last_seen) VALUES (?, ?, ?)",
                (client_id, data, now),
            )
            self._db.commit()
            return True

    def touch_client(self, client_id: str) -> None:
        """Restart a client's ttl. Called when it obtains a token, so CLIENT_TTL means idle."""
        self._write("UPDATE clients SET last_seen = ? WHERE client_id = ?", (time.time(), client_id))

    # ---- pending logins ----------------------------------------------------

    def put_pending(self, txn: str, client_id: str, params: str, expires_at: float) -> None:
        self._write(
            "INSERT INTO pending (txn, client_id, params, expires_at) VALUES (?, ?, ?, ?)",
            (txn, client_id, params, expires_at),
        )

    def get_pending(self, txn: str) -> tuple[str, str] | None:
        row = self._read("SELECT client_id, params FROM pending WHERE txn = ? AND expires_at > ?", (txn, time.time()))
        return (row[0], row[1]) if row else None

    def take_pending(self, txn: str) -> tuple[str, str] | None:
        """Claim and consume a pending login in one statement, so two simultaneous
        submissions of the same txn cannot both mint a code."""
        with self._lock:
            row = self._db.execute(
                "DELETE FROM pending WHERE txn = ? AND expires_at > ? RETURNING client_id, params",
                (txn, time.time()),
            ).fetchone()
            self._db.commit()
        return (row[0], row[1]) if row else None

    # ---- authorization codes -----------------------------------------------

    def put_code(self, code_hash: str, data: str, expires_at: float) -> None:
        self._write("INSERT INTO codes (code_hash, data, expires_at) VALUES (?, ?, ?)", (code_hash, data, expires_at))

    def get_code(self, code_hash: str) -> str | None:
        row = self._read("SELECT data FROM codes WHERE code_hash = ?", (code_hash,))
        return row[0] if row else None

    def delete_code(self, code_hash: str) -> None:
        self._write("DELETE FROM codes WHERE code_hash = ?", (code_hash,))

    # ---- tokens ------------------------------------------------------------

    def put_token(
        self, token_hash: str, kind: str, client_id: str, grant_id: str, data: str, expires_at: float
    ) -> None:
        self._write(
            "INSERT INTO tokens (token_hash, kind, client_id, grant_id, data, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (token_hash, kind, client_id, grant_id, data, expires_at),
        )

    def get_token(self, token_hash: str, kind: str) -> str | None:
        row = self._read(
            "SELECT data FROM tokens WHERE token_hash = ? AND kind = ? AND expires_at > ?",
            (token_hash, kind, time.time()),
        )
        return row[0] if row else None

    def grant_of(self, token_hash: str) -> str | None:
        row = self._read("SELECT grant_id FROM tokens WHERE token_hash = ?", (token_hash,))
        return row[0] if row else None

    def delete_token(self, token_hash: str) -> None:
        self._write("DELETE FROM tokens WHERE token_hash = ?", (token_hash,))

    def delete_grant(self, grant_id: str) -> None:
        self._write("DELETE FROM tokens WHERE grant_id = ?", (grant_id,))

    # ---- login throttle ----------------------------------------------------

    def lockout_until(self, keys: Sequence[str]) -> float:
        latest = 0.0
        for key in keys:
            row = self._read("SELECT locked_until FROM login_failures WHERE key = ?", (key,))
            if row:
                latest = max(latest, row[0])
        return latest

    def record_failure(self, thresholds: Sequence[tuple[str, int]]) -> float:
        """Count one failed attempt against each key. Returns when the caller may retry."""
        now = time.time()
        latest = 0.0
        with self._lock:
            for key, threshold in thresholds:
                row = self._db.execute(
                    "SELECT count, last_failure FROM login_failures WHERE key = ?", (key,)
                ).fetchone()
                count = row[0] + 1 if row and row[1] > now - FAILURE_WINDOW else 1
                locked_until = 0.0
                if count > threshold:
                    backoff = LOCKOUT_BASE * 2 ** min(count - threshold - 1, 20)
                    locked_until = now + min(backoff, LOCKOUT_MAX)
                self._db.execute(
                    "INSERT OR REPLACE INTO login_failures (key, count, last_failure, locked_until)"
                    " VALUES (?, ?, ?, ?)",
                    (key, count, now, locked_until),
                )
                latest = max(latest, locked_until)
            self._db.commit()
        return latest

    def clear_failures(self, keys: Sequence[str]) -> None:
        with self._lock:
            for key in keys:
                self._db.execute("DELETE FROM login_failures WHERE key = ?", (key,))
            self._db.commit()

    # ---- maintenance -------------------------------------------------------

    def revoke_everything(self) -> int:
        """Drop every issued grant and anything mid-flight. Returns the grants revoked."""
        with self._lock:
            grants = self._db.execute("SELECT count(DISTINCT grant_id) FROM tokens").fetchone()[0]
            self._db.execute("DELETE FROM tokens")
            self._db.execute("DELETE FROM codes")
            self._db.execute("DELETE FROM pending")
            self._db.commit()
        return int(grants)

    def sweep(self) -> None:
        """Drop anything expired. Cheap enough to run on every path that writes."""
        now = time.time()
        with self._lock:
            self._db.execute("DELETE FROM pending WHERE expires_at < ?", (now,))
            self._db.execute("DELETE FROM codes WHERE expires_at < ?", (now,))
            self._db.execute("DELETE FROM tokens WHERE expires_at < ?", (now,))
            self._db.execute(
                "DELETE FROM login_failures WHERE last_failure < ? AND locked_until < ?",
                (now - FAILURE_WINDOW, now),
            )
            self._db.execute(
                "DELETE FROM clients WHERE last_seen < ? AND client_id NOT IN (SELECT client_id FROM tokens)",
                (now - CLIENT_TTL,),
            )
            self._db.commit()


class BugsinkOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, store: Store, public_base: str, password: str) -> None:
        self.store = store
        self.public_base = public_base.rstrip("/")
        self._password = password.encode()

    # ---- clients (dynamic registration) ------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self.store.get_client(client_id)
        return OAuthClientInformationFull.model_validate_json(data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.store.sweep()
        if not self.store.put_client(client_info.client_id, client_info.model_dump_json()):
            logger.warning("refused registration: %d clients stored and none evictable", MAX_CLIENTS)
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="this server is not accepting new registrations right now",
            )
        logger.info("registered client %s (%s)", client_info.client_id, client_info.client_name)

    # ---- authorization -----------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Park the request and send the human to the login page.

        No code is minted here — only a successful password POST creates one.
        """
        self.store.sweep()
        txn = secrets.token_urlsafe(24)
        self.store.put_pending(txn, client.client_id, params.model_dump_json(), time.time() + PENDING_TTL)
        return f"{self.public_base}/login?txn={txn}"

    def check_password(self, attempt: str) -> bool:
        # bytes, not str: compare_digest raises TypeError on a str holding any non-ascii
        # character, which turns a mistyped password into a 500 and a non-ascii
        # MCP_PASSWORD into a server nobody can ever log into
        return secrets.compare_digest(attempt.encode(), self._password)

    def lockout_remaining(self, ip: str) -> float:
        """Seconds before this address may attempt a password again. 0 when it may now."""
        return max(0.0, self.store.lockout_until([_ip_key(ip), GLOBAL_FAILURE_KEY]) - time.time())

    def record_failure(self, ip: str) -> float:
        """Count one failed attempt. Returns the seconds it must now wait, 0 if none."""
        locked_until = self.store.record_failure(
            [(_ip_key(ip), IP_LOCKOUT_AFTER), (GLOBAL_FAILURE_KEY, GLOBAL_LOCKOUT_AFTER)]
        )
        return max(0.0, locked_until - time.time())

    def clear_failures(self, ip: str) -> None:
        self.store.clear_failures([_ip_key(ip), GLOBAL_FAILURE_KEY])

    def load_pending(self, txn: str) -> tuple[str, AuthorizationParams] | None:
        """Read a parked request without consuming it — the login page renders from this."""
        row = self.store.get_pending(txn)
        if row is None:
            return None
        client_id, params = row
        return client_id, AuthorizationParams.model_validate_json(params)

    def complete_login(self, txn: str) -> str | None:
        """Consume the parked request, mint the code, and hand back the client's redirect URL.

        Takes only the txn: client_id and the PKCE challenge come from the stored row, so
        nothing the login form posts can swap in a different client or drop the challenge.
        """
        claimed = self.store.take_pending(txn)
        if claimed is None:
            return None
        client_id, raw_params = claimed
        params = AuthorizationParams.model_validate_json(raw_params)
        code = secrets.token_urlsafe(32)
        auth_code = AuthorizationCode(
            code=code,
            scopes=params.scopes or [SCOPE],
            expires_at=time.time() + AUTH_CODE_TTL,
            client_id=client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject=SUBJECT,
        )
        self.store.put_code(_hash(code), auth_code.model_dump_json(), auth_code.expires_at)
        logger.info("issued authorization code to client %s", client_id)
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        data = self.store.get_code(_hash(authorization_code))
        if data is None:
            return None
        code = AuthorizationCode.model_validate_json(data)
        return code if code.client_id == client.client_id else None

    # ---- tokens ------------------------------------------------------------

    def _issue(
        self, client_id: str, scopes: list[str], resource: str | None, grant_id: str | None = None
    ) -> OAuthToken:
        self.store.sweep()
        # one grant spans an access token, its refresh token and everything a rotation
        # mints from them, so revoking any of them ends the whole thing
        grant = grant_id or secrets.token_urlsafe(16)
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = int(time.time())
        access_token = AccessToken(
            token=access,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + ACCESS_TOKEN_TTL,
            resource=resource,
            subject=SUBJECT,
        )
        refresh_token = RefreshToken(
            token=refresh, client_id=client_id, scopes=scopes, expires_at=now + REFRESH_TOKEN_TTL, subject=SUBJECT
        )
        self.store.put_token(
            _hash(access), "access", client_id, grant, access_token.model_dump_json(), now + ACCESS_TOKEN_TTL
        )
        self.store.put_token(
            _hash(refresh), "refresh", client_id, grant, refresh_token.model_dump_json(), now + REFRESH_TOKEN_TTL
        )
        self.store.touch_client(client_id)
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # single use: burn the code before the tokens exist, so a replay finds nothing
        self.store.delete_code(_hash(authorization_code.code))
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.resource)

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        data = self.store.get_token(_hash(refresh_token), "refresh")
        if data is None:
            return None
        token = RefreshToken.model_validate_json(data)
        return token if token.client_id == client.client_id else None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        # rotate: the presented refresh token dies with the exchange, but the grant carries
        # over so a later revoke still reaches everything minted from this authorization
        token_hash = _hash(refresh_token.token)
        grant = self.store.grant_of(token_hash)
        self.store.delete_token(token_hash)
        return self._issue(client.client_id, scopes or refresh_token.scopes, None, grant_id=grant)

    async def load_access_token(self, token: str) -> AccessToken | None:
        data = self.store.get_token(_hash(token), "access")
        return AccessToken.model_validate_json(data) if data else None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        # rfc 7009 §2.1: the whole grant goes. Deleting only the presented token would leave
        # its partner able to mint a replacement, which makes /revoke look like it worked
        grant = self.store.grant_of(_hash(token.token))
        if grant is None:
            return
        self.store.delete_grant(grant)
        logger.info("revoked grant for client %s", token.client_id)

    def sign_out_everything(self) -> int:
        """Revoke every grant this server has issued. Registrations survive, so a connector
        can re-authorize with its existing client_id rather than registering again."""
        grants = self.store.revoke_everything()
        logger.warning("signed out every connector: %d grants revoked", grants)
        return grants


def _ip_key(ip: str) -> str:
    return f"ip:{ip}"


def build_provider(*, db_path: str, public_base: str, password: str) -> BugsinkOAuthProvider:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise RuntimeError(
            f"MCP_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters: it is the only "
            "credential standing between the public internet and your error data"
        )
    parent = os.path.dirname(db_path)
    if parent:  # a bare filename, which is the natural local value, has no directory to make
        os.makedirs(parent, exist_ok=True)
    return BugsinkOAuthProvider(Store(db_path), public_base, password)


_STYLE = """<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 system-ui, sans-serif; display: grid; place-items: center;
         min-height: 100dvh; margin: 0; padding: 1.5rem; }
  form, .card { width: min(24rem, 100%); display: grid; gap: .75rem; }
  h1 { font-size: 1.15rem; margin: 0; }
  p { margin: 0; opacity: .7; }
  strong { font-weight: 600; }
  input, button { font: inherit; padding: .6rem .7rem; border-radius: .4rem;
                  border: 1px solid color-mix(in srgb, currentColor 30%, transparent); }
  button { background: currentColor; border: 0; cursor: pointer; }
  button span { color: Canvas; }
  .warn { opacity: 1; }
  .error { color: #c0392b; opacity: 1; }
</style>"""

# Template rather than str.format: the placeholders sit in a document full of CSS braces,
# and every value below is user- or client-supplied, so the render helpers escape them all.
LOGIN_PAGE = Template(f"""<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect to Bugsink</title>
{_STYLE}
<form method="post" action="/login">
  <h1><strong>$client_name</strong> wants to connect to your Bugsink</h1>
  <p>It is asking to read and triage the errors on this instance. After you authorize it,
     you will be sent to <strong>$redirect_host</strong>.</p>
  <p class="warn">If you did not just start this yourself, close this page and enter nothing.</p>
  <input type="hidden" name="txn" value="$txn">
  <input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required>
  $error
  <button type="submit"><span>Authorize</span></button>
</form>
""")

LOGOUT_PAGE = Template(f"""<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign out of Bugsink</title>
{_STYLE}
<form method="post" action="/logout">
  <h1>Sign out every connector</h1>
  <p>This revokes every token this server has issued. Anything connected stops working at
     once and has to be authorized again with this password.</p>
  <p class="warn">Use this if a connector was lost, shared, or you no longer recognize it.</p>
  <input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required>
  $error
  <button type="submit"><span>Sign out everything</span></button>
</form>
""")

LOGOUT_DONE = Template(f"""<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signed out of Bugsink</title>
{_STYLE}
<div class="card">
  <h1>Signed out.</h1>
  <p>$summary Reconnecting from claude.ai will ask for this password again.</p>
</div>
""")

EXPIRED_PAGE = "<h1>This login link has expired.</h1><p>Start the connection again.</p>"


def _error_block(error: str) -> str:
    return f'<p class="error">{html.escape(error)}</p>' if error else ""


def render_login_page(*, txn: str, client_name: str, redirect_host: str, error: str = "") -> str:
    """Render the consent page. Every argument is escaped here — callers pass plain text.

    The client name and redirect host come from a registration anyone can create, so
    showing them is the only thing that lets the owner tell their own connection attempt
    from a link someone sent them.
    """
    return LOGIN_PAGE.substitute(
        txn=html.escape(txn, quote=True),
        client_name=html.escape(client_name),
        redirect_host=html.escape(redirect_host),
        error=_error_block(error),
    )


def render_logout_page(*, error: str = "") -> str:
    return LOGOUT_PAGE.substitute(error=_error_block(error))


def render_logout_done(grants: int) -> str:
    summary = "Nothing was connected." if grants == 0 else f"{grants} grant{'' if grants == 1 else 's'} revoked."
    return LOGOUT_DONE.substitute(summary=html.escape(summary))
