#!/usr/bin/env python3
"""
USAGE: 

python3 log-transaction.py \
  --base-url https://100.124.177.211 \
  --username "admin" \
  --password "admin" \
  --kc-admin-username "admin" \
  --kc-admin-password "admin" \
  --insecure

-----------------------------------------------
Transaction diff harvester (one-shot) with:
- Keycloak user token (auto-fetch client secret if needed)
- Keycloak LOGIN event lookup for User IP (realm=api_realm)
- Flattened output:
  * JSON -> 'a/b/c value'
  * 'a.b.c = value' or 'a.b.c   value' -> 'a/b/c value'
  * Curly-brace DSL (e.g., 'bfd { ... }') -> 'a/b/c value'
    - arrays like:
        key [
          1
          2
        ]
      become: key [1, 2]

Writes: Transaction-<id>.txt
"""

import argparse
import json
import re
import ssl
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen


# ------------------------------- Config & HTTP helpers -------------------------------

@dataclass
class Config:
    # API base; e.g. https://100.124.177.211
    base_url: str
    # Keycloak base (derived if omitted): <base_url>/core/httpproxy/v1/keycloak
    kc_url: Optional[str] = None
    # Realms
    api_realm: str = "eda"
    kc_admin_realm: str = "master"

    # App user creds (realm=api_realm)
    username: str = ""
    password: str = ""

    # OIDC client
    client_id: str = "eda"
    client_secret: Optional[str] = None
    scope: Optional[str] = "openid"

    # Admin creds to auto-fetch client_secret & read events
    kc_admin_username: Optional[str] = None
    kc_admin_password: Optional[str] = None

    # TLS/HTTP
    insecure: bool = False
    timeout: int = 30

    # Keycloak Events matching window (+/- seconds around commit time)
    event_window_seconds: int = 3600


def _ssl_ctx(insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_json(method: str, url: str, headers: Dict[str, str], data: Optional[bytes],
               ctx: ssl.SSLContext, timeout: int):
    req = Request(url=url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    with urlopen(req, context=ctx, timeout=timeout) as resp:
        raw = resp.read()
    return None if not raw else json.loads(raw.decode("utf-8"))


# ------------------------------- Keycloak helpers -----------------------------------

def _kc_base(cfg: Config) -> str:
    return (cfg.kc_url or (cfg.base_url.rstrip('/') + '/core/httpproxy/v1/keycloak')).rstrip('/')


def _kc_token_endpoint(cfg: Config, realm: str) -> str:
    return f"{_kc_base(cfg)}/realms/{realm}/protocol/openid-connect/token"


def _kc_admin_token(cfg: Config, ctx: ssl.SSLContext) -> str:
    if not (cfg.kc_admin_username and cfg.kc_admin_password):
        raise RuntimeError("Missing --kc-admin-username/--kc-admin-password for admin API")
    data = urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": cfg.kc_admin_username,
        "password": cfg.kc_admin_password,
    }).encode("utf-8")
    j = _http_json(
        "POST", _kc_token_endpoint(cfg, cfg.kc_admin_realm),
        {"Content-Type": "application/x-www-form-urlencoded"}, data, ctx, cfg.timeout
    )
    if not j or "access_token" not in j:
        raise RuntimeError("Admin auth failed: no access_token")
    return j["access_token"]


def _kc_fetch_client_secret(cfg: Config, ctx: ssl.SSLContext) -> str:
    admin_token = _kc_admin_token(cfg, ctx)
    clients = _http_json(
        "GET", f"{_kc_base(cfg)}/admin/realms/{cfg.api_realm}/clients",
        {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
        None, ctx, cfg.timeout
    ) or []
    kc_id = next((c.get("id") for c in clients if c.get("clientId") == cfg.client_id), None)
    if not kc_id:
        raise RuntimeError(f"Client '{cfg.client_id}' not found in realm '{cfg.api_realm}'")
    secret_json = _http_json(
        "GET", f"{_kc_base(cfg)}/admin/realms/{cfg.api_realm}/clients/{kc_id}/client-secret",
        {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
        None, ctx, cfg.timeout
    ) or {}
    val = secret_json.get("value") or secret_json.get("secret")
    if not val:
        raise RuntimeError("Failed to fetch client secret")
    return val


def get_token(cfg: Config, ctx: ssl.SSLContext) -> str:
    client_secret = cfg.client_secret or _kc_fetch_client_secret(cfg, ctx)
    body = {
        "client_id": cfg.client_id,
        "grant_type": "password",
        "scope": cfg.scope or "openid",
        "username": cfg.username,
        "password": cfg.password,
        "client_secret": client_secret,
    }
    j = _http_json(
        "POST", _kc_token_endpoint(cfg, cfg.api_realm),
        {"Content-Type": "application/x-www-form-urlencoded"},
        urlencode(body).encode("utf-8"),
        ctx, cfg.timeout
    )
    if not j or "access_token" not in j:
        raise RuntimeError("Auth failed: no access_token in response")
    return j["access_token"]


# ------------------------------- Keycloak events (user IP) --------------------------

def _iso_to_epoch_ms(ts: str) -> int:
    """ISO8601 '...Z' -> epoch milliseconds UTC."""
    ts = (ts or "").strip()
    if not ts:
        return 0
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _kc_find_user_id(cfg: Config, ctx: ssl.SSLContext, admin_token: str, username: str) -> Optional[str]:
    base_headers = {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"}
    # exact match first
    url = f"{_kc_base(cfg)}/admin/realms/{cfg.api_realm}/users?username={quote(username)}&exact=true"
    users = _http_json("GET", url, base_headers, None, ctx, cfg.timeout) or []
    if not users:
        url = f"{_kc_base(cfg)}/admin/realms/{cfg.api_realm}/users?search={quote(username)}"
        users = _http_json("GET", url, base_headers, None, ctx, cfg.timeout) or []
        users = [u for u in users if (u.get("username") or "").lower() == username.lower()]
    return users[0].get("id") if users else None


def get_user_login_ip_near_commit(cfg: Config, ctx: ssl.SSLContext, username: str, commit_iso_ts: str) -> Optional[str]:
    admin_token = _kc_admin_token(cfg, ctx)
    user_id = _kc_find_user_id(cfg, ctx, admin_token, username)
    if not user_id:
        return None

    commit_ms = _iso_to_epoch_ms(commit_iso_ts)
    window_ms = max(1, cfg.event_window_seconds) * 1000

    params = {"type": "LOGIN", "user": user_id, "max": 100}
    url = f"{_kc_base(cfg)}/admin/realms/{cfg.api_realm}/events?{urlencode(params)}"
    events = _http_json("GET", url, {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
                        None, ctx, cfg.timeout) or []

    best_ip = None
    best_diff = None
    for ev in events:
        ev_time = ev.get("time")  # epoch ms
        ip = ev.get("ipAddress")
        if ev_time is None or not ip:
            continue
        diff = abs(int(ev_time) - commit_ms)
        if diff <= window_ms and (best_diff is None or diff < best_diff or
                                  (diff == best_diff and int(ev_time) <= commit_ms)):
            best_ip = ip
            best_diff = diff
    return best_ip


# ------------------------------- Flattening & diff -----------------------------------

_key_val_re = re.compile(r"^\s*(?P<key>[^=\s].*?)(?:\s*=\s*|\s+)(?P<val>.+?)\s*$")

def _dot_or_space_line_to_flat(line: str) -> Optional[str]:
    """
    Convert:
      'a.b.c = v'  -> 'a/b/c v'
      'a.b.c   v'  -> 'a/b/c v'
    Returns None if it doesn't match.
    """
    m = _key_val_re.match(line)
    if not m:
        return None
    key, val = m.group("key"), m.group("val")
    key = key.replace(".", "/")
    key = re.sub(r"\[(\d+)\]", r"/\1", key)
    key = re.sub(r"/+", "/", key).strip("/")
    return f"{key} {val}"


def _flatten_json(obj, prefix: str = "") -> List[str]:
    """Flatten JSON into 'path value' using '/' and numeric indices."""
    lines: List[str] = []
    if isinstance(obj, dict):
        for k in sorted(obj.keys()):
            newp = f"{prefix}/{k}" if prefix else str(k)
            lines.extend(_flatten_json(obj[k], newp))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            newp = f"{prefix}/{i}" if prefix else str(i)
            lines.extend(_flatten_json(v, newp))
    else:
        val = json.dumps(obj, ensure_ascii=False, sort_keys=True)
        lines.append(f"{prefix} {val}")
    return lines


def _flatten_curly_dsl(text: str) -> List[str]:
    """
    Flatten a brace-based DSL:
      block start: 'a b c {'
      leaf:        'key value...'
      array:       'key [', then values on lines, ending with ']'
    into 'a/b/c/key value'.
    """
    lines = text.splitlines()
    path_stack: List[str] = []
    block_depth: List[int] = []  # how many segments were pushed for each '{'
    out: List[str] = []

    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        s = raw.strip()
        i += 1
        if not s:
            continue

        # Close braces
        if s == "}" or s.startswith("}"):
            if block_depth:
                pops = block_depth.pop()
                for _ in range(pops):
                    if path_stack:
                        path_stack.pop()
            continue

        # Block open: '... {'
        if s.endswith("{"):
            content = s[:-1].strip()
            toks = content.split() if content else []
            for t in toks:
                path_stack.append(t)
            block_depth.append(len(toks))
            continue

        # Array on a single line: 'key [ ... ]'
        m1 = re.match(r"^(?P<k>\S+)\s*\[\s*(?P<vals>.*?)\s*\]\s*$", s)
        if m1:
            k = m1.group("k")
            vals = m1.group("vals").strip()
            if vals:
                # normalize whitespace -> comma separated
                inner = [v for v in re.split(r"[,\s]+", vals) if v]
                val = "[" + ", ".join(inner) + "]"
            else:
                val = "[]"
            out.append(f"{'/'.join(path_stack + [k])} {val}")
            continue

        # Multiline array: 'key [' then items on new lines until ']'
        if s.endswith("["):
            k = s[:-1].strip()
            inner_vals: List[str] = []
            while i < n:
                inner = lines[i].strip()
                i += 1
                if inner == "]" or inner.endswith("]"):
                    break
                if inner:
                    # strip trailing commas
                    inner_vals.append(inner.rstrip(","))
            # normalize numbers/words -> comma-separated
            # if items were split across words, keep each line as an item
            # also split by whitespace within a line and keep tokens
            tokens: List[str] = []
            for itm in inner_vals:
                # preserve quoted strings as-is; otherwise split on whitespace/commas
                if (itm.startswith('"') and itm.endswith('"')) or (itm.startswith("'") and itm.endswith("'")):
                    tokens.append(itm)
                else:
                    tokens += [t for t in re.split(r"[,\s]+", itm) if t]
            val = "[" + ", ".join(tokens) + "]"
            out.append(f"{'/'.join(path_stack + [k])} {val}")
            continue

        # Leaf: 'key value...'  (ignore lone keywords without a value)
        parts = s.split(None, 1)
        if len(parts) == 2:
            k, v = parts[0], parts[1]
            out.append(f"{'/'.join(path_stack + [k])} {v}")
            continue

        # Otherwise keep as-is (rare)
        out.append(f"{'/'.join(path_stack + [s])}")
    return out


def _normalize_text_block(s: str) -> List[str]:
    """
    Preferred order:
      1) JSON -> flatten
      2) Curly-brace DSL -> flatten
      3) 'a.b.c = v' or 'a.b.c  v' -> rewrite
      4) Raw lines (fallback)
    """
    t = (s or "").strip()
    if not t:
        return []
    # JSON
    try:
        obj = json.loads(t)
        return _flatten_json(obj)
    except Exception:
        pass
    # DSL?
    if "{" in t or "}" in t:
        return _flatten_curly_dsl(t)
    # dot/equals style
    out: List[str] = []
    for raw in t.splitlines():
        flat = _dot_or_space_line_to_flat(raw)
        out.append(flat if flat is not None else raw.strip())
    return out


def ndiff_delta(before: str, after: str) -> List[str]:
    """Compute +/- only diff on the normalized (flattened) lines."""
    import difflib
    b = _normalize_text_block(before)
    a = _normalize_text_block(after)
    diff = list(difflib.ndiff(b, a))

    out: List[str] = []
    seen_pairs = set()
    seen_singles = set()
    i = 0
    while i < len(diff):
        d = diff[i]
        if d.startswith("- "):
            minus = "-" + d[2:]
            if i + 1 < len(diff) and diff[i + 1].startswith("+ "):
                plus = "+" + diff[i + 1][2:]
                pair = (minus, plus)
                if pair not in seen_pairs:
                    out.extend([minus, plus])
                    seen_pairs.add(pair)
                i += 2
            else:
                if minus not in seen_singles:
                    out.append(minus)
                    seen_singles.add(minus)
                i += 1
        elif d.startswith("+ "):
            plus = "+" + d[2:]
            if plus not in seen_singles:
                out.append(plus)
                seen_singles.add(plus)
            i += 1
        else:
            i += 1
    return out


# ------------------------------- EDA API helpers ------------------------------------

def api_get(cfg: Config, token: str, path_qs: str, ctx: ssl.SSLContext):
    url = cfg.base_url.rstrip("/") + "/" + path_qs.lstrip("/")
    return _http_json(
        "GET", url,
        {"Accept": "application/json", "Authorization": f"Bearer {token}"},
        None, ctx, cfg.timeout
    )


def latest_transaction_ok(summary_json: Dict) -> Optional[Tuple[int, str, str]]:
    results = (summary_json or {}).get("results") or []
    if not results:
        return None
    r0 = results[0]
    if not (r0.get("dryRun") is False and r0.get("state") == "complete" and r0.get("success") is True):
        return None
    return int(r0["id"]), r0.get("username", ""), r0.get("lastChangeTimestamp", "")


def run_once(cfg: Config, ctx: ssl.SSLContext) -> Optional[int]:
    token = get_token(cfg, ctx)

    summary = api_get(cfg, token, "core/transaction/v2/result/summary?size=1", ctx)
    ok = latest_transaction_ok(summary)
    if not ok:
        print("No eligible transaction (dryRun=false, state=complete, success=true) found.", file=sys.stderr)
        return None

    tx_id, tx_user, tx_time = ok

    # Resolve user IP (best effort)
    user_ip = "Could not obtain IP from Keycloak, please enable Keycloak > Realm Settings> Events > User events settings > Save Events = On"
    try:
        hit_ip = get_user_login_ip_near_commit(cfg, ctx, tx_user, tx_time)
        if hit_ip:
            user_ip = hit_ip
    except Exception as e:
        print(f"[WARN] Keycloak events lookup: {e}", file=sys.stderr)

    exec_json = api_get(cfg, token, f"core/transaction/v2/result/execution/{tx_id}", ctx) or {}
    nodes = exec_json.get("nodesWithConfigChanges") or []
    node_pairs = [(n.get("name"), n.get("namespace")) for n in nodes if n.get("name") and n.get("namespace")]

    log_lines: List[str] = []

    def _fmt_line(change: str, node: str = "", ns: str = "") -> str:
        return f"{tx_time} , {tx_id} , {tx_user} , {user_ip} , {node} , {ns} , {change}"

    if node_pairs:
        for node, ns in node_pairs:
            qs = f"core/transaction/v2/result/diffs/nodecfg/{tx_id}?node={quote(node)}&namespace={quote(ns)}"
            diff_json = api_get(cfg, token, qs, ctx) or {}
            before = ((diff_json.get("before") or {}).get("data")) or ""
            after = ((diff_json.get("after") or {}).get("data")) or ""
            delta = ndiff_delta(before, after)

            if delta:
                for change in delta:
                    log_lines.append(_fmt_line(change, node, ns))
    if not log_lines:
        log_lines.append(_fmt_line("(no config changes)"))

    out = Path(f"Transaction-{tx_id}.txt")
    out.write_text("\n".join(log_lines), encoding="utf-8")
    print(f"Wrote {out.resolve()}")
    return tx_id


# ------------------------------------ CLI ------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Fetch latest transaction and write flattened per-node config deltas (one-shot)")
    p.add_argument("--base-url", required=True, help="API base, e.g. https://100.124.177.211")

    # Keycloak options
    p.add_argument("--kc-url", default=None, help="Keycloak base, e.g. https://host/core/httpproxy/v1/keycloak")
    p.add_argument("--api-realm", default="eda")
    p.add_argument("--kc-admin-realm", default="master")

    # App user (realm=api_realm)
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)

    # OIDC client
    p.add_argument("--client-id", default="eda")
    p.add_argument("--client-secret", default=None, help="If omitted, will fetch via Keycloak Admin")
    p.add_argument("--scope", default="openid")

    # Admin creds (needed if --client-secret omitted, and to read events for IP)
    p.add_argument("--kc-admin-username", default=None)
    p.add_argument("--kc-admin-password", default=None)

    # Events matching window
    p.add_argument("--event-window-seconds", type=int, default=3600,
                   help="Match LOGIN event within +/- this many seconds of the commit time (default 3600)")

    # TLS/HTTP
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification (self-signed certs)")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds")

    args = p.parse_args()
    cfg = Config(
        base_url=args.base_url,
        kc_url=args.kc_url,
        api_realm=args.api_realm,
        kc_admin_realm=args.kc_admin_realm,
        username=args.username,
        password=args.password,
        client_id=args.client_id,
        client_secret=args.client_secret,
        scope=args.scope,
        kc_admin_username=args.kc_admin_username,
        kc_admin_password=args.kc_admin_password,
        insecure=args.insecure,
        timeout=args.timeout,
        event_window_seconds=args.event_window_seconds,
    )
    ctx = _ssl_ctx(cfg.insecure)

    try:
        run_once(cfg, ctx)
    except Exception as e:
        print(f"[WARN] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
