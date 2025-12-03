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
import urllib.error
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

    # Keycloak user/admin events logging
    user_event_page_size: int = 500

    # Transaction polling (page size for summary pagination; all pages are fetched)
    summary_size: int = 200
    start_id: int = 1
    max_missing: int = 20
    state_file: str = "transaction_state.json"


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

def _parse_iso_datetime(ts: str) -> Optional[datetime]:
    ts = (ts or "").strip()
    if not ts:
        return None
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _iso_to_epoch_ms(ts: str) -> int:
    """ISO8601 -> epoch milliseconds (respecting timezone in the string or assuming UTC)."""
    ts = (ts or "").strip()
    if not ts:
        return 0
    dt = _parse_iso_datetime(ts)
    if not dt:
        return 0
    return int(dt.timestamp() * 1000)


def _dt_to_iso_local(dt: datetime) -> Tuple[str, datetime]:
    """Return (ISO string, localized dt) with seconds precision in the server's local timezone."""
    dt_local = dt.astimezone()
    iso = dt_local.isoformat(timespec="seconds")
    return iso, dt_local


def _dt_to_display(dt: datetime) -> str:
    _, dt_local = _dt_to_iso_local(dt)
    tzname = dt_local.tzname() or "local"
    return f"{dt_local.strftime('%Y-%m-%dT%H:%M:%S')} {tzname}"


def _normalize_iso_ts(ts: str) -> Tuple[str, str, int]:
    """
    Return (iso_local, display, epoch_ms) from a raw ISO-ish string; falls back to now if parse fails.
    """
    dt = _parse_iso_datetime(ts) or datetime.now(timezone.utc)
    iso_local, _ = _dt_to_iso_local(dt)
    return iso_local, _dt_to_display(dt), int(dt.timestamp() * 1000)


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


# ------------------------------- Keycloak user/admin event logging ------------------

_ALLOWED_LOGIN_EVENTS = {"LOGIN", "LOGOUT"}
_ALLOWED_ADMIN_RESOURCE_TYPES = {"USER", "GROUP", "CLIENT_ROLE", "USER_FEDERATION", "COMPONENT", "REALM_ROLE", "REALM"}
_ALLOWED_ADMIN_OPS = {"CREATE", "UPDATE", "DELETE"}


def _iso_from_epoch_ms(ms: int) -> str:
    try:
        dt = datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)
        iso_local, _ = _dt_to_iso_local(dt)
        return iso_local
    except Exception:
        return "unknown-time"


def _kc_fetch_login_logout_events(cfg: Config, ctx: ssl.SSLContext, admin_token: str) -> List[Dict]:
    params = [("max", cfg.user_event_page_size)]
    for t in sorted(_ALLOWED_LOGIN_EVENTS):
        params.append(("type", t))
    url = f"{_kc_base(cfg)}/admin/realms/{cfg.api_realm}/events?{urlencode(params, doseq=True)}"
    return _http_json(
        "GET", url,
        {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
        None, ctx, cfg.timeout
    ) or []


def _kc_fetch_admin_events(cfg: Config, ctx: ssl.SSLContext, admin_token: str) -> List[Dict]:
    base_params = [("max", cfg.user_event_page_size)]
    for op in sorted(_ALLOWED_ADMIN_OPS):
        base_params.append(("operationTypes", op))

    def _do(params: List[Tuple[str, str]]) -> List[Dict]:
        url = f"{_kc_base(cfg)}/admin/realms/{cfg.api_realm}/admin-events?{urlencode(params, doseq=True)}"
        return _http_json(
            "GET", url,
            {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
            None, ctx, cfg.timeout
        ) or []

    # Some Keycloak versions error when resourceTypes is provided; try with, then without.
    try:
        params = list(base_params)
        for rt in sorted(_ALLOWED_ADMIN_RESOURCE_TYPES):
            params.append(("resourceTypes", rt))
        return _do(params)
    except Exception:
        try:
            return _do(base_params)
        except Exception:
            return []


def _kc_resolve_username_by_id(cfg: Config, ctx: ssl.SSLContext, admin_token: str, user_id: str,
                               cache: Dict[str, Optional[str]]) -> Optional[str]:
    if not user_id:
        return None
    if user_id in cache:
        return cache[user_id]
    try:
        url = f"{_kc_base(cfg)}/admin/realms/{cfg.api_realm}/users/{quote(user_id)}"
        j = _http_json(
            "GET", url,
            {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
            None, ctx, cfg.timeout
        ) or {}
        username = j.get("username") or j.get("email") or j.get("id")
    except Exception:
        username = None
    cache[user_id] = username
    return username


def _kc_resolve_groupname_by_id(cfg: Config, ctx: ssl.SSLContext, admin_token: str, group_id: str,
                                cache: Dict[str, Optional[str]]) -> Optional[str]:
    if not group_id:
        return None
    if group_id in cache:
        return cache[group_id]
    try:
        url = f"{_kc_base(cfg)}/admin/realms/{cfg.api_realm}/groups/{quote(group_id)}"
        j = _http_json(
            "GET", url,
            {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
            None, ctx, cfg.timeout
        ) or {}
        name = j.get("name") or j.get("id")
    except Exception:
        name = None
    cache[group_id] = name
    return name


def _extract_user_target(ev: Dict) -> Tuple[Optional[str], Optional[str]]:
    """Return (target_id, target_username) from an admin event if possible."""
    rt = (ev.get("resourceType") or "").upper()
    if rt != "USER":
        return None, None
    resource_path = ev.get("resourcePath") or ""
    target_id = None
    if resource_path.lower().startswith("users/"):
        parts = resource_path.split("/")
        if len(parts) >= 2:
            target_id = parts[1]
    target_username = None
    rep = ev.get("representation")
    if rep:
        try:
            rep_obj = json.loads(rep)
            target_username = rep_obj.get("username") or rep_obj.get("email")
            target_id = rep_obj.get("id") or target_id
        except Exception:
            pass
    return target_id, target_username


def _extract_group_target(ev: Dict) -> Tuple[Optional[str], Optional[str]]:
    """Return (target_id, target_name) from an admin event if possible."""
    rt = (ev.get("resourceType") or "").upper()
    if rt != "GROUP":
        return None, None
    resource_path = ev.get("resourcePath") or ""
    target_id = None
    if resource_path.lower().startswith("groups/"):
        parts = resource_path.split("/")
        if len(parts) >= 2:
            target_id = parts[1]
    target_name = None
    rep = ev.get("representation")
    if rep:
        try:
            rep_obj = json.loads(rep)
            target_name = rep_obj.get("name") or rep_obj.get("id")
            target_id = rep_obj.get("id") or target_id
        except Exception:
            pass
    return target_id, target_name


def _is_ldap_provider_event(ev: Dict) -> bool:
    rt = (ev.get("resourceType") or "").upper()
    if rt not in {"USER_FEDERATION", "COMPONENT"}:
        return False
    rep = ev.get("representation")
    if rep:
        try:
            rep_obj = json.loads(rep)
            provider_id = (rep_obj.get("providerId") or rep_obj.get("provider") or "").lower()
            if provider_id == "ldap":
                return True
        except Exception:
            pass
    path = (ev.get("resourcePath") or "").lower()
    return "ldap" in path


def _filter_admin_events(admin_events: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    for ev in admin_events:
        rt = (ev.get("resourceType") or "").upper()
        op = (ev.get("operationType") or "").upper()
        if op not in _ALLOWED_ADMIN_OPS:
            continue
        if rt == "REALM_ROLE":
            continue  # ignore realm role events per requirement
        if rt in {"USER", "GROUP", "CLIENT_ROLE", "REALM"}:
            out.append(ev)
        elif rt in {"USER_FEDERATION", "COMPONENT"}:
            if _is_ldap_provider_event(ev):
                out.append(ev)
    return out


def _format_login_logout_line(ev: Dict, user_lookup=None) -> Optional[Tuple[int, str, str]]:
    try:
        ts_ms = int(ev.get("time") or 0)
    except Exception:
        return None
    if ts_ms <= 0:
        return None
    event_type = (ev.get("type") or "LOGIN").upper()
    if event_type not in _ALLOWED_LOGIN_EVENTS:
        return None
    details = ev.get("details") or {}
    user_id = ev.get("userId") or details.get("userId")
    user = details.get("username") or ev.get("username")
    if not user and user_lookup and user_id:
        resolved = user_lookup(user_id)
        if resolved:
            user = resolved
    if not user:
        user = user_id or "-"
    ip = ev.get("ipAddress") or "-"
    client = (ev.get("clientId") or "").strip()
    client_lower = client.lower()
    # Ignore API client logins
    if client_lower == "eda":
        return None

    iso = _iso_from_epoch_ms(ts_ms)
    display_ts = _dt_to_display(datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc))
    if client_lower == "auth":
        if event_type == "LOGIN":
            line = f"{display_ts} | Event=EDA-Login | User={user} | IPADDR={ip} | The user signed-in to the EDA GUI."
        else:  # LOGOUT
            line = f"{display_ts} | Event=EDA-Logout | User={user} | IPADDR={ip} | The user signed-out of the EDA GUI."
    else:
        # Skip unknown clients to avoid noise
        return None
    return ts_ms, iso, line


def _format_admin_event_line(ev: Dict, user_lookup=None,
                             user_target_cache: Optional[Dict[str, Optional[str]]] = None,
                             group_target_cache: Optional[Dict[str, Optional[str]]] = None,
                             group_lookup=None) -> Optional[Tuple[int, str, str]]:
    try:
        ts_ms = int(ev.get("time") or 0)
    except Exception:
        return None
    if ts_ms <= 0:
        return None
    rt = (ev.get("resourceType") or "UNKNOWN").upper()
    op = (ev.get("operationType") or "UNKNOWN").upper()
    if op not in _ALLOWED_ADMIN_OPS:
        return None
    if rt not in _ALLOWED_ADMIN_RESOURCE_TYPES:
        return None
    if rt in {"USER_FEDERATION", "COMPONENT"} and not _is_ldap_provider_event(ev):
        return None

    auth = ev.get("authDetails") or {}
    details = ev.get("details") or {}
    actor = auth.get("username")
    actor_id = auth.get("userId")
    details_actor_id = details.get("userId")
    resolved_actor = None
    if user_lookup:
        for uid in (actor_id, details_actor_id):
            if uid:
                resolved_actor = user_lookup(uid)
                if resolved_actor:
                    break
    if not actor or actor.startswith("service-account-") or (resolved_actor and actor in {actor_id, details_actor_id}):
        actor = resolved_actor or actor or actor_id or details_actor_id or "-"
    ip = auth.get("ipAddress") or "-"
    resource_path = ev.get("resourcePath") or "-"

    iso = _iso_from_epoch_ms(ts_ms)
    display_ts = _dt_to_display(datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc))
    line: Optional[str] = None

    if rt == "USER":
        target_id, target_username = _extract_user_target(ev)
        if user_target_cache is not None and target_id and target_username:
            user_target_cache.setdefault(target_id, target_username)
        if not target_username and target_id:
            if user_target_cache is not None and target_id in user_target_cache:
                target_username = user_target_cache.get(target_id)
            if not target_username and user_lookup:
                resolved_target = user_lookup(target_id)
                if resolved_target:
                    target_username = resolved_target
                    if user_target_cache is not None:
                        user_target_cache[target_id] = resolved_target
        if user_target_cache is not None and target_id and target_username:
            user_target_cache[target_id] = target_username
        target_label = target_username or target_id or "unknown-user"
        action_word = "updated"
        if op == "CREATE":
            action_word = "created"
        elif op == "DELETE":
            action_word = "deleted"
        line = (
            f"{display_ts} | Event=USER-{op} | User={actor} | IPADDR={ip} | "
            f"User {target_label} has been {action_word}."
        )
    elif rt == "GROUP":
        target_id, target_name = _extract_group_target(ev)
        if group_target_cache is not None and target_id and target_name:
            group_target_cache.setdefault(target_id, target_name)
        if not target_name and target_id:
            if group_target_cache is not None and target_id in group_target_cache:
                target_name = group_target_cache.get(target_id)
            if not target_name and group_lookup:
                resolved_group = group_lookup(target_id)
                if resolved_group:
                    target_name = resolved_group
                    if group_target_cache is not None:
                        group_target_cache[target_id] = resolved_group
        if group_target_cache is not None and target_id and target_name:
            group_target_cache[target_id] = target_name
        target_label = target_name or target_id or "unknown-group"
        action_word = "updated"
        if op == "CREATE":
            action_word = "created"
        elif op == "DELETE":
            action_word = "deleted"
        line = (
            f"{display_ts} | Event=USERGROUP-{op} | User={actor} | IPADDR={ip} | "
            f"UserGroup {target_label} has been {action_word}."
        )
    elif rt == "REALM":
        # Treat all REALM admin updates as password policy changes (per requirements)
        line = (
            f"{display_ts} | Event=REALM-{op} | User={actor} | IPADDR={ip} | "
            f"Password policy has been modified."
        )
    else:
        descriptor = f"{rt}-{op}"
        if rt in {"USER_FEDERATION", "COMPONENT"}:
            descriptor = f"LDAP-{op}"
        line = (
            f"{display_ts} | Event=Keycloak-{descriptor} | User={actor} | IPADDR={ip} | "
            f"Resource={resource_path}"
        )
    return ts_ms, iso, line


def collect_keycloak_user_logs(cfg: Config, ctx: ssl.SSLContext, last_event_ms: int,
                               user_id_map: Optional[Dict[str, str]],
                               group_id_map: Optional[Dict[str, str]]) -> Tuple[int, int, Dict[str, List[Tuple[int, str]]], Dict[str, str], Dict[str, str]]:
    """
    Fetch Keycloak user/admin events we care about; returns (count, max_seen_ms, lines_by_month, updated_user_id_map, updated_group_id_map).
    Caller is responsible for persisting the new max_seen_ms and writing the lines/maps.
    """
    if not (cfg.kc_admin_username and cfg.kc_admin_password):
        return 0, last_event_ms, {}, user_id_map or {}, group_id_map or {}

    admin_token = _kc_admin_token(cfg, ctx)

    login_events: List[Dict] = []
    admin_events_raw: List[Dict] = []
    user_cache: Dict[str, Optional[str]] = {}
    base_user_map = dict(user_id_map or {})
    base_group_map = dict(group_id_map or {})
    user_target_cache: Dict[str, Optional[str]] = dict(base_user_map)
    group_target_cache: Dict[str, Optional[str]] = dict(base_group_map)

    try:
        login_events = _kc_fetch_login_logout_events(cfg, ctx, admin_token)
    except Exception as e:
        print(f"[WARN] Keycloak login/logout events fetch failed: {e}", file=sys.stderr)

    try:
        admin_events_raw = _kc_fetch_admin_events(cfg, ctx, admin_token)
    except Exception as e:
        print(f"[WARN] Keycloak admin events fetch failed: {e}", file=sys.stderr)

    admin_events = _filter_admin_events(admin_events_raw)
    # Pre-fill caches from any available CREATE/UPDATE representations to help DELETE events resolve names.
    for ev in admin_events:
        tid, tuser = _extract_user_target(ev)
        if tid and tuser:
            user_target_cache.setdefault(tid, tuser)
        gid, gname = _extract_group_target(ev)
        if gid and gname:
            group_target_cache.setdefault(gid, gname)

    new_lines_by_month: Dict[str, List[Tuple[int, str]]] = {}
    max_seen_ms = last_event_ms

    def _add_line(ts_ms: int, iso_ts: str, line: str):
        nonlocal max_seen_ms
        if ts_ms <= last_event_ms:
            return
        month = _month_key(iso_ts)
        new_lines_by_month.setdefault(month, []).append((ts_ms, line))
        max_seen_ms = max(max_seen_ms, ts_ms)

    for ev in login_events:
        formatted = _format_login_logout_line(ev, lambda uid: _kc_resolve_username_by_id(cfg, ctx, admin_token, uid, user_cache))
        if formatted:
            ts_ms, iso_ts, line = formatted
            _add_line(ts_ms, iso_ts, line)

    for ev in admin_events:
        formatted = _format_admin_event_line(
            ev,
            lambda uid: _kc_resolve_username_by_id(cfg, ctx, admin_token, uid, user_cache),
            user_target_cache,
            group_target_cache,
            lambda gid: _kc_resolve_groupname_by_id(cfg, ctx, admin_token, gid, group_target_cache),
        )
        if formatted:
            ts_ms, iso_ts, line = formatted
            _add_line(ts_ms, iso_ts, line)

    total = sum(len(v) for v in new_lines_by_month.values())
    # Remove usernames for deleted users if we saw DELETE with that id; likewise for groups
    for ev in admin_events:
        if (ev.get("resourceType") or "").upper() == "USER" and (ev.get("operationType") or "").upper() == "DELETE":
            tid, _ = _extract_user_target(ev)
            if tid and tid in user_target_cache:
                user_target_cache.pop(tid, None)
        if (ev.get("resourceType") or "").upper() == "GROUP" and (ev.get("operationType") or "").upper() == "DELETE":
            gid, _ = _extract_group_target(ev)
            if gid and gid in group_target_cache:
                group_target_cache.pop(gid, None)
    updated_user_map = {k: v for k, v in user_target_cache.items() if v}
    updated_group_map = {k: v for k, v in group_target_cache.items() if v}
    return total, max_seen_ms, new_lines_by_month, updated_user_map, updated_group_map


def _month_key(ts: str) -> str:
    dt = _parse_iso_datetime(ts)
    if not dt:
        return "unknown-month"
    return dt.strftime("%Y-%m")


def _load_state(path: Path) -> Dict:
    if not path.exists():
        return {
            "last_transaction_id": None,
            "last_commit_timestamp": None,
            "last_user_event_ms": 0,
            "user_id_map": {},
            "group_id_map": {},
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        tx_id = data.get("last_transaction_id")
        if tx_id is not None:
            tx_id = int(tx_id)
        ts = data.get("last_commit_timestamp")
        ev_ms = data.get("last_user_event_ms") or 0
        user_map = data.get("user_id_map") or {}
        group_map = data.get("group_id_map") or {}
        return {
            "last_transaction_id": tx_id,
            "last_commit_timestamp": ts,
            "last_user_event_ms": int(ev_ms),
            "user_id_map": user_map if isinstance(user_map, dict) else {},
            "group_id_map": group_map if isinstance(group_map, dict) else {},
        }
    except Exception:
        return {
            "last_transaction_id": None,
            "last_commit_timestamp": None,
            "last_user_event_ms": 0,
            "user_id_map": {},
            "group_id_map": {},
        }


def _save_state(path: Path, state: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def eligible_transactions(summary_json: Dict) -> List[Dict]:
    results = (summary_json or {}).get("results") or []
    out: List[Dict] = []
    for entry in results:
        try:
            tx_id = int(entry["id"])
        except Exception:
            continue
        out.append({
            "id": tx_id,
            "username": entry.get("username", ""),
            "time": entry.get("lastChangeTimestamp", ""),
            "success": bool(entry.get("success")),
            "dryRun": bool(entry.get("dryRun")),
            "state": entry.get("state", ""),
        })
    return out


def format_change_line(tx_ts_display: str, tx_id: int, tx_user: str, user_ip: str,
                       modified: str, namespace: str, change: str) -> str:
    mod_val = (modified or "").strip() or "none"
    ns_val = (namespace or "").strip() or "none"

    def _decorate_change(val: str) -> str:
        if not val:
            return val
        if val.startswith("+") or val.startswith("-"):
            return f"({val[0]}){val[1:]}"
        return val

    return (
        f"{tx_ts_display} | Event=Transaction-{tx_id} | User={tx_user} | IPADDR={user_ip} | "
        f"Modified={mod_val} | Namespace={ns_val} | {_decorate_change(change)}"
    )


def format_status_line(tx_ts_display: str, tx_id: int, tx_user: str, user_ip: str, message: str) -> str:
    return f"{tx_ts_display} | Event=Transaction-{tx_id} | User={tx_user} | IPADDR={user_ip} | Modified=none | {message}"


def _fetch_all_summaries(cfg: Config, ctx: ssl.SSLContext, token: str) -> List[Dict]:
    """Fetch all summary pages (no total limit), using cfg.summary_size as the page size."""
    page_size = max(1, cfg.summary_size)
    page = 0
    seen_ids = set()
    all_entries: List[Dict] = []
    while True:
        path = f"core/transaction/v2/result/summary?page={page}&size={page_size}"
        summary = api_get(cfg, token, path, ctx) or {}
        results = (summary or {}).get("results") or []
        if not results:
            break
        for entry in results:
            tx_id = entry.get("id")
            if tx_id in seen_ids:
                continue
            seen_ids.add(tx_id)
            all_entries.append(entry)
        if len(results) < page_size:
            break
        page += 1
    return all_entries


def _resource_label(group: str, kind: str) -> str:
    grp = (group or "").lower()
    if grp.startswith("bootstrap.eda.nokia.com"):
        prefix = "Bootstrap "
    else:
        prefix = ""
    if kind:
        return f"{prefix}{kind}"
    fallback = (group or "").split(".")[0] or "Resource"
    return f"{prefix}{fallback.capitalize()}"


def _resource_namespace(kind: str, namespace: str, name: str) -> str:
    ns_val = (namespace or "").strip()
    if ns_val:
        return ns_val
    if (kind or "").lower() == "namespace" and name:
        return name
    return "none"


def format_resource_event(tx_ts_display: str, tx_id: int, tx_user: str, user_ip: str,
                          namespace: str, message: str) -> str:
    ns_val = (namespace or "").strip() or "none"
    return (
        f"{tx_ts_display} | Event=Transaction-{tx_id} | User={tx_user} | IPADDR={user_ip} | "
        f"Modified=EDA | Namespace={ns_val} | {message}"
    )


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


def _collect_resource_change_lines(cfg: Config, ctx: ssl.SSLContext, token: str,
                                   tx_id: int, tx_user: str, tx_ts_display: str, user_ip: str) -> Tuple[List[str], set]:
    lines: List[str] = []
    namespaces: set = set()
    try:
        input_json = api_get(cfg, token, f"core/transaction/v2/result/inputresources/{tx_id}", ctx) or {}
    except Exception as e:
        if isinstance(e, urllib.error.HTTPError) and e.code == 400:
            return lines, namespaces  # silently skip missing/unauthorized transactions
        print(f"[WARN] inputresources fetch failed for tx {tx_id}: {e}", file=sys.stderr)
        return lines, namespaces

    resources = input_json.get("inputCrs") or []
    for r in resources:
        name_info = r.get("name") or {}
        gvk = name_info.get("gvk") or {}
        res_name = name_info.get("name")
        group = gvk.get("group")
        version = gvk.get("version")
        kind = gvk.get("kind")
        namespace = name_info.get("namespace", "")
        if not (res_name and group and version and kind):
            continue

        qs = (
            f"core/transaction/v2/result/diffs/resource/{tx_id}"
            f"?group={quote(group)}&version={quote(version)}&kind={quote(kind)}&name={quote(res_name)}"
        )
        if namespace:
            qs += f"&namespace={quote(namespace)}"

        diff_json: Dict = {}
        try:
            diff_json = api_get(cfg, token, qs, ctx) or {}
        except Exception as e:
            print(f"[WARN] resource diff fetch failed for tx {tx_id} ({group}/{kind}/{res_name}): {e}", file=sys.stderr)

        before = ((diff_json.get("before") or {}).get("data")) if isinstance(diff_json, dict) else None
        after = ((diff_json.get("after") or {}).get("data")) if isinstance(diff_json, dict) else None
        is_delete = bool(r.get("isDelete"))

        if is_delete or (before and not after):
            action = "deleted"
        elif after and not before:
            action = "created"
        elif before and after:
            action = "updated"
        else:
            action = "updated"

        label = _resource_label(group, kind)
        ns_for_line = _resource_namespace(kind, namespace, res_name)
        namespaces.add(ns_for_line if ns_for_line else "")
        if action == "created":
            msg = f"{label} resource named {res_name} has been created."
        elif action == "deleted":
            msg = f"{label} resource named {res_name} has been deleted."
        else:
            msg = f"{label} resource named {res_name} has been modified."

        lines.append(format_resource_event(tx_ts_display, tx_id, tx_user, user_ip, ns_for_line, msg))
    return lines, namespaces


def _collect_nodecfg_lines(cfg: Config, ctx: ssl.SSLContext, token: str,
                           tx_id: int, tx_user: str, tx_ts_display: str, user_ip: str,
                           namespaces: set, known_nodes: List[str]) -> List[str]:
    lines: List[str] = []

    # Build default namespace guesses
    ns_candidates = set([ns for ns in namespaces if ns] + ["eda", "eda-telemetry", "default", ""])
    node_candidates = list(dict.fromkeys(known_nodes))  # de-dup preserve order

    for node in node_candidates:
        for ns in ns_candidates:
            qs = f"core/transaction/v2/result/diffs/nodecfg/{tx_id}?node={quote(node)}"
            if ns:
                qs += f"&namespace={quote(ns)}"
            try:
                diff_json = api_get(cfg, token, qs, ctx) or {}
            except Exception as e:
                # 400 for missing/invalid node/namespace is expected; skip
                continue

            if diff_json.get("dataUnavailable") is True:
                continue

            before = ((diff_json.get("before") or {}).get("data")) or ""
            after = ((diff_json.get("after") or {}).get("data")) or ""
            delta = ndiff_delta(before, after)
            if not delta:
                continue
            for change in delta:
                lines.append(format_change_line(tx_ts_display, tx_id, tx_user, user_ip, node, ns, change))
    return lines


def _collect_transaction_lines(cfg: Config, ctx: ssl.SSLContext, token: str,
                               tx_id: int, tx_user: str, tx_ts_display: str, tx_iso: str, user_ip: str) -> List[str]:
    resource_lines, resource_namespaces = _collect_resource_change_lines(cfg, ctx, token, tx_id, tx_user, tx_ts_display, user_ip)

    # Known nodes from existing log (Modified values) and common defaults
    known_nodes = set()
    log_file = Path(f"Transaction-{_month_key(tx_iso)}.log")
    if log_file.exists():
        for ln in log_file.read_text().splitlines():
            m = re.search(r"Modified=([^|]+)", ln)
            if m:
                val = m.group(1).strip()
                if val and val.lower() not in {"eda", "none"}:
                    known_nodes.add(val)
    # Default guesses
    for prefix in ("leaf", "spine"):
        for i in range(1, 9):
            known_nodes.add(f"{prefix}{i}")

    node_lines = _collect_nodecfg_lines(cfg, ctx, token, tx_id, tx_user, tx_ts_display, user_ip, resource_namespaces, list(known_nodes))

    log_lines: List[str] = []
    log_lines.extend(node_lines)
    log_lines.extend(resource_lines)

    if not log_lines:
        log_lines.append(format_change_line(tx_ts_display, tx_id, tx_user, user_ip, "none", "", "(no config changes)"))
    return log_lines


def run_once(cfg: Config, ctx: ssl.SSLContext) -> Optional[int]:
    token = get_token(cfg, ctx)

    state_path = Path(cfg.state_file)
    state = _load_state(state_path)
    last_tx_id = state.get("last_transaction_id")
    last_user_event_ms = int(state.get("last_user_event_ms") or 0)
    user_id_map: Dict[str, str] = state.get("user_id_map") or {}
    group_id_map: Dict[str, str] = state.get("group_id_map") or {}
    start_id = (last_tx_id + 1) if last_tx_id is not None else max(1, cfg.start_id)
    max_missing = max(1, cfg.max_missing)
    missing = 0
    last_processed: Optional[int] = None
    last_tx_iso: Optional[str] = state.get("last_commit_timestamp")
    txn_lines_by_month: Dict[str, List[Tuple[int, str]]] = {}
    user_lines_by_month: Dict[str, List[Tuple[int, str]]] = {}
    user_events_logged = 0
    new_event_ms = last_user_event_ms

    tx_id = start_id
    while missing < max_missing:
        try:
            summary = api_get(cfg, token, f"core/transaction/v2/result/summary/{tx_id}", ctx)
        except Exception:
            summary = None

        if not summary:
            missing += 1
            tx_id += 1
            continue

        missing = 0
        tx_user = summary.get("username", "")
        tx_time = summary.get("lastChangeTimestamp", "")
        tx_success = bool(summary.get("success"))
        tx_dry_run = bool(summary.get("dryRun"))
        tx_state = summary.get("state", "")
        tx_iso, tx_ts_display, tx_ms = _normalize_iso_ts(tx_time)

        user_ip = "Failed to retrieve the IP ; Keycloak (Select Realm EDA) > Realm Settings > Events > User/Admin Events Settings > Save Events > On"
        try:
            hit_ip = get_user_login_ip_near_commit(cfg, ctx, tx_user, tx_time)
            if hit_ip:
                user_ip = hit_ip
        except Exception as e:
            print(f"[WARN] Keycloak events lookup: {e}", file=sys.stderr)

        if tx_dry_run:
            log_lines = [format_status_line(tx_ts_display, tx_id, tx_user, user_ip,
                                            "Dryrun , no changes were made on the system or the nodes.")]
        elif not tx_success or tx_state != "complete":
            log_lines = [format_status_line(tx_ts_display, tx_id, tx_user, user_ip,
                                            "Failed transaction attempt, no changes were made on the system or the nodes.")]
        else:
            log_lines = _collect_transaction_lines(cfg, ctx, token, tx_id, tx_user, tx_ts_display, tx_iso, user_ip)

        month = _month_key(tx_iso)
        txn_lines_by_month.setdefault(month, []).extend((tx_ms, line) for line in log_lines)

        last_processed = tx_id
        last_tx_iso = tx_iso
        tx_id += 1

    try:
        user_events_logged, new_event_ms, user_lines_by_month, user_id_map, group_id_map = collect_keycloak_user_logs(
            cfg, ctx, last_user_event_ms, user_id_map, group_id_map
        )
    except Exception as e:
        print(f"[WARN] Keycloak user/admin events lookup: {e}", file=sys.stderr)
        user_events_logged = 0
        user_lines_by_month = {}
        new_event_ms = last_user_event_ms

    # Write combined lines per month in chronological order
    months = sorted(set(list(txn_lines_by_month.keys()) + list(user_lines_by_month.keys())))
    for month in months:
        combined: List[Tuple[int, str]] = []
        combined.extend(txn_lines_by_month.get(month, []))
        combined.extend(user_lines_by_month.get(month, []))
        if not combined:
            continue
        combined.sort(key=lambda x: (x[0], x[1]))
        out = Path(f"Transaction-{month}.log")
        with out.open("a", encoding="utf-8") as fh:
            for _, line in combined:
                fh.write(line + "\n")
        print(f"Appended {len(combined)} chronological lines to {out.resolve()}")

    # Persist state after writing
    if last_processed is not None:
        state["last_transaction_id"] = last_processed
        state["last_commit_timestamp"] = last_tx_iso
    if new_event_ms > last_user_event_ms:
        state["last_user_event_ms"] = new_event_ms
    state["user_id_map"] = user_id_map
    state["group_id_map"] = group_id_map
    _save_state(state_path, state)

    if last_processed is None and not months:
        print("No transactions processed (max_missing reached).")
    else:
        if user_events_logged:
            print(f"Appended {user_events_logged} Keycloak user/admin events to Transaction-*.log.")
    return last_processed


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

    # Keycloak user/admin event logging
    p.add_argument("--user-events-page-size", type=int, default=500,
                   help="Max events to request per Keycloak events/admin-events call (default 500)")

    # Transaction polling
    p.add_argument("--summary-size", type=int, default=200,
                   help="Page size when paging summaries (default 200)")
    p.add_argument("--start-id", type=int, default=1,
                   help="Transaction ID to start from if no state is present (default 1)")
    p.add_argument("--max-missing", type=int, default=20,
                   help="Stop after this many consecutive missing IDs (default 20)")
    p.add_argument("--state-file", default="transaction_state.json",
                   help="Path to file storing the last processed transaction metadata")

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
        summary_size=max(1, args.summary_size),
        state_file=args.state_file,
        start_id=args.start_id,
        max_missing=max(1, args.max_missing),
        user_event_page_size=max(1, args.user_events_page_size),
    )
    ctx = _ssl_ctx(cfg.insecure)

    try:
        run_once(cfg, ctx)
    except Exception as e:
        print(f"[WARN] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
