## EDA + Keycloak Event Harvester

`log-transaction.py` pulls EDA transaction deltas and Keycloak user/admin events, normalizes them, and appends everything into monthly logs named `Transaction-YYYY-MM.log` (local server timezone, `YYYY-MM-DDTHH:MM:SS <TZNAME>`). A single state file (`transaction_state.json` by default) tracks the last processed transaction, last commit time, last Keycloak event, and cached user/group ID mappings so reruns only capture new activity.

### What gets logged
- EDA transactions: config diffs per resource/node, plus status lines for dry runs or failed transactions.
- Keycloak GUI logins/logouts (`clientId=auth`) as `GUI-Login` / `GUI-Logout`.
- Keycloak admin events:
  - Users: create/update/delete (resolves usernames, caches IDs; clears cache on delete).
  - Groups: create/update/delete (resolves group names; clears cache on delete).
  - Client roles: create/update/delete.
  - Realm updates: logged as “Password policy has been modified.”
  - LDAP provider create/update/delete (user federation/component) only.
- Realm-role events are ignored by design; API logins (`clientId=eda`) are ignored.

### Requirements
- Python 3.8+ where the script runs.
- HTTPS reachability to the EDA API base (e.g., `https://100.124.177.211`).
- EDA user credentials and Keycloak admin credentials (to fetch client secrets, resolve usernames, and read events).

### Usage
Run with your endpoints and credentials. Example:
```bash
python3 log-transaction.py \
  --base-url https://100.124.177.211 \
  --username admin \
  --password admin \
  --kc-admin-username admin \
  --kc-admin-password admin \
  --insecure
```
Notes:
- Omit `--insecure` if certificates are trusted.
- Supply `--client-secret` to avoid auto-fetching the OIDC secret.
- `--state-file` changes where progress and ID maps are stored.
- `--start-id`, `--summary-size`, `--max-missing` control transaction scanning.

After a run, check `Transaction-YYYY-MM.log` for that month. Re-run anytime; only new transactions/events since the last state are appended.
