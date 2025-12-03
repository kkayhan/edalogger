## EDA + Keycloak Event Harvester

`edalogger.py` pulls EDA transaction deltas and Keycloak user/admin events, normalizes them, and appends everything into monthly logs named `Transaction-YYYY-MM.log` (local server timezone, `YYYY-MM-DDTHH:MM:SS <TZNAME>`). A single state file (`transaction_state.json` by default) tracks the last processed transaction, last commit time, last Keycloak event, and cached user/group ID mappings so reruns only capture new activity.

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
python3 edalogger.py \
  --base-url https://100.124.177.211 \
  --username admin \
  --password admin \
  --kc-admin-username admin \
  --kc-admin-password admin \
  --insecure
```
### Advanced use
- TLS without `--insecure`: Point `--base-url` at a host with a trusted certificate, or add your CA to the system trust store (or `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE` env). Example:
  ```bash
  SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt \
  python3 edalogger.py --base-url https://eda.example.com --username alice --password '...' --kc-admin-username kcadmin --kc-admin-password '...'
  ```
- Supplying a client secret: If you don’t want to auto-fetch via Keycloak admin, provide it explicitly:
  ```bash
  python3 edalogger.py --base-url https://eda.example.com --username alice --password '...' \
    --kc-admin-username kcadmin --kc-admin-password '...' \
    --client-secret 'your-client-secret'
  ```
- State file location/name: Default is `transaction_state.json` in the working dir. Override it to isolate runs:
  ```bash
  python3 edalogger.py ... --state-file /var/lib/edalogger/state-prod.json
  ```
- Scan controls:
  - `--start-id`: where to begin if no state exists. Example: `--start-id 100` to start at tx 100.
  - `--summary-size`: page size when fetching summaries. Example: `--summary-size 500` for larger batches.
  - `--max-missing`: stop after N consecutive missing IDs. Example: `--max-missing 5` to bail after 5 gaps.
- Timezone: Logs use the server’s local time (`YYYY-MM-DDTHH:MM:SS <TZNAME>`). To force UTC output, run on a UTC host or set `TZ=UTC` when invoking: `TZ=UTC python3 edalogger.py ...`.
- Reruns: The state file controls what’s considered “new.” Clear the state to re-harvest from `--start-id`; otherwise only newer transactions/events are appended.
- Keycloak filtering: GUI logins/logouts are logged; API logins and realm-role events are ignored; realm updates are logged as password policy changes.

### Troubleshooting
- TLS/SSL errors: Remove `--insecure` only if your CA is trusted. Otherwise, install the CA or set `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE` to the CA bundle.
- 401/403 from API: Verify `--username/--password`, client secret (if supplied), and that the user has access to the EDA API and Keycloak admin endpoints.
- 400 on transaction fetch: Missing transaction IDs are skipped; adjust `--start-id`/`--max-missing` if you expect gaps.
- No new logs on rerun: Check the state file; delete it to reprocess from the start ID, or bump `--start-id` to skip older IDs.
- GUI logins not appearing: Ensure Keycloak events are enabled and `clientId=auth` is used for GUI; API (`clientId=eda`) logins are intentionally ignored.
- User/group names missing: Requires Keycloak admin access; ensure admin creds are correct so lookups and caches can resolve IDs.

After a run, check `Transaction-YYYY-MM.log` for that month. Re-run anytime; only new transactions/events since the last state are appended.
