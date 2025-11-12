## EDA Transaction Log Harvester

`log-transaction.py` retrieves the most recent successful EDA transaction, flattens the configuration diffs returned by the API, and writes one log line per config change to `Transaction-<id>.txt`. Each line contains the commit timestamp, transaction id, username, user IP (resolved via Keycloak events when available), node name, namespace, and the added/removed config fragment.

### Requirements
- Python 3.8+ on the machine running the script
- HTTPS reachability to the EDA API (e.g., `https://100.124.177.211`)
- A valid EDA user account plus admin credentials for Keycloak to look up client secrets and login events

### Usage
1. Install any dependencies your environment needs for HTTPS (system default Python libraries are sufficient for most cases).
2. Run the script with your API and Keycloak details. Example:
   ```bash
   python3 log-transaction.py \
     --base-url https://100.124.177.211 \
     --username admin \
     --password admin \
     --kc-admin-username admin \
     --kc-admin-password admin \
     --insecure
   ```
   Add `--client-secret <value>` if you prefer to supply the OIDC secret manually, and omit `--insecure` when using trusted certificates.
3. After a successful run, inspect the generated `Transaction-<id>.txt`. Every config delta is logged as:
   ```
   <commit_date> , <transaction_id> , <username> , <user_ip> , <node> , <namespace> , <+/- change line>
   ```

Re-run the script any time you want to snapshot the latest completed transaction; it will refresh the file for the most recent id returned by the API.
