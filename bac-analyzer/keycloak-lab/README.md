# Keycloak lab config for bac-analyzer

Use these configs when testing against the [Keycloak BAC lab](../../keycloak-lab).

1. Start the lab: `cd ../../keycloak-lab && docker-compose up --build -d` (wait ~2 min).
2. From `bac-analyzer/`:
   ```bash
   python fetch_keycloak_tokens.py --config keycloak-lab/keycloak-tokens.yaml -o tokens.json
   python analyzer.py --endpoints keycloak-lab/endpoints.yaml --matrix keycloak-lab/authorization_matrix.yaml --diff
   ```

- **keycloak-tokens.yaml** – Keycloak URL, realm, client, and per-role credentials for token fetch.
- **endpoints.yaml** – Demo API endpoints (localhost:50111).
- **authorization_matrix.yaml** – Expected policy; manager is **deny** on `delete_user` so the analyzer detects the lab’s intentional vuln.
