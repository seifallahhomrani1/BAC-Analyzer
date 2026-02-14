# Keycloak BAC Testing Lab

Local Keycloak + Demo API lab for testing Broken Access Control (BAC) analyzers. Uses non-default ports and is fully reproducible with Docker Compose.

## Architecture

- **Keycloak** (port **49123**) – Auth server, realm `bac-lab`
- **PostgreSQL** (port **55432**) – Keycloak database
- **Demo API** (port **50111**) – Flask app that validates JWT and enforces roles

## Ports

| Service   | Port  |
|----------|--------|
| Keycloak | 49123  |
| Postgres | 55432  |
| Demo API | 50111  |

## Quick Start

```bash
docker-compose up --build
```

Wait until Keycloak is ready and `keycloak-init` has created users (about 1–2 minutes). Then the lab is ready.

## URLs

- **Keycloak Admin**: http://localhost:49123  
  Login: `admin` / `adminpassword`
- **Demo API**: http://localhost:50111

## Realm: bac-lab

- **Roles**: `admin`, `manager`, `user`
- **Client**: `bac-analyzer` (confidential)
  - Client secret: `bac-secret-123`
  - Direct access grants enabled (resource owner password)
  - Valid redirect URIs: `*`

## Users

| Username     | Password    | Role    |
|-------------|-------------|---------|
| admin_user  | admin_pass  | admin   |
| manager_user| manager_pass| manager |
| normal_user | user_pass   | user    |

## Get an Access Token (curl)

Replace `USERNAME` and `PASSWORD` with one of the users above.

```bash
curl -s -X POST "http://localhost:49123/realms/bac-lab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=USERNAME" \
  -d "password=PASSWORD" \
  -d "grant_type=password" \
  -d "client_id=bac-analyzer" \
  -d "client_secret=bac-secret-123" | jq -r '.access_token'
```

Example for admin:

```bash
curl -s -X POST "http://localhost:49123/realms/bac-lab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin_user" \
  -d "password=admin_pass" \
  -d "grant_type=password" \
  -d "client_id=bac-analyzer" \
  -d "client_secret=bac-secret-123" | jq -r '.access_token'
```

Use the token against the Demo API:

```bash
TOKEN="<paste access_token here>"
curl -H "Authorization: Bearer $TOKEN" http://localhost:50111/api/users
```

## Demo API Endpoints

| Method | Path               | admin | manager | user        |
|--------|--------------------|-------|---------|-------------|
| GET    | /api/users         | 200   | 200     | 403         |
| DELETE | /api/users/<id>    | 200   | **200** | 403         |
| GET    | /api/profile/<id>  | 200   | 403     | 200 only if id=self |

**Intentional vulnerability**: `manager` can call `DELETE /api/users/<id>` (should be admin-only). Use this to test your BAC analyzer.

## Security Simulation

The Demo API is configured so that **manager** can delete users. This simulates a privilege escalation so that a BAC/differential analyzer can detect the misconfiguration.

## Testing with bac-analyzer

If you use the [bac-analyzer](../bac-analyzer) tool in the parent folder:

1. **Start the lab** (from this directory):
   ```bash
   docker-compose up --build -d
   ```
   Wait ~2 minutes for Keycloak and init to finish.

2. **Fetch tokens and run the analyzer** (from `bac-analyzer/`):
   ```bash
   cd ../bac-analyzer
   pip install -r requirements.txt
   python fetch_keycloak_tokens.py --config keycloak-lab/keycloak-tokens.yaml -o tokens.json
   python analyzer.py --endpoints keycloak-lab/endpoints.yaml --matrix keycloak-lab/authorization_matrix.yaml --diff
   ```
   To **forward traffic to Burp Suite** for inspection, start Burp with a listener on e.g. `127.0.0.1:8080`, then add:
   ```bash
   python fetch_keycloak_tokens.py ... --proxy http://127.0.0.1:8080 -o tokens.json
   python analyzer.py ... --proxy http://127.0.0.1:8080 --diff
   ```

3. **What to expect**
   - **Matrix check**: One mismatch — `manager` + `delete_user`: expected `deny`, actual `allow` (the intentional vuln).
   - **Differential analysis** (`--diff`): Findings such as “Lower privilege role has same access as admin” for `delete_user` (admin vs manager both 200).

The `keycloak-lab/` config in bac-analyzer uses the correct policy (manager **deny** on delete), so the analyzer flags the Demo API’s incorrect behavior.

## Files

- `docker-compose.yml` – Keycloak, Postgres, Demo API, keycloak-init
- `realm-export.json` – Realm and client (mounted as `bac-lab-realm.json` for import)
- `keycloak-init/` – Creates users with roles after Keycloak starts
- `demo_api/` – Flask app + Dockerfile

## Stopping

```bash
docker-compose down
```

To remove the database volume as well:

```bash
docker-compose down -v
```
