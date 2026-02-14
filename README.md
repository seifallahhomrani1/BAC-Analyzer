# bac-analyzer

A minimal Python CLI tool for detecting Broken Access Control (BAC) vulnerabilities by validating authorization matrices and identifying privilege escalation flaws in APIs.

![BAC Detection](https://img.shields.io/badge/security-broken_access_control-red) ![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)

## Features

- **Matrix Validation**: Compare expected vs. actual authorization decisions using role-based rules
- **Differential Analysis**: Automatically detect privilege inconsistencies without predefined rules:
  - Same Access (lower-privilege role matches admin access)
  - Inverted Privilege (admin denied while user allowed)
  - Suspicious Equality (all roles granted identical access)
- **Burp Suite Integration**: Forward all traffic through proxy for manual inspection
- **JWT-Aware**: Works with Bearer token authentication (Keycloak/OIDC compatible)
- **Zero Dependencies Beyond `requests`/`pyyaml`**: Minimal attack surface

## Installation

```bash
git clone https://github.com/yourusername/bac-analyzer.git
cd bac-analyzer
pip install -r requirements.txt
```

## Usage

### Basic Matrix Validation

```bash
python analyzer.py \
  --endpoints endpoints.yaml \
  --matrix authorization_matrix.yaml
```

### Differential Analysis (No Matrix Required)

```bash
python analyzer.py --diff
```

### With Burp Proxy

```bash
python analyzer.py --diff --proxy http://127.0.0.1:8080
```

### Full Workflow with Keycloak Lab

```bash
# Terminal 1: Start test environment
cd keycloak-lab
docker-compose up --build -d

# Terminal 2: Fetch tokens and run analysis
cd bac-analyzer
python fetch_keycloak_tokens.py --config keycloak-lab/keycloak-tokens.yaml -o tokens.json
python analyzer.py \
  --endpoints keycloak-lab/endpoints.yaml \
  --matrix keycloak-lab/authorization_matrix.yaml \
  --diff \
  --proxy http://127.0.0.1:8080
```

## Configuration Files

### `tokens.json`
```json
{
  "admin": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIn0...",
  "manager": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIn0...",
  "user": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIn0..."
}
```

### `endpoints.yaml`
```yaml
endpoints:
  - name: get_users
    method: GET
    url: http://localhost:50111/api/users
  - name: delete_user
    method: DELETE
    url: http://localhost:50111/api/users/1
```

### `authorization_matrix.yaml`
```yaml
matrix:
  admin:
    get_users: allow
    delete_user: allow
  manager:
    get_users: allow
    delete_user: deny   # Will detect intentional vuln in Keycloak lab
  user:
    get_users: deny
    delete_user: deny
```

## Output

Results saved to `report.json`:
```json
{
  "matrix_mismatches": [
    {
      "role": "manager",
      "endpoint": "delete_user",
      "expected": "deny",
      "actual": "allow",
      "status": 200
    }
  ],
  "differential_findings": [
    {
      "type": "differential_access",
      "endpoint": "delete_user",
      "method": "DELETE",
      "url": "http://localhost:50111/api/users/1",
      "roles_compared": ["admin", "manager"],
      "status_codes": {"admin": 200, "manager": 200},
      "severity": "high",
      "reason": "Lower privilege role has same access as admin"
    }
  ],
  "idor_findings": []
}
```

## Testing Environment

The repository includes a ready-to-run Keycloak lab with intentional vulnerabilities:

```bash
cd keycloak-lab
docker-compose up --build
```

- **Keycloak**: `http://localhost:49123` (non-default port)
- **Demo API**: `http://localhost:50111`
- **Intentional flaw**: `manager` role can DELETE users (should be admin-only)
- Pre-configured users: `admin_user`/`admin_pass`, `manager_user`/`manager_pass`, `normal_user`/`user_pass`

MIT License – See [LICENSE](LICENSE) for details.

---

*Tested with Python 3.10+ • No external services required • 100% offline operation*