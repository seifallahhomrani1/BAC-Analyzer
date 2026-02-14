"""
Demo API for BAC testing lab.
Validates JWT via Keycloak and enforces role-based access.
Intentionally allows manager to DELETE /api/users/<id> (privilege escalation simulation).
"""
import os
import urllib.request
import json
from functools import wraps

import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:49123").rstrip("/")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "bac-lab")
JWKS_URI = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"

_jwks_cache = None


def get_jwks():
    global _jwks_cache
    if _jwks_cache is None:
        req = urllib.request.Request(JWKS_URI)
        with urllib.request.urlopen(req, timeout=10) as r:
            _jwks_cache = json.loads(r.read().decode())
    return _jwks_cache


def get_signing_key(kid=None):
    jwks = get_jwks()
    for key in jwks.get("keys", []):
        if kid is None or key.get("kid") == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    raise ValueError("Unknown key id")


def verify_token():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return None, 401
    token = auth[7:].strip()
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid") if header else None
        key = get_signing_key(kid)
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_exp": True},
        )
        return payload, None
    except Exception:
        return None, 401


def require_auth(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        payload, err = verify_token()
        if err:
            return jsonify({"error": "Unauthorized"}), 401
        request.current_user = payload
        return f(*args, **kwargs)
    return wrapped


def get_roles():
    payload = getattr(request, "current_user", None) or {}
    return payload.get("realm_access", {}).get("roles") or []


def has_role(role):
    return role in get_roles()


# In-memory stub data
USERS = [
    {"id": "1", "username": "admin_user", "name": "Admin User"},
    {"id": "2", "username": "manager_user", "name": "Manager User"},
    {"id": "3", "username": "normal_user", "name": "Normal User"},
]


@app.route("/api/users", methods=["GET"])
@require_auth
def list_users():
    # admin and manager allowed; user denied
    if has_role("admin") or has_role("manager"):
        return jsonify({"users": USERS}), 200
    return jsonify({"error": "Forbidden"}), 403


@app.route("/api/users/<user_id>", methods=["DELETE"])
@require_auth
def delete_user(user_id):
    # Intentionally weak: manager can delete (vulnerability for analyzer to detect)
    # Correct would be: only admin
    if has_role("admin") or has_role("manager"):
        return jsonify({"deleted": user_id}), 200
    return jsonify({"error": "Forbidden"}), 403


@app.route("/api/profile/<profile_id>", methods=["GET"])
@require_auth
def get_profile(profile_id):
    # admin: any profile; manager: forbidden (only GET /api/users); user: only self
    if has_role("admin"):
        return jsonify({"id": profile_id, "username": profile_id, "profile": "data"}), 200
    if has_role("manager"):
        return jsonify({"error": "Forbidden"}), 403
    if has_role("user"):
        username = request.current_user.get("preferred_username", "")
        if profile_id == "self" or profile_id == username:
            return jsonify({"id": username, "username": username, "profile": "data"}), 200
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({"error": "Forbidden"}), 403


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", "50111"))
    app.run(host="0.0.0.0", port=port, debug=False)
