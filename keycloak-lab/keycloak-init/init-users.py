#!/usr/bin/env python3
"""Create realm users in bac-lab via Keycloak Admin API. Verbose version."""
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

BASE = "http://localhost:49123"
REALM = "bac-lab"
ADMIN_USER = "admin"
ADMIN_PASS = "adminpassword"

USERS = [
    ("admin_user", "admin_pass", "admin"),
    ("manager_user", "manager_pass", "manager"),
    ("normal_user", "user_pass", "user"),
]


def request(method, path, data=None, token=None):
    url = f"{BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode(), r.getcode()


def get_token():
    url = f"{BASE}/realms/master/protocol/openid-connect/token"
    body = urllib.parse.urlencode({
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
        "grant_type": "password",
        "client_id": "admin-cli",
    }).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as r:
        out = json.loads(r.read().decode())
    return out["access_token"]


def main():
    # Skipped health check
    token = get_token()
    for username, password, role_name in USERS:
        try:
            resp, code = request("GET", f"/admin/realms/{REALM}/users?username={username}", token=token)
            users = json.loads(resp)
            if users:
                print(f"User {username} already exists")
                continue
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
        body = json.dumps({
            "username": username,
            "enabled": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        }).encode()
        try:
            request("POST", f"/admin/realms/{REALM}/users", data=body, token=token)
        except urllib.error.HTTPError as e:
            if e.code != 409:  # 409 = already exists
                raise
            print(f"User {username} already exists (409)")
            continue
        resp, _ = request("GET", f"/admin/realms/{REALM}/users?username={username}", token=token)
        users = json.loads(resp)
        if not users:
            print(f"Warning: could not find user {username} after create")
            continue
        user_id = users[0]["id"]
        resp, _ = request("GET", f"/admin/realms/{REALM}/roles/{role_name}", token=token)
        role = json.loads(resp)
        request("POST", f"/admin/realms/{REALM}/users/{user_id}/role-mappings/realm", data=json.dumps([role]), token=token)
        print(f"Created {username} with role {role_name}")
    print("Init done.")


if __name__ == "__main__":
    main()
