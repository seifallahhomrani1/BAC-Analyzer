"""
Differential Role Comparison Engine.
Detects authorization inconsistencies by comparing API responses across roles
without relying on authorization_matrix.yaml.
"""

from typing import Any

from requester import call_api


def is_success(status_code: int) -> bool:
    """Return True if status_code indicates successful response."""
    return status_code < 400


def compare_roles(
    results: dict[str, dict[str, int]],
    endpoints_by_name: dict[str, dict[str, Any]],
) -> list[dict]:
    """
    Analyze per-endpoint role results and detect anomalies.
    results: endpoint_name -> role -> status_code
    Returns list of differential findings.
    """
    findings: list[dict] = []

    for endpoint_name, role_statuses in results.items():
        if endpoint_name not in endpoints_by_name:
            continue
        endpoint = endpoints_by_name[endpoint_name]
        method = endpoint.get("method", "GET")
        url = endpoint.get("url", "")

        def make_finding(
            roles_compared: list[str],
            severity: str,
            reason: str,
        ) -> dict:
            status_codes = {r: role_statuses[r] for r in roles_compared}
            return {
                "type": "differential_access",
                "endpoint": endpoint_name,
                "method": method,
                "url": url,
                "roles_compared": roles_compared,
                "status_codes": status_codes,
                "severity": severity,
                "reason": reason,
            }

        # Rule 3 — Suspicious Equality: ALL roles return 200
        if role_statuses and all(
            is_success(sc) and sc == 200 for sc in role_statuses.values()
        ):
            findings.append(
                make_finding(
                    list(role_statuses.keys()),
                    "medium",
                    "All roles have identical access",
                )
            )

        # Rule 1 & 2: compare admin vs lower-privilege roles
        admin_status = role_statuses.get("admin")
        if admin_status is None:
            continue

        for role in role_statuses:
            if role == "admin":
                continue
            other_status = role_statuses[role]

            # Rule 2 — Inverted Privilege: admin denied, other allowed
            if not is_success(admin_status) and is_success(other_status):
                findings.append(
                    make_finding(
                        ["admin", role],
                        "critical",
                        "Inverted privilege hierarchy",
                    )
                )
            # Rule 1 — Same Access: both success, lower privilege same as admin
            elif is_success(admin_status) and admin_status == other_status:
                findings.append(
                    make_finding(
                        ["admin", role],
                        "high",
                        "Lower privilege role has same access as admin",
                    )
                )

    return findings


def run_differential_analysis(
    tokens: dict[str, str],
    endpoints_by_name: dict[str, dict[str, Any]],
    proxies: dict[str, str] | None = None,
) -> list[dict]:
    """
    Run differential analysis: call each endpoint with every role token,
    then compare results and flag anomalies.
    """
    print("Running differential analysis...")
    results: dict[str, dict[str, int]] = {}

    for endpoint_name, endpoint in endpoints_by_name.items():
        print(f"  Comparing roles for endpoint: {endpoint_name}")
        results[endpoint_name] = {}
        for role, token in tokens.items():
            status_code = call_api(endpoint, token, proxies=proxies)
            results[endpoint_name][role] = status_code

    print("Comparing roles...")
    findings = compare_roles(results, endpoints_by_name)
    return findings
