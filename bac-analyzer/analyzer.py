#!/usr/bin/env python3
"""
BAC Analyzer - Validates authorization matrix by comparing expected vs actual API responses.
Detects Broken Access Control / RBAC misconfigurations.
"""

import argparse
import json
from pathlib import Path

import yaml

from differential_analyzer import run_differential_analysis
from matrix_validator import compare, is_allowed
from requester import call_api


def load_tokens(path: str = "tokens.json") -> dict[str, str]:
    """Load role -> token mapping from JSON."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_endpoints(path: str = "endpoints.yaml") -> dict[str, dict]:
    """Load endpoints from YAML. Returns name -> endpoint dict."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    endpoints_list = data.get("endpoints", [])
    return {e["name"]: e for e in endpoints_list}


def load_matrix(path: str = "authorization_matrix.yaml") -> dict[str, dict[str, str]]:
    """Load authorization matrix: role -> { endpoint_name: allow|deny }."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("matrix", {})


def status_to_result(status_code: int) -> str:
    """Convert HTTP status code to allow/deny."""
    return "allow" if is_allowed(status_code) else "deny"


def run_checks(
    tokens: dict[str, str],
    endpoints_by_name: dict[str, dict],
    matrix: dict[str, dict[str, str]],
    proxies: dict[str, str] | None = None,
) -> list[dict]:
    """Run all role x endpoint checks and return list of mismatches."""
    mismatches: list[dict] = []

    for role, token in tokens.items():
        if role not in matrix:
            print(f"  [skip] Role '{role}' not in authorization matrix")
            continue

        role_expectations = matrix[role]

        for endpoint_name, expected in role_expectations.items():
            if endpoint_name not in endpoints_by_name:
                print(f"  [skip] Endpoint '{endpoint_name}' not in endpoints config")
                continue

            endpoint = endpoints_by_name[endpoint_name]
            status_code = call_api(endpoint, token, proxies=proxies)
            actual = status_to_result(status_code)

            if not compare(expected, actual):
                mismatches.append({
                    "role": role,
                    "endpoint": endpoint_name,
                    "expected": expected,
                    "actual": actual,
                    "status": status_code,
                })

    return mismatches


def parse_args() -> argparse.Namespace:
    base = Path(__file__).parent
    parser = argparse.ArgumentParser(description="BAC Analyzer - Authorization matrix and differential analysis")
    parser.add_argument("--diff", action="store_true", help="Run differential role comparison analysis")
    parser.add_argument("--tokens", default=str(base / "tokens.json"), help="Path to tokens.json")
    parser.add_argument("--endpoints", default=str(base / "endpoints.yaml"), help="Path to endpoints.yaml")
    parser.add_argument("--matrix", default=str(base / "authorization_matrix.yaml"), help="Path to authorization_matrix.yaml")
    parser.add_argument("--openapi", metavar="spec.yaml", help="OpenAPI spec path (optional)")
    parser.add_argument("--base-url", metavar="URL", help="Base URL for API (optional)")
    parser.add_argument("--idor", action="store_true", help="Run IDOR checks (optional)")
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help="Forward HTTP(S) traffic to proxy (e.g. http://127.0.0.1:8080 for Burp Suite)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    base = Path(__file__).parent
    print("BAC Analyzer - Loading config...")

    tokens = load_tokens(args.tokens)
    endpoints_by_name = load_endpoints(args.endpoints)
    matrix = load_matrix(args.matrix)

    # Proxy for Burp etc.: both http and https via same proxy URL
    proxies = None
    if args.proxy:
        proxy_url = args.proxy.strip()
        if not proxy_url.startswith("http"):
            proxy_url = "http://" + proxy_url
        proxies = {"http": proxy_url, "https": proxy_url}
        print(f"  Proxy: {proxy_url}")

    roles_in_matrix = set(matrix.keys()) & set(tokens.keys())
    endpoints_in_matrix = set()
    for role_expectations in matrix.values():
        endpoints_in_matrix.update(role_expectations.keys())
    endpoints_tested = endpoints_in_matrix & set(endpoints_by_name.keys())

    total_checks = sum(
        1
        for role in roles_in_matrix
        for ep in matrix[role]
        if ep in endpoints_by_name
    )

    print(f"  Roles: {list(tokens.keys())}")
    print(f"  Endpoints: {list(endpoints_by_name.keys())}")
    print("Running authorization checks...\n")

    mismatches = run_checks(tokens, endpoints_by_name, matrix, proxies=proxies)

    # Print mismatches
    if mismatches:
        print("--- Mismatches ---")
        for m in mismatches:
            print(
                f"  Role: {m['role']}, Endpoint: {m['endpoint']} | "
                f"Expected: {m['expected']}, Actual: {m['actual']} (HTTP {m['status']})"
            )
        print()
    else:
        print("No mismatches found.\n")

    # Differential analysis (when --diff)
    differential_findings: list[dict] = []
    if args.diff:
        print()
        differential_findings = run_differential_analysis(
            tokens, endpoints_by_name, proxies=proxies
        )
        if differential_findings:
            print("\n--- Differential findings ---")
            for f in differential_findings:
                print(
                    f"  [{f['severity'].upper()}] {f['endpoint']} | "
                    f"roles: {f['roles_compared']} | {f['reason']}"
                )
            print()

    # Summary
    print("--- Summary ---")
    print(f"Tested roles: {len(roles_in_matrix)}")
    print(f"Tested endpoints: {len(endpoints_tested)}")
    print(f"Total checks: {total_checks}")
    print(f"Mismatches found: {len(mismatches)}")
    if args.diff:
        print(f"Differential findings: {len(differential_findings)}")

    # Report structure: matrix_mismatches, idor_findings, differential_findings
    report = {
        "matrix_mismatches": mismatches,
        "idor_findings": [],
        "differential_findings": differential_findings,
    }
    report_path = base / "report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to {report_path}")


if __name__ == "__main__":
    main()
