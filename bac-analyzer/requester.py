"""HTTP requester for BAC analyzer. Sends API requests with Bearer token."""

import requests
from typing import Any


def call_api(
    endpoint: dict[str, Any],
    token: str,
    proxies: dict[str, str] | None = None,
) -> int:
    """
    Send HTTP request using the endpoint config and Bearer token.
    Returns the response status code. Handles exceptions gracefully.
    If proxies is set (e.g. {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}),
    traffic is forwarded to the proxy (e.g. Burp Suite).
    """
    method = endpoint.get("method", "GET")
    url = endpoint.get("url", "")
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=10,
            proxies=proxies,
        )
        return response.status_code
    except requests.RequestException:
        return 0  # Treat network/request errors as failure (deny)
