"""Validation helpers for comparing expected vs actual authorization results."""


def is_allowed(status_code: int) -> bool:
    """Return True if status_code indicates success (not an error)."""
    return status_code < 400


def compare(expected: str, actual: str) -> bool:
    """Return True if expected and actual authorization results match."""
    return expected == actual
