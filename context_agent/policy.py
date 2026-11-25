"""Deliberately small osquery subset, enforced on server and agent."""
import re

TABLES = {
    "processes": {"pid", "name", "path"},
    "listening_ports": {"pid", "port", "protocol", "address"},
    "deb_packages": {"name", "version", "arch"},
    "rpm_packages": {"name", "version", "release", "arch"},
    "programs": {"name", "version", "publisher"},
    "services": {"name", "display_name", "status", "start_type"},
}
_QUERY = re.compile(
    r"\A\s*select\s+(?P<columns>[a-z_,\s]+)\s+from\s+(?P<table>[a-z_]+)"
    r"(?:\s+where\s+(?P<field>[a-z_]+)\s*=\s*'(?P<value>[a-zA-Z0-9_.+@ -]{1,128})')?"
    r"\s+limit\s+(?P<limit>[0-9]{1,3})\s*;?\s*\Z", re.IGNORECASE)


def validate_query(query):
    if not isinstance(query, str) or len(query) > 1024:
        raise ValueError("Invalid query length")
    match = _QUERY.fullmatch(query)
    if not match:
        raise ValueError("Only a single allowlisted SELECT with LIMIT and optional equality filter is supported")
    table = match.group("table").lower()
    columns = [value.strip().lower() for value in match.group("columns").split(",")]
    allowed = TABLES.get(table, set())
    field = (match.group("field") or "").lower()
    if not allowed or not columns or not all(column in allowed for column in columns):
        raise ValueError("Table or column is not allowed")
    if field and field not in allowed:
        raise ValueError("Filter column is not allowed")
    if not 1 <= int(match.group("limit")) <= 100:
        raise ValueError("LIMIT must be between 1 and 100")
    return query.strip().rstrip(";")
