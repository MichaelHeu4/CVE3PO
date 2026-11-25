"""Deliberately small osquery subset, enforced on server and agent."""
import re

TABLES = {
    "processes": {"pid", "name", "path", "state", "on_disk", "start_time", "parent"},
    "listening_ports": {"pid", "port", "protocol", "address"},
    "deb_packages": {"name", "version", "arch", "source", "status"},
    "rpm_packages": {"name", "version", "release", "arch", "epoch"},
    "programs": {"name", "version", "publisher"},
    "services": {"name", "display_name", "status", "start_type"},
    "systemd_units": {"id", "description", "load_state", "active_state", "sub_state", "unit_file_state", "fragment_path"},
    "process_open_sockets": {"pid", "family", "protocol", "local_address", "local_port", "remote_address", "remote_port", "state"},
    "process_memory_map": {"pid", "path", "permissions"},
    "system_controls": {"name", "current_value", "config_value", "type"},
    "registry": {"key", "path", "name", "type", "data", "mtime"},
    "file": {"path", "filename", "type", "mode", "uid", "gid", "size", "mtime", "product_version"},
}
_QUERY = re.compile(
    r"\A\s*select\s+(?P<columns>[a-z_,\s]+)\s+from\s+(?P<table>[a-z_]+)"
    r"(?:\s+where\s+(?P<where>.+?))?"
    r"\s+limit\s+(?P<limit>[0-9]{1,3})\s*;?\s*\Z", re.IGNORECASE)
_CONDITION = re.compile(r"\s*([a-z_]+)\s*(=|!=|<>|<=|>=|<|>|like)\s*('[a-z0-9_.+@%/\\: -]{1,256}'|[0-9]{1,20})\s*", re.IGNORECASE)


def validate_query(query):
    if not isinstance(query, str) or len(query) > 1024:
        raise ValueError("Invalid query length")
    match = _QUERY.fullmatch(query)
    if not match:
        raise ValueError("Only a single allowlisted SELECT with LIMIT and optional equality filter is supported")
    table = match.group("table").lower()
    columns = [value.strip().lower() for value in match.group("columns").split(",")]
    allowed = TABLES.get(table, set())
    if not allowed or not columns or not all(column in allowed for column in columns):
        raise ValueError("Table or column is not allowed")
    clauses = re.split(r"\s+and\s+", match.group("where"), flags=re.IGNORECASE) if match.group("where") else []
    conditions = []
    if len(clauses) > 5:
        raise ValueError("Too many filters")
    for clause in clauses:
        condition = _CONDITION.fullmatch(clause)
        if not condition or condition.group(1).lower() not in allowed:
            raise ValueError("Unsupported filter")
        conditions.append((condition.group(1).lower(), condition.group(2).lower(), condition.group(3).strip("'")))
    if table == "registry":
        safe_prefix = "hkey_local_machine\\system\\currentcontrolset\\control\\securityproviders\\schannel\\protocols\\"
        if not any(field in ("key", "path") and op == "=" and value.casefold().startswith(safe_prefix) for field, op, value in conditions):
            raise ValueError("Registry checks require an exact path under the Schannel protocols key")
    if table == "system_controls" and not any(field == "name" and op == "=" and (value.startswith("net.") or value in {"kernel.unprivileged_bpf_disabled", "kernel.kptr_restrict"}) for field, op, value in conditions):
        raise ValueError("System control checks require an allowed exact setting name")
    if table == "file" and not any(field == "path" and op == "=" and "%" not in value for field, op, value in conditions):
        raise ValueError("File checks require an exact path")
    if not 1 <= int(match.group("limit")) <= 100:
        raise ValueError("LIMIT must be between 1 and 100")
    return query.strip().rstrip(";")
