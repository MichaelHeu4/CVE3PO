"""Bounded Apache configuration evidence collection; never a CVE verdict."""
import glob
import os
import re
import time

MAX_FILES = 64
MAX_ROWS = 5000
MAX_SECONDS = 120
DIRECTIVES = {"include", "includeoptional", "sslstrictsnivhostcheck", "sslcacertificatefile",
              "sslcacertificatepath", "sslverifyclient", "sslprotocol", "sslengine",
              "servername", "serveralias", "sslsessiontickets", "loadmodule", "options",
              "allowoverride", "proxyrequests", "traceenable", "servertokens"}


def collect(config, run_limited):
    """Read explicitly configured Apache roots; unresolved conditions remain unknown."""
    root = config.get("apache_server_root", "")
    main = config.get("apache_config_path", "")
    roots = config.get("apache_allowed_roots", [])
    if os.name == "nt":
        raise ValueError("Augeas Apache collection currently supports Linux only")
    if not isinstance(root, str) or not isinstance(main, str) or not os.path.isabs(root) or not os.path.isabs(main) or not isinstance(roots, list) or not roots:
        raise ValueError("Configure absolute apache_server_root, apache_config_path and apache_allowed_roots")
    if not all(isinstance(item, str) and os.path.isabs(item) for item in roots):
        raise ValueError("Apache allowed roots must be absolute paths")
    allowed = [os.path.realpath(item) for item in roots]

    def permitted(path):
        resolved = os.path.realpath(path)
        return any(os.path.commonpath([resolved, parent]) == parent for parent in allowed)

    if not permitted(main):
        raise ValueError("Apache configuration is outside allowed roots")
    pending, seen, files, findings, warnings = [(main, None, "global")], set(), [], [], []
    deadline = time.monotonic() + MAX_SECONDS
    while pending:
        path, parent, inherited_scope = pending.pop(0)
        if time.monotonic() >= deadline:
            warnings.append("Time limit reached; include graph is incomplete")
            break
        if not permitted(path):
            warnings.append("Include outside allowed roots: " + path[:300])
            continue
        path = os.path.realpath(path)
        if path in seen:
            warnings.append("Repeated include or cycle: " + path[:300])
            continue
        seen.add(path)
        if len(seen) > MAX_FILES:
            warnings.append("File limit reached; include graph is incomplete")
            break
        if not os.path.isfile(path):
            warnings.append("Missing or unreadable configuration: " + path[:300])
            continue
        # Literal is generated locally, never received from the server or AI.
        literal = path.replace("'", "''")
        query = "SELECT node, label, value FROM augeas WHERE path = '%s' LIMIT %d" % (literal, MAX_ROWS + 1)
        rows = run_limited([config["osquery_path"], "--json", query], timeout=max(1, min(20, int(deadline-time.monotonic()))))
        if not isinstance(rows, list) or not rows:
            warnings.append("Augeas returned no parsed rows; lens, permissions or file content need verification: " + path[:300])
            continue
        if len(rows) > MAX_ROWS:
            warnings.append("Augeas row limit reached: " + path[:300])
            rows = rows[:MAX_ROWS]
        nodes = {str(row.get("node", "")): row for row in rows if isinstance(row, dict) and row.get("node")}
        arguments = {}
        for child, row in nodes.items():
            parent_node, separator, name = child.rpartition("/")
            if separator and re.fullmatch(r"arg(?:\[\d+\])?", name):
                arguments.setdefault(parent_node, []).append(str(row.get("value", ""))[:512])
        files.append({"path": path, "included_from": parent, "inherited_scope": inherited_scope})
        vhosts = sorted((node for node, row in nodes.items() if str(row.get("label", "")).lower() == "virtualhost"), key=len, reverse=True)
        if any(str(row.get("label", "")).lower() in {"ifmodule", "ifdefine", "ifversion", "if"} for row in nodes.values()):
            warnings.append("Conditional sections require manual verification: " + path[:300])
        for node, row in nodes.items():
            if len(findings) >= 100:
                warnings.append("Evidence limit reached; results are incomplete")
                pending.clear()
                break
            label, value = str(row.get("label", "")), str(row.get("value", ""))
            if label.lower() == "virtualhost":
                args = arguments.get(node, [])
                findings.append({"file": path, "node": node, "virtual_host": node, "directive": "VirtualHost", "arguments": args[:8]})
                continue
            if label.lower() != "directive" or value.lower() not in DIRECTIVES:
                continue
            args = arguments.get(node, [])
            scope = next((v for v in vhosts if node.startswith(v + "/")), inherited_scope)
            # Limit what leaves the host to the specific configuration fields needed here.
            findings.append({"file": path, "node": node, "virtual_host": scope, "directive": value, "arguments": args[:8]})
            if value.lower() not in ("include", "includeoptional"):
                continue
            if not args:
                warnings.append("Include has no parsed path: " + node[:300])
                continue
            if len(args[0]) >= 512:
                warnings.append("Include path is too long to resolve safely: " + node[:300])
                continue
            target = args[0].strip('"\'')
            if "$" in target or "`" in target:
                warnings.append("Include uses an unresolved variable: " + target[:300])
                continue
            pattern = target if os.path.isabs(target) else os.path.join(root, target)
            wildcard_start = min((pattern.find(char) for char in "*?[" if char in pattern), default=len(pattern))
            safe_parent = os.path.dirname(pattern[:wildcard_start]) if wildcard_start < len(pattern) else pattern
            if not permitted(safe_parent):
                warnings.append("Include pattern outside allowed roots: " + pattern[:300])
                continue
            matches = sorted(glob.glob(pattern))[:MAX_FILES + 1]
            if not matches and value.lower() == "include":
                warnings.append("Required include has no matches: " + pattern[:300])
            if len(matches) > MAX_FILES:
                warnings.append("Include match limit reached: " + pattern[:300])
            for match in matches[:MAX_FILES]:
                if os.path.isdir(match):
                    if not permitted(match):
                        warnings.append("Include directory outside allowed roots: " + match[:300])
                        continue
                    for directory, subdirs, filenames in os.walk(match, followlinks=False, onerror=lambda exc: warnings.append("Could not read include directory: " + str(exc)[:300])):
                        subdirs.sort()
                        for filename in sorted(filenames):
                            pending.append((os.path.join(directory, filename), path, scope))
                            if len(pending) > MAX_FILES:
                                warnings.append("Include directory file limit reached: " + match[:300])
                                break
                        if len(pending) > MAX_FILES:
                            break
                else:
                    pending.append((match, path, scope))
    if not files:
        warnings.append("No Apache configuration files could be verified")
    warnings.append("Includes and conditional sections may change effective settings; configuration evidence alone does not prove exploitability or non-applicability")
    vhosts = [{"scope": entry["virtual_host"], "file": entry["file"], "addresses": entry["arguments"],
               "directives": [item for item in findings if item["virtual_host"] == entry["virtual_host"] and item["directive"] != "VirtualHost"]}
              for entry in findings if entry["directive"] == "VirtualHost"]
    return {"status": "success", "interpretation": "not_determined", "files": files,
            "directives": findings, "virtual_hosts": vhosts, "warnings": warnings, "complete": False}
