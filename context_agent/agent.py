"""CVE3PO context pilot agent. Separate from the existing inventory agent."""
import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    from .policy import validate_local_query
except ImportError:
    from policy import validate_local_query

MAX_OUTPUT = 1_500_000
LOG = logging.getLogger("cve3po-context-agent")


def apply_windows_affinity(cpus):
    """Limit this process to selected logical CPUs in its primary group."""
    if not cpus:
        return
    if os.name != "nt":
        raise ValueError("Windows CPU affinity is only supported on Windows")
    import ctypes
    if any(not isinstance(cpu, int) or isinstance(cpu, bool) or cpu < 0 or cpu >= 64 for cpu in cpus):
        raise ValueError("CPU numbers must be within the primary processor group (0-63)")
    mask = sum(1 << cpu for cpu in set(cpus))
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.GetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
    kernel.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    process_mask, system_mask = ctypes.c_size_t(), ctypes.c_size_t()
    process = kernel.GetCurrentProcess()
    if not kernel.GetProcessAffinityMask(process, ctypes.byref(process_mask), ctypes.byref(system_mask)):
        raise ctypes.WinError(ctypes.get_last_error())
    if mask & system_mask.value != mask:
        raise ValueError("Configured CPUs are unavailable in the primary processor group")
    if not kernel.SetProcessAffinityMask(process, mask):
        raise ctypes.WinError(ctypes.get_last_error())


def load_config(path):
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)
    url = config["server_url"].rstrip("/")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("server_url must be an HTTPS URL without credentials")
    if not config.get("token") or not os.path.isabs(config["osquery_path"]):
        raise ValueError("A token and absolute osquery_path are required")
    config["server_url"] = url
    config["poll_seconds"] = max(15, min(int(config.get("poll_seconds", 60)), 3600))
    return config


def run_limited(args, environment=None, timeout=60):
    # A file avoids buffering unbounded process output in memory.
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(args, stdout=output, stderr=subprocess.DEVNULL, env=environment, shell=False)
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if time.monotonic() >= deadline or output.tell() > MAX_OUTPUT:
                    process.kill()
                    process.wait()
                    raise ValueError("Process exceeded time or output limit")
                time.sleep(0.1)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        if process.returncode != 0 or output.tell() > MAX_OUTPUT:
            raise ValueError("Process failed or output exceeded limit")
        output.seek(0)
        return json.loads(output.read(MAX_OUTPUT + 1).decode("utf-8"))


def execute(job, config):
    try:
        if job["kind"] == "apache":
            try:
                from .apache_check import collect
            except ImportError:
                from apache_check import collect
            return collect(config, run_limited)
        if job["kind"] == "query":
            query = validate_local_query(job["query"], config)
            data = run_limited([config["osquery_path"], "--json", query])
            if not isinstance(data, list) or len(data) > 100:
                raise ValueError("Invalid osquery result")
            return {"status": "success", "rows": data, "interpretation": "not_determined"}
        if job["kind"] == "inventory":
            legacy = config.get("legacy_agent_path", "")
            if not os.path.isabs(legacy):
                raise ValueError("No absolute legacy_agent_path configured")
            environment = os.environ.copy()
            environment["DRY_RUN"] = "true"
            if config.get("legacy_agent_config"):
                environment["SOFTWARE_AGENT_CONFIG"] = config["legacy_agent_config"]
            data = run_limited([legacy], environment, timeout=120)
            if not isinstance(data, dict) or not isinstance(data.get("software"), list):
                raise ValueError("Invalid inventory snapshot")
            return {"status": "success", "inventory": data}
        raise ValueError("Unknown job kind")
    except (OSError, ValueError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": str(exc)[:500]}


def post(config, path, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(config["server_url"] + path, body,
        {"Authorization": "Bearer " + config["token"], "Content-Type": "application/json"}, method="POST")
    # Redirects must not forward agent credentials to another host.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
        return json.load(response)


def run(config, stop):
    apply_windows_affinity(config.get("windows_cpus", []))
    try:
        version = subprocess.run([config["osquery_path"], "--version"], capture_output=True, text=True, timeout=5, check=True).stdout.strip()[:100]
    except (OSError, subprocess.SubprocessError):
        version = "unavailable"
    capabilities = {"agent": "cve3po-context-agent", "version": "0.2", "platform": platform.system(),
                    "osquery_available": os.path.isfile(config["osquery_path"]),
                    "osquery_version": version,
                    "apache_check": bool(platform.system() == "Linux" and config.get("apache_config_path") and config.get("apache_server_root") and config.get("apache_allowed_roots")),
                    "augeas_allowed_roots": config.get("augeas_allowed_roots", []),
                    "augeas_allowed_labels": config.get("augeas_allowed_labels", []),
                    "inventory_available": os.path.isfile(config.get("legacy_agent_path", ""))}
    while not stop.is_set():
        try:
            job = post(config, "/api/context-agent/poll/", {"capabilities": capabilities}).get("job")
            if job:
                result = execute(job, config)
                post(config, "/api/context-agent/jobs/%d/result/" % job["id"], {"lease": job["lease"], "result": result})
        except Exception:
            LOG.exception("Context agent poll failed")
        stop.wait(config["poll_seconds"])


def config_path():
    return os.environ.get("CVE3PO_CONTEXT_CONFIG", os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "CVE3PO-Context", "config.json") if os.name == "nt" else "/etc/cve3po-context-agent/config.json")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run(load_config(config_path()), threading.Event())
