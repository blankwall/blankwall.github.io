"""Read-only macOS inventory of privileged services and investigation leads."""

import argparse
import datetime
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys


def command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        return "", str(error)
    return result.stdout, result.stderr.strip() if result.returncode else ""


def parse_processes(text):
    rows = []
    for line in text.splitlines():
        fields = line.strip().split(None, 4)
        if len(fields) != 5:
            continue
        try:
            pid, ppid, ruid, euid = map(int, fields[:4])
        except ValueError:
            continue
        if euid == 0:
            rows.append(dict(pid=pid, ppid=ppid, ruid=ruid, euid=euid,
                             executable=fields[4]))
    return rows


def third_party(path):
    if not path.startswith("/"):
        return False
    if path.startswith(("/usr/local/", "/opt/")):
        return True
    return not path.startswith(("/System/", "/usr/", "/bin/", "/sbin/"))


def file_info(path):
    path = Path(path)
    try:
        info = path.stat()
        writable_ancestors = []
        for parent in path.parents:
            if os.access(parent, os.W_OK):
                writable_ancestors.append(str(parent))
        return {
            "path": str(path), "resolved_path": str(path.resolve()),
            "uid": info.st_uid, "gid": info.st_gid,
            "mode": stat.filemode(info.st_mode),
            "group_or_other_write_bit": bool(info.st_mode & 0o022),
            "writable_by_current_user": os.access(path, os.W_OK),
            "writable_ancestors_by_current_user": writable_ancestors,
        }
    except OSError as error:
        return {"path": str(path), "error": str(error)}


def read_jobs(directories, warnings):
    jobs = []
    for directory in directories:
        try:
            paths = sorted(Path(directory).glob("*.plist"))
        except OSError as error:
            warnings.append(str(error))
            continue
        for path in paths:
            try:
                with path.open("rb") as stream:
                    data = plistlib.load(stream)
                if not isinstance(data, dict):
                    raise ValueError("Not a plist dictionary")
                arguments = data.get("ProgramArguments", [])
                executable = data.get("Program")
                if not executable and isinstance(arguments, list) and arguments:
                    executable = arguments[0]
                if not isinstance(executable, str) or not executable.startswith("/"):
                    warnings.append(f"{path}: no absolute executable path; skipped")
                    continue
                jobs.append({
                    "label": data.get("Label", path.stem),
                    "plist": str(path), "executable": executable,
                    "configured_user": data.get("UserName", "root"),
                    "mach_services": data.get("MachServices", {}),
                    "sockets": data.get("Sockets", {}),
                    "keep_alive": data.get("KeepAlive", False),
                    "run_at_load": data.get("RunAtLoad", False),
                })
            except (OSError, ValueError, plistlib.InvalidFileException) as error:
                warnings.append(f"{path}: {error}")
    return jobs


def parse_lsof(text):
    rows = []
    pid, kind, name = None, None, None

    def append():
        if pid is not None and kind in ("unix", "IPv4", "IPv6") and name:
            rows.append({"pid": pid, "type": kind, "name": name})

    for line in text.splitlines():
        if not line:
            continue
        field, value = line[0], line[1:]
        if field in ("p", "f"):
            append()
            kind, name = None, None
        if field == "p":
            pid = int(value)
        elif field == "t":
            kind = value
        elif field == "n":
            name = value
    append()
    return rows


def signature(path):
    # codesign writes display metadata to stderr even when successful.
    try:
        result = subprocess.run(
            ["/usr/bin/codesign", "-dv", "--verbose=2", path],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as failure:
        return {"error": str(failure)}
    output = result.stdout + "\n" + result.stderr
    details = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in ("Identifier", "TeamIdentifier", "Authority", "Signature"):
            details.setdefault(key, []).append(value)
    if not details:
        details["note"] = result.stderr.strip() or "No readable signing metadata"
    return details


def inventory(include_apple=False):
    warnings = []
    output, error = command(["/bin/ps", "-axo", "pid=,ppid=,ruid=,uid=,comm="])
    if error:
        raise RuntimeError(f"Cannot collect process inventory: {error}")
    processes = parse_processes(output)
    jobs = read_jobs(
        ["/Library/LaunchDaemons", "/System/Library/LaunchDaemons"], warnings,
    )
    selected_processes = [
        p for p in processes if p["executable"].startswith("/")
        and (include_apple or third_party(p["executable"]))
    ]
    selected_jobs = [
        job for job in jobs
        if job["configured_user"] == "root"
        and (include_apple or third_party(job["executable"]))
    ]
    paths = sorted({p["executable"] for p in selected_processes}
                   | {j["executable"] for j in selected_jobs})
    services = []
    for path in paths:
        resolved = os.path.realpath(path)
        matching_processes = [
            p for p in selected_processes
            if os.path.realpath(p["executable"]) == resolved
        ]
        matching_jobs = [
            job for job in selected_jobs
            if os.path.realpath(job["executable"]) == resolved
        ]
        info = file_info(path)
        leads = []
        if matching_processes:
            leads.append("Observed effective UID 0")
        if matching_jobs and not matching_processes:
            leads.append("Configured root job; no matching root process observed")
        if any(job["mach_services"] or job["sockets"] for job in matching_jobs):
            leads.append("Declared IPC activation: inspect caller authorization")
        if info.get("writable_by_current_user") or info.get("writable_ancestors_by_current_user"):
            leads.append("Caller-writable executable or ancestor: inspect ownership and ACLs")
        services.append({
            "executable": path, "file": info, "processes": matching_processes,
            "launch_daemons": matching_jobs, "signing": signature(path),
            "investigation_leads": leads,
        })

    endpoints = []
    if selected_processes:
        output, error = command([
            "/usr/sbin/lsof", "-nP", "-a", "-p",
            ",".join(str(p["pid"]) for p in selected_processes), "-F", "pftn",
        ])
        endpoints = parse_lsof(output)
        if error:
            warnings.append(f"lsof: {error}")
    socket_nodes = []
    try:
        for path in sorted(Path("/var/run").iterdir()):
            try:
                info = path.stat()
                if stat.S_ISSOCK(info.st_mode) and info.st_uid == 0:
                    socket_nodes.append(file_info(path))
            except OSError as error:
                warnings.append(f"{path}: {error}")
    except OSError as error:
        warnings.append(str(error))
    return {
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "caller_euid": os.geteuid(),
        "scope": "All root executables" if include_apple else
                 "Non-platform paths (path heuristic, not publisher verification)",
        "services": services,
        "unresolved_root_processes": [
            p for p in processes if not p["executable"].startswith("/")
        ],
        "visible_process_endpoints": endpoints,
        "unattributed_root_owned_socket_nodes": socket_nodes,
        "warnings": warnings,
        "limitations": [
            "Read-only snapshot; no sudo, socket connections, helper requests, or service changes.",
            "Root service does not mean exploitable service; signing metadata does not prove safety.",
            "No matching root process does not establish job inactivity; activation may be on demand.",
            "lsof visibility is limited without root; missing endpoints do not prove absence.",
            "Socket nodes are not attributed to services unless independently observed through lsof.",
            "Writable paths and socket modes are investigation leads, not proof of an authorization bypass.",
            "Process names may be truncated; exact executable-path matching can miss jobs or wrappers.",
            "No exhaustive XPC, set-ID, entitlement, TCC, or authorization-policy analysis.",
        ],
    }


def print_summary(report):
    print(f"Root-helper triage: {len(report['services'])} executable candidates")
    print(f"Scope: {report['scope']}")
    for service in report["services"]:
        pids = ", ".join(str(p["pid"]) for p in service["processes"]) or "not observed"
        print(f"\n{service['executable']}\n  Root PIDs: {pids}")
        info = service["file"]
        if "error" in info:
            print(f"  File metadata unavailable: {info['error']}")
        else:
            print(f"  File: {info['mode']} uid={info['uid']} gid={info['gid']}")
            for parent in info["writable_ancestors_by_current_user"]:
                print(f"  Current-user-writable ancestor: {parent}")
        for job in service["launch_daemons"]:
            print(f"  LaunchDaemon: {job['label']} ({job['plist']})")
            if job["mach_services"]:
                print("  Mach services: " + ", ".join(job["mach_services"]))
            if job["sockets"]:
                print("  Socket configuration: " + json.dumps(job["sockets"]))
        teams = service["signing"].get("TeamIdentifier", [])
        print("  Signing team: " + (", ".join(teams) or "unavailable"))
        for lead in service["investigation_leads"]:
            print(f"  Investigate: {lead}")
    print("\nVisible process endpoints:")
    for endpoint in report["visible_process_endpoints"]:
        print(f"  PID {endpoint['pid']} {endpoint['type']}: {endpoint['name']}")
    print("\nRoot processes without an absolute executable path (unclassified):")
    for process in report["unresolved_root_processes"]:
        print(f"  PID {process['pid']}: {process['executable']}")
    print("\nRoot-owned /var/run socket nodes (unattributed):")
    for node in report["unattributed_root_owned_socket_nodes"]:
        print(f"  {node['mode']} {node['path']}")
    print("\nThese are investigation leads, not demonstrated paths to root.")
    print("Endpoint visibility is limited; no helper operations were invoked.")
    for warning in report["warnings"]:
        print(f"Warning: {warning}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-apple", action="store_true",
                        help="Include platform executable paths")
    parser.add_argument("--json", action="store_true", help="Print full JSON to stdout")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("This inventory requires macOS")
    try:
        report = inventory(args.include_apple)
    except RuntimeError as error:
        parser.exit(1, f"{error}\n")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_summary(report)


if __name__ == "__main__":
    main()
