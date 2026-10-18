from __future__ import annotations
import os
import shutil
import time
from dataclasses import dataclass
import psutil

QUARANTINE_DIR = r"C:\Users"

@dataclass
class ActionResult:
    action: str
    success: bool
    detail: str


def inspect_process_tree(pid: int) -> ActionResult:
    try:
        proc = psutil.Process(pid)
        children = [c.pid for c in proc.children(recursive=True)]
        detail = (
            f"name={proc.name()} ppid={proc.ppid()} children={children} "
            f"cmdline={' '.join(proc.cmdline())}"
        )
        return ActionResult("inspect_process_tree", True, detail)
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return ActionResult("inspect_process_tree", False, str(e))


def list_open_files(pid: int) -> ActionResult:
    try:
        proc = psutil.Process(pid)
        files = [f.path for f in proc.open_files()]
        return ActionResult("list_open_files", True, f"{len(files)} open files: {files[:20]}")
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return ActionResult("list_open_files", False, str(e))


def check_network_connections(pid: int) -> ActionResult:
    try:
        proc = psutil.Process(pid)
        conns = proc.net_connections(kind="inet")
        summary = [f"{c.laddr}->{c.raddr} [{c.status}]" for c in conns]
        return ActionResult("check_network_connections", True, f"{len(summary)} connections: {summary[:10]}")
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return ActionResult("check_network_connections", False, str(e))


def quarantine_file(path: str) -> ActionResult:
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        if not os.path.exists(path):
            return ActionResult("quarantine_file", False, f"path does not exist: {path}")
        dest = os.path.join(QUARANTINE_DIR, f"{int(time.time())}_{os.path.basename(path)}")
        shutil.move(path, dest)
        return ActionResult("quarantine_file", True, f"moved {path} -> {dest}")
    except OSError as e:
        return ActionResult("quarantine_file", False, str(e))


def kill_process(pid: int) -> ActionResult:
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()
        proc.wait(timeout=3)
        return ActionResult("kill_process", True, f"terminated pid={pid} ({name})")
    except psutil.TimeoutExpired:
        try:
            proc.kill()
            return ActionResult("kill_process", True, f"force-killed pid={pid}")
        except Exception as e:
            return ActionResult("kill_process", False, str(e))
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return ActionResult("kill_process", False, str(e))


def check_shadow_copies():
    return ActionResult("check_shadow_copies", True, "stub: wire up a real snapshot check for your OS")


def isolate_host():
    return ActionResult(
        "isolate_host",
        True,
        "SIMULATED: would isolate host from network here. "
        "Wire to a real firewall rule only in an isolated test VM.",
    )