from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List, Optional, Set
import psutil
from feature_extraction import WindowFeatures

DEFAULT_ALLOWLIST = {
    "rsync", "restic", "borg", "duplicity", "tar", "zip", "gzip",
    "7z", "7z.exe", "7zg.exe", "winrar.exe", "robocopy.exe",
}

@dataclass
class Policy:
    detect_threshold: float = 0.7   
    high_score: float = 0.9         
    high_files: int = 50            
    high_eps: float = 20.0          
    allowlist: Set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWLIST))


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: str
    remote_connections: int


@dataclass
class Decision:
    verdict: str              
    severity: str             
    reasons: List[str]
    actions: List[str]        

def gather_process_info(pid: Optional[int]) -> Optional[ProcessInfo]:
    if pid is None:
        return None
    try:
        proc = psutil.Process(pid)
        getter = getattr(proc, "net_connections", None) or proc.connections
        remote = [c for c in getter(kind="inet") if c.raddr]
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            exe = ""
        return ProcessInfo(pid=pid, name=proc.name(), exe=exe, remote_connections=len(remote))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def decide(
    score: float,
    window: WindowFeatures,
    proc: Optional[ProcessInfo],
    policy: Optional[Policy] = None,
) -> Decision:
    p = policy or Policy()

    if score < p.detect_threshold:
        return Decision("ignore", "none", [f"score {score:.2f} is below {p.detect_threshold}"], [])

    reasons = [
        f"model score {score:.2f} is at or above the {p.detect_threshold} threshold",
        f"{window.files_touched} files touched ({window.writes} writes, {window.renames} renames) "
        f"at {window.events_per_second:.0f} events/s",
    ]
    if window.mean_entropy_delta >= 2.0:
        reasons.append(
            f"file contents became much more random (+{window.mean_entropy_delta:.1f} bits/byte), "
            "which is what encryption does"
        )
    if window.ext_change_rate >= 0.5:
        reasons.append(f"{window.ext_change_rate:.0%} of renames changed the file extension")

    if proc and proc.name.lower() in p.allowlist:
        reasons.append(f"process '{proc.name}' is on the allowlist of known bulk-I/O tools")
        return Decision("alert", "medium", reasons, [])

    high = score >= p.high_score and (
        window.files_touched >= p.high_files or window.events_per_second >= p.high_eps
    )
    if not high:
        reasons.append("below the high-severity bar, so a human should review it")
        return Decision("alert", "medium", reasons, [])

    if proc is None:
        reasons.append("no process was identified (a userspace file watcher gives no PID), "
                       "so there is nothing to stop automatically")
        return Decision("alert", "high", reasons, [])

    if proc.pid in {os.getpid(), os.getppid(), 1}:
        reasons.append(f"pid {proc.pid} is a protected process (this tool, its parent, or init)")
        return Decision("alert", "high", reasons, [])

    reasons.append(f"high severity: stopping '{proc.name}' (pid {proc.pid})")
    actions = ["kill_process"]
    verdict = "kill"
    if proc.remote_connections > 0:
        reasons.append(
            f"it also has {proc.remote_connections} open connection(s) to remote hosts, "
            "so data may be leaving: isolating the host as well"
        )
        actions.append("isolate_host")
        verdict = "kill_and_isolate"
    return Decision(verdict, "high", reasons, actions)