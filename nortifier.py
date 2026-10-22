from __future__ import annotations
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional
from decision_engine import Decision, ProcessInfo
from feature_extraction import WindowFeatures

def _command(title: str, message: str) -> Optional[List[str]]:
    if sys.platform.startswith("linux"):
        return ["notify-send", "--urgency=critical", title, message]
        
    if sys.platform.startswith("win"):
        def esc(s: str) -> str:
            return s.replace("'", "''")
        script = (
            "Add-Type -AssemblyName System.Windows.Forms;"
            "$n = New-Object System.Windows.Forms.NotifyIcon;"
            "$n.Icon = [System.Drawing.SystemIcons]::Warning;"
            "$n.Visible = $true;"
            f"$n.ShowBalloonTip(10000, '{esc(title)}', '{esc(message)}', 'Warning');"
            "Start-Sleep -Seconds 11; $n.Dispose()"
        )
        return ["powershell", "-NoProfile", "-Command", script]
    return None


def _default_runner(cmd: List[str]):
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def short_message(decision: Decision, window: WindowFeatures,
                  proc: Optional[ProcessInfo], score: float) -> str:
    who = f"{proc.name} (pid {proc.pid})" if proc else f"folder '{window.actor_id}'"
    steps = {"alert": "Alert only, no action taken",
             "kill": "Process stopped",
             "kill_and_isolate": "Process stopped, host isolated"}
    return (f"{who}: {window.files_touched} files changed at "
            f"{window.events_per_second:.0f} events/s (score {score:.2f}). "
            f"{steps.get(decision.verdict, decision.verdict)}.")


class Notifier:
    def __init__(self, cooldown_seconds: float = 60.0,
                 runner: Callable[[List[str]], None] = _default_runner):
        self.cooldown = cooldown_seconds
        self._runner = runner
        self._last: Dict[str, float] = {}

    def send(self, decision: Decision, window: WindowFeatures,
             proc: Optional[ProcessInfo], score: float, acted: bool = False) -> bool:
        if decision.verdict == "ignore":
            return False
        now = time.time()
        if now - self._last.get(window.actor_id, 0.0) < self.cooldown:
            return False

        severity = decision.severity.upper()
        title = f"Ransomware behavior detected ({severity})"
        message = short_message(decision, window, proc, score)
        if decision.actions and not acted:
            message = message.replace("Process stopped", "Would stop process (dry run)")
            message = message.replace("host isolated", "would isolate host")

        cmd = _command(title, message)
        if cmd is None:
            print(f"[notifier] no desktop notifications on this system: {title} - {message}")
            return False
        try:
            self._runner(cmd)
        except Exception as e:  
            print(f"[notifier] could not show notification ({type(e).__name__}: {e})")
            return False
        self._last[window.actor_id] = now
        return True