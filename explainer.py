from __future__ import annotations
import json
import re
import urllib.request
from typing import Optional
from decision_engine import Decision, ProcessInfo
from feature_extraction import WindowFeatures

ACTION_TEXT = {
    "kill_process": "stop the process",
    "isolate_host": "cut the host off from the network",
}

def template_summary(
    decision: Decision, window: WindowFeatures, proc: Optional[ProcessInfo], score: float
):
    who = f"{proc.name} (pid {proc.pid})" if proc else f"folder '{window.actor_id}' (no process identified)"
    actions = ", ".join(ACTION_TEXT[a] for a in decision.actions) or "none (alert only)"
    lines = [
        f"Verdict: {decision.verdict.upper()}  |  severity: {decision.severity}  |  score: {score:.2f}",
        f"Source: {who}",
        "Why:",
        *[f"  - {r}" for r in decision.reasons],
        f"Action: {actions}",
    ]
    return "\n".join(lines)


def _ask_ollama(prompt: str, model: str, host: str, timeout: float) -> Optional[str]:
    body = json.dumps(
        {"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.2}}
    ).encode()
    req = urllib.request.Request(
        host.rstrip("/") + "/api/generate", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = json.loads(resp.read().decode()).get("response", "").strip()
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        return text or None
    except Exception:
        return None  


def explain(
    decision: Decision,
    window: WindowFeatures,
    proc: Optional[ProcessInfo],
    score: float,
    local_model: Optional[str] = None,
    ollama_host: str = "http://localhost:11434",
    timeout: float = 30.0,
) -> str:
    base = template_summary(decision, window, proc, score)
    if not local_model:
        return base

    prompt = (
        "You are writing a short incident note for a security analyst. A rule engine has "
        "ALREADY made the decision below. Do not change it, do not add facts that are not "
        "listed, and do not give advice. Write 3 or 4 plain sentences saying what was "
        "observed and what was done.\n\n" + base
    )
    if "qwen3" in local_model.lower():
        prompt += "\n\n/no_think"
    text = _ask_ollama(prompt, local_model, ollama_host, timeout)
    if text is None:
        return base + f"\n(local model '{local_model}' was unavailable; template summary shown)"
    return base + f"\n\nPlain-language note (written by local model '{local_model}', "\
                  "not part of the decision):\n" + text