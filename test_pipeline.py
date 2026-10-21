from __future__ import annotations
import http.server
import json
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import psutil  
import orchestrator  
from decision_engine import Policy, ProcessInfo, decide, gather_process_info  # noqa: E402
from explainer import explain, template_summary  # noqa: E402
from feature_extraction import WindowFeatures  # noqa: E402

def make_window(**kw) -> WindowFeatures:
    base = dict(
        actor_id="simtest", window_start=0.0, window_seconds=3.0, files_touched=80,
        writes=80, renames=80, deletes=0, creates=0, mean_entropy_delta=3.7,
        max_entropy_delta=7.5, ext_change_rate=1.0, unique_dirs_touched=1,
        events_per_second=40.0, high_entropy_write_rate=0.9,
    )
    base.update(kw)
    return WindowFeatures(**base)

def proc(name="badproc", pid=424242, remote=0) -> ProcessInfo:
    return ProcessInfo(pid=pid, name=name, exe="/x/" + name, remote_connections=remote)

def test_low_score_is_ignored():
    d = decide(0.3, make_window(), proc())
    assert d.verdict == "ignore" and d.actions == []

def test_medium_score_alerts_only():
    d = decide(0.8, make_window(), proc())
    assert d.verdict == "alert" and d.severity == "medium" and d.actions == []

def test_high_severity_without_process_only_alerts():
    d = decide(0.99, make_window(), None)
    assert d.verdict == "alert" and d.severity == "high" and d.actions == []
    assert any("no process" in r for r in d.reasons)

def test_allowlisted_tool_never_auto_killed():
    d = decide(0.99, make_window(), proc(name="rsync"))
    assert d.verdict == "alert" and d.actions == []


def test_high_severity_with_process_kills():
    d = decide(0.99, make_window(), proc())
    assert d.verdict == "kill" and d.actions == ["kill_process"]


def test_remote_connections_add_isolation():
    d = decide(0.99, make_window(), proc(remote=2))
    assert d.verdict == "kill_and_isolate" and d.actions == ["kill_process", "isolate_host"]


def test_protected_pid_is_never_killed():
    d = decide(0.99, make_window(), proc(pid=os.getpid()))
    assert d.verdict == "alert" and d.actions == []


def test_small_burst_is_not_high_severity():
    d = decide(0.95, make_window(files_touched=10, events_per_second=5.0), proc())
    assert d.verdict == "alert" and d.actions == []


def test_custom_policy_threshold():
    d = decide(0.8, make_window(), proc(), Policy(detect_threshold=0.9))
    assert d.verdict == "ignore"


# ---------- explainer ----------

def test_template_summary_has_the_key_facts():
    d = decide(0.99, make_window(), proc())
    text = template_summary(d, make_window(), proc(), 0.99)
    assert "KILL" in text and "badproc" in text and "stop the process" in text


def test_explainer_without_model_is_just_the_template():
    d = decide(0.99, make_window(), proc())
    text = explain(d, make_window(), proc(), 0.99)
    assert "Verdict:" in text and "local model" not in text


def test_explainer_falls_back_when_model_unreachable():
    d = decide(0.99, make_window(), proc())
    text = explain(d, make_window(), proc(), 0.99, local_model="nope",
                   ollama_host="http://127.0.0.1:9", timeout=2)
    assert "Verdict:" in text and "unavailable" in text


class _FakeOllama(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.server.last_request = json.loads(self.rfile.read(length))
        body = json.dumps({"response": "<think>secret reasoning</think>Files were scrambled fast."}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_explainer_uses_local_model_and_strips_think_tags():
    server = http.server.HTTPServer(("127.0.0.1", 0), _FakeOllama)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        d = decide(0.99, make_window(), proc())
        text = explain(d, make_window(), proc(), 0.99, local_model="fake",
                       ollama_host=f"http://127.0.0.1:{server.server_port}", timeout=5)
    finally:
        server.shutdown()
    assert "Files were scrambled fast." in text
    assert "<think>" not in text and "secret reasoning" not in text
    assert "not part of the decision" in text
    assert "ALREADY made" in server.last_request["prompt"]


# ---------- orchestrator against a real process ----------

class _FixedDetector:
    def __init__(self, score):
        self._score = score

    def score(self, window):
        return self._score


def _start_sleeper():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    time.sleep(0.3)
    return p


def _alive(p) -> bool:
    return p.poll() is None and psutil.pid_exists(p.pid)


def test_gather_process_info_finds_a_real_process():
    p = _start_sleeper()
    try:
        info = gather_process_info(p.pid)
        assert info is not None and info.pid == p.pid and info.remote_connections == 0
    finally:
        p.kill()
        p.wait()
    assert gather_process_info(None) is None


def test_dry_run_leaves_the_process_alone():
    p = _start_sleeper()
    try:
        orchestrator.handle_windows(
            [make_window(actor_id=str(p.pid))], _FixedDetector(0.99), Policy(),
            enforce=False, local_model=None, ollama_host="",
        )
        assert _alive(p), "a dry run must not kill anything"
    finally:
        p.kill()
        p.wait()


def test_enforce_stops_the_process():
    p = _start_sleeper()
    try:
        orchestrator.handle_windows(
            [make_window(actor_id=str(p.pid))], _FixedDetector(0.99), Policy(),
            enforce=True, local_model=None, ollama_host="",
        )
        p.wait(timeout=5)
        assert not _alive(p), "--enforce should have stopped the process"
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()


def test_enforce_ignores_low_scores():
    p = _start_sleeper()
    try:
        orchestrator.handle_windows(
            [make_window(actor_id=str(p.pid))], _FixedDetector(0.2), Policy(),
            enforce=True, local_model=None, ollama_host="",
        )
        assert _alive(p)
    finally:
        p.kill()
        p.wait()


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)