from __future__ import annotations
import argparse
import time
from decision_engine import ProcessInfo, decide
from explainer import explain
from feature_extraction import WindowFeatures

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local-model", default=None,
                    help="Model name exactly as `ollama list` shows it.")
    ap.add_argument("--ollama-host", default="http://localhost:11434")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="Seconds to wait for the model (the first call loads it, so allow time).")
    args = ap.parse_args()

    window = WindowFeatures(
        actor_id="4242", window_start=0.0, window_seconds=3.0, files_touched=80, writes=80,
        renames=80, deletes=0, creates=0, mean_entropy_delta=3.7, max_entropy_delta=7.5,
        ext_change_rate=1.0, unique_dirs_touched=1, events_per_second=40.0,
        high_entropy_write_rate=0.9,
    )
    proc = ProcessInfo(pid=4242, name="unknown_app.exe", exe="C:/Users/x/unknown_app.exe",
                       remote_connections=1)
    score = 0.99
    decision = decide(score, window, proc)

    start = time.time()
    text = explain(decision, window, proc, score, local_model=args.local_model,
                   ollama_host=args.ollama_host, timeout=args.timeout)
    print(text)
    if args.local_model:
        print(f"\n(took {time.time() - start:.1f}s)")

if __name__ == "__main__":
    main()