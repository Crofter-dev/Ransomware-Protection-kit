from __future__ import annotations
import argparse
import os
import time
import response as actions
from decision_engine import Policy, decide, gather_process_info
from detector import RansomwareDetector
from explainer import explain
from feature_extraction import WindowFeatures
from file_monitor import FileMonitor

def _resolve_pid(actor_id: str):
    try:
        return int(actor_id)
    except ValueError:
        return None


def carry_out(decision, pid: int | None) -> list[str]:
    results = []
    for step in decision.actions:
        if step == "kill_process" and pid is not None:
            r = actions.kill_process(pid)
        elif step == "isolate_host":
            r = actions.isolate_host()
        else:
            continue
        results.append(f"{r.action}: {'ok' if r.success else 'FAILED'} - {r.detail}")
    return results


def handle_windows(windows: list[WindowFeatures], detector: RansomwareDetector,
                   policy: Policy, enforce: bool, local_model: str | None, ollama_host: str) -> None:
    for w in windows:
        score = detector.score(w)
        tag = "SUSPICIOUS" if score >= policy.detect_threshold else "ok"
        print(
            f"[detector] actor={w.actor_id} score={score:.3f} [{tag}] "
            f"writes={w.writes} renames={w.renames} "
            f"mean_entropy_delta={w.mean_entropy_delta:.2f} eps={w.events_per_second:.1f}"
        )
        if score < policy.detect_threshold:
            continue

        pid = _resolve_pid(w.actor_id)
        proc = gather_process_info(pid)
        decision = decide(score, w, proc, policy)

        print("----- incident -----")
        print(explain(decision, w, proc, score, local_model=local_model, ollama_host=ollama_host))
        if decision.actions:
            if enforce:
                for line in carry_out(decision, pid):
                    print("[enforce]", line)
            else:
                print("[dry run] no action taken (add --enforce to act)")
        print("--------------------")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--watch-dir", default="./watched")
    parser.add_argument("--threshold", type=float, default=0.7)
    parser.add_argument("--enforce", action="store_true",
                        help="Actually carry out kill/isolate decisions. Default is a dry run.")
    parser.add_argument("--local-model", default=None,
                        help="Name of a model served by a local Ollama, used only to word the summary.")
    parser.add_argument("--ollama-host", default="http://localhost:11434")
    args = parser.parse_args()

    os.makedirs(args.watch_dir, exist_ok=True)
    detector = RansomwareDetector(threshold=args.threshold)
    policy = Policy(detect_threshold=args.threshold)

    monitor = FileMonitor(
        args.watch_dir,
        on_windows=lambda windows: handle_windows(
            windows, detector, policy, args.enforce, args.local_model, args.ollama_host
        ),
    )
    monitor.start()

    mode = "ENFORCING" if args.enforce else "dry run"
    print(f"[orchestrator] live ({mode}). watching {args.watch_dir}. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()

if __name__ == "__main__":
    main()