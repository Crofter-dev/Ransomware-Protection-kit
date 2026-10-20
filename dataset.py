from __future__ import annotations
import argparse
import csv
import os
import random
import shutil
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.join(HERE, "..", "tools"), os.path.join(HERE, "..")):
    sys.path.insert(0, os.path.abspath(_p))

import simulator as sim  
from feature_extraction import FEATURE_NAMES  
from file_monitor import FileMonitor 

WINDOW_SECONDS = 3.0  
SETTLE = WINDOW_SECONDS + 1.5  

def _text_files(folder, n, rng, prefix="doc", ext=".txt"):
    os.makedirs(folder, exist_ok=True)
    for i in range(n):
        with open(os.path.join(folder, f"{prefix}_{i:03d}{ext}"), "w") as f:
            f.write(f"{prefix} {i} some ordinary text\n" * rng.randint(10, 60))

def _files(folder):
    return sorted(os.listdir(folder))

def ben_edit(folder, rng):
    def setup():
        _text_files(folder, rng.randint(3, 15), rng)

    def action():
        names = _files(folder)
        for _ in range(rng.randint(5, 25)):
            with open(os.path.join(folder, rng.choice(names)), "a") as f:
                f.write("one more line of text\n" * rng.randint(1, 5))
            time.sleep(rng.uniform(0.05, 0.4))

    return setup, action

def ben_bulk_rename(folder, rng):
    n = rng.randint(10, 60)
    delay = rng.choice([0, 0.005, 0.02])

    def setup():
        _text_files(folder, n, rng, prefix="img", ext=".jpg")

    def action():
        for name in _files(folder):
            os.rename(os.path.join(folder, name), os.path.join(folder, "2024_" + name))
            time.sleep(delay)

    return setup, action

def ben_ext_change(folder, rng):
    n = rng.randint(10, 60)
    delay = rng.choice([0, 0.005, 0.02])

    def setup():
        _text_files(folder, n, rng, ext=".txt")

    def action():
        for name in _files(folder):
            base, _ = os.path.splitext(name)
            os.rename(os.path.join(folder, name), os.path.join(folder, base + ".md"))
            time.sleep(delay)

    return setup, action

def ben_copy_many(folder, rng):
    def setup():
        os.makedirs(folder, exist_ok=True)

    def action():
        _text_files(folder, rng.randint(20, 100), rng, prefix="copy")

    return setup, action

def ben_download(folder, rng):
    def setup():
        os.makedirs(folder, exist_ok=True)

    def action():
        for i in range(rng.randint(2, 6)):
            part = os.path.join(folder, f"file_{i}.part")
            with open(part, "wb") as f:
                f.write(os.urandom(rng.randint(20_000, 200_000)))
            time.sleep(rng.uniform(0.1, 0.6))
            os.rename(part, part[: -len(".part")] + ".zip")

    return setup, action

def ben_rewrite_many(folder, rng):
    n = rng.randint(20, 60)
    delay = rng.choice([0, 0.005, 0.01])

    def setup():
        _text_files(folder, n, rng)

    def action():
        for name in _files(folder):
            with open(os.path.join(folder, name), "w") as f:
                f.write("rebuilt output line\n" * rng.randint(10, 60))
            time.sleep(delay)

    return setup, action

def atk_rename(folder, rng):
    n = rng.randint(20, 80)
    delay = rng.choice([0, 0.005, 0.02, 0.05])

    def setup():
        sim.seed_target(folder, n)

    def action():
        sim.run_encrypt_pass(folder, delay)

    return setup, action

def atk_inplace(folder, rng):
    n = rng.randint(20, 80)
    delay = rng.choice([0, 0.005, 0.02, 0.05])

    def setup():
        sim.seed_target(folder, n)

    def action():
        for name in _files(folder):
            path = os.path.join(folder, name)
            with open(path, "rb") as f:
                data = f.read()
            with open(path, "wb") as f:
                f.write(sim._xor_bytes(data))
            time.sleep(delay)

    return setup, action


def atk_slow(folder, rng):
    n = rng.randint(15, 25)

    def setup():
        sim.seed_target(folder, n)

    def action():
        sim.run_encrypt_pass(folder, 0.2)

    return setup, action

BENIGN = [ben_edit, ben_bulk_rename, ben_ext_change, ben_copy_many, ben_download, ben_rewrite_many]
ATTACK = [atk_rename, atk_inplace, atk_slow]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", type=int, default=120)
    ap.add_argument("--attack-fraction", type=float, default=0.4)
    ap.add_argument("--parallel", type=int, default=6)
    ap.add_argument("--watch-dir", default=os.path.join(HERE, "..", "watched_capture"))
    ap.add_argument("--out", default=os.path.join(HERE, "..", "data", "windows.csv"))
    ap.add_argument("--seed", type=int, default=11)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    watch = os.path.abspath(args.watch_dir)
    shutil.rmtree(watch, ignore_errors=True)
    os.makedirs(watch)

    plan = []
    for i in range(args.scenarios):
        is_attack = rng.random() < args.attack_fraction
        maker = rng.choice(ATTACK if is_attack else BENIGN)
        name = f"{'atk' if is_attack else 'ben'}_{maker.__name__.split('_', 1)[1]}_{i:03d}"
        plan.append((name, maker, int(is_attack), random.Random(rng.random())))

    collected = []  
    lock = threading.Lock()

    def on_windows(windows):
        now = time.time()
        with lock:
            for w in windows:
                collected.append((now, w))

    monitor = FileMonitor(watch, on_windows=on_windows, window_seconds=WINDOW_SECONDS)
    monitor.start()
    time.sleep(1.0)

    meta = {}  

    def run_one(name, maker, label, srng):
        folder = os.path.join(watch, name)
        setup, action = maker(folder, srng)
        setup()
        time.sleep(SETTLE)
        meta[name] = (label, maker.__name__, time.time())
        action()
        time.sleep(SETTLE)

    t0 = time.time()
    for b in range(0, len(plan), args.parallel):
        batch = plan[b : b + args.parallel]
        threads = [threading.Thread(target=run_one, args=item) for item in batch]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if not monitor._observer.is_alive():
            raise SystemExit("[capture] the file monitor thread died -- aborting "
                             "instead of writing a partial dataset (see traceback above)")
        print(f"[capture] {min(b + args.parallel, len(plan))}/{len(plan)} scenarios done "
              f"({time.time() - t0:.0f}s)", flush=True)

    monitor.stop()

    rows = []
    for emit_time, w in collected:
        if w.actor_id not in meta:
            continue
        label, kind, started = meta[w.actor_id]
        if emit_time < started:
            continue
        rows.append(w.as_vector() + [label, kind, w.actor_id])

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(FEATURE_NAMES + ["label", "kind", "scenario"])
        wr.writerows(rows)

    n1 = sum(1 for r in rows if r[len(FEATURE_NAMES)] == 1)
    print(f"[capture] wrote {len(rows)} windows to {args.out} "
          f"({n1} attack, {len(rows) - n1} normal)")
    shutil.rmtree(watch, ignore_errors=True)

if __name__ == "__main__":
    main()