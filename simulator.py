from __future__ import annotations
import argparse
import os
import random
import time

KEYSTREAM_SEED = 1337
LOCKED_EXT = ".locked_demo"

def _xor_bytes(data: bytes):
    rng = random.Random(KEYSTREAM_SEED)
    keystream = bytes(rng.randrange(256) for _ in range(len(data)))
    return bytes(a ^ b for a, b in zip(data, keystream))

def seed_target(target: str, count: int):
    os.makedirs(target, exist_ok=True)
    for i in range(count):
        path = os.path.join(target, f"document_{i:03d}.txt")
        with open(path, "w") as f:
            f.write(f"sample content for file {i}\n" * 20)
    print(f"[simulator] seeded {count} sample files in {target}")


def run_encrypt_pass(target: str, delay: float):
    touched = 0
    for root, _, files in os.walk(target):
        for name in files:
            if name.endswith(LOCKED_EXT):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as f:
                    data = f.read()
                scrambled = _xor_bytes(data)
                with open(path, "wb") as f:
                    f.write(scrambled)
                new_path = path + LOCKED_EXT
                os.rename(path, new_path)
                touched += 1
                if delay:
                    time.sleep(delay)
            except OSError as e:
                print(f"[simulator] skipped {path}: {e}")
    print(f"[simulator] scrambled + renamed {touched} files under {target}")


def revert(target: str):
    restored = 0
    for root, _, files in os.walk(target):
        for name in files:
            if not name.endswith(LOCKED_EXT):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as f:
                    data = f.read()
                original = _xor_bytes(data)  # XOR is self-inverse
                with open(path, "wb") as f:
                    f.write(original)
                orig_path = path[: -len(LOCKED_EXT)]
                os.rename(path, orig_path)
                restored += 1
            except OSError as e:
                print(f"[simulator] skipped {path}: {e}")
    print(f"[simulator] restored {restored} files under {target}")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Directory to operate in (created if missing)")
    parser.add_argument("--count", type=int, default=50, help="Number of sample files to seed")
    parser.add_argument("--delay", type=float, default=0.02, help="Seconds between file ops (0 = as fast as possible)")
    parser.add_argument("--revert", action="store_true", help="Undo a previous run instead of running one")
    parser.add_argument("--no-seed", action="store_true", help="Skip seeding, just run the encrypt pass on what's there")
    args = parser.parse_args()

    abs_target = os.path.abspath(args.target)
    if abs_target in ("/", os.path.expanduser("~")):
        raise SystemExit("Refusing to run against a root or home directory. Use a dedicated test folder.")

    if args.revert:
        revert(abs_target)
        return

    if not args.no_seed:
        seed_target(abs_target, args.count)
    run_encrypt_pass(abs_target, args.delay)

if __name__ == "__main__":
    main()