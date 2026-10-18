from __future__ import annotations
import os
import threading
import time
from typing import Callable, Dict, Optional
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from feature_extraction import FileEvent, WindowAggregator, shannon_entropy

def _safe_read_head(path: str, max_bytes: int = 65536):
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except OSError:
        return b""


def _actor_id_for(path: str):
    parts = path.replace("\\", "/").split("/")
    return parts[-2] if len(parts) >= 2 else "unknown"


class _Handler(FileSystemEventHandler):
    def __init__(self, aggregator: WindowAggregator, entropy_cache: Dict[str, float]):
        self.aggregator = aggregator
        self.entropy_cache = entropy_cache

    def _push(self, path: str, event_type: str, ext_before: str = "", ext_after: str = ""):
        entropy_before = self.entropy_cache.get(path)
        entropy_after = None
        size_bytes = 0

        if event_type in ("modified", "created") and os.path.isfile(path):
            data = _safe_read_head(path)
            entropy_after = shannon_entropy(data)
            size_bytes = os.path.getsize(path) if os.path.exists(path) else 0
            self.entropy_cache[path] = entropy_after

        self.aggregator.push(
            FileEvent(
                actor_id=_actor_id_for(path),
                path=path,
                event_type=event_type,
                entropy_before=entropy_before,
                entropy_after=entropy_after,
                size_bytes=size_bytes,
                ext_before=ext_before,
                ext_after=ext_after,
            )
        )

    def on_created(self, event):
        if not event.is_directory:
            self._push(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self._push(event.src_path, "modified")

    def on_deleted(self, event):
        if not event.is_directory:
            self._push(event.src_path, "deleted")
            self.entropy_cache.pop(event.src_path, None)

    def on_moved(self, event):
        if not event.is_directory:
            ext_before = os.path.splitext(event.src_path)[1]
            ext_after = os.path.splitext(event.dest_path)[1]
            self._push(event.dest_path, "moved", ext_before=ext_before, ext_after=ext_after)


class FileMonitor:
    def __init__(
        self,
        watch_dir: str,
        on_windows: Callable[[list], None],
        window_seconds: float = 3.0,
        flush_interval: float = 1.0,
    ):
        self.watch_dir = watch_dir
        self.on_windows = on_windows
        self.flush_interval = flush_interval
        self.aggregator = WindowAggregator(window_seconds=window_seconds)
        self._entropy_cache: Dict[str, float] = {}
        self._observer: None
        self._stop = threading.Event()
        self._flush_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = _Handler(self.aggregator, self._entropy_cache)
        self._observer = Observer()
        self._observer.schedule(handler, self.watch_dir, recursive=True)
        self._observer.start()

        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()
        print(f"[file_monitor] watching {self.watch_dir}")

    def _flush_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.flush_interval)
            windows = self.aggregator.flush_ready()
            if windows:
                self.on_windows(windows)

    def stop(self) -> None:
        self._stop.set()
        if self._observer:
            self._observer.stop()
            self._observer.join()


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "./watched"
    os.makedirs(target, exist_ok=True)

    def _print_windows(windows):
        for w in windows:
            print(
                f"[window] actor={w.actor_id} files={w.files_touched} "
                f"writes={w.writes} renames={w.renames} "
                f"mean_entropy_delta={w.mean_entropy_delta:.2f} "
                f"eps={w.events_per_second:.1f}"
            )

    monitor = FileMonitor(target, _print_windows)
    monitor.start()
    print("Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()