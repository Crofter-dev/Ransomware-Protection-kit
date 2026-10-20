from __future__ import annotations
import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

def shannon_entropy(data: bytes):
    if not data:
        return 0.0
    counts: Dict[int, int] = defaultdict(int)
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return entropy

@dataclass
class FileEvent:
    actor_id: str          
    event_type: str        
    timestamp: float = field(default_factory=time.time)
    entropy_before: Optional[float] = None
    entropy_after: Optional[float] = None
    size_bytes: int = 0
    ext_before: str = ""
    ext_after: str = ""

@dataclass
class WindowFeatures:
    actor_id: str
    window_start: float
    window_seconds: float
    files_touched: int
    writes: int
    renames: int
    deletes: int
    creates: int
    mean_entropy_delta: float
    max_entropy_delta: float
    ext_change_rate: float          
    unique_dirs_touched: int
    events_per_second: float
    high_entropy_write_rate: float  

    def as_vector(self):
        return [
            self.files_touched,
            self.writes,
            self.renames,
            self.deletes,
            self.creates,
            self.mean_entropy_delta,
            self.max_entropy_delta,
            self.ext_change_rate,
            self.unique_dirs_touched,
            self.events_per_second,
            self.high_entropy_write_rate,
        ]

FEATURE_NAMES = [
    "files_touched",
    "writes",
    "renames",
    "deletes",
    "creates",
    "mean_entropy_delta",
    "max_entropy_delta",
    "ext_change_rate",
    "unique_dirs_touched",
    "events_per_second",
    "high_entropy_write_rate",
]


class WindowAggregator:

    def __init__(self, window_seconds: float = 3.0, max_buffer: int = 5000):
        self.window_seconds = window_seconds
        self._buffers: Dict[str, Deque[FileEvent]] = defaultdict(
            lambda: deque(maxlen=max_buffer)
        )
        self._window_start: Dict[str, float] = {}
        self._lock = threading.Lock()

    def push(self, event: FileEvent) -> None:
        with self._lock:
            buf = self._buffers[event.actor_id]
            if event.actor_id not in self._window_start:
                self._window_start[event.actor_id] = event.timestamp
            buf.append(event)

    def flush_ready(self, now: Optional[float] = None) -> List[WindowFeatures]:
        with self._lock:
            return self._flush_locked(now)

    def _flush_locked(self, now: Optional[float]) -> List[WindowFeatures]:
        now = now if now is not None else time.time()
        ready: List[WindowFeatures] = []
        for actor_id, start in list(self._window_start.items()):
            if now - start < self.window_seconds:
                continue
            events = list(self._buffers[actor_id])
            if events:
                ready.append(self._summarize(actor_id, start, now, events))
            self._buffers[actor_id].clear()
            del self._window_start[actor_id]
        return ready

    @staticmethod
    def _summarize(
        actor_id: str, start: float, end: float, events: List[FileEvent]
    ) -> WindowFeatures:
        writes = [e for e in events if e.event_type == "modified"]
        renames = [e for e in events if e.event_type == "moved"]
        deletes = [e for e in events if e.event_type == "deleted"]
        creates = [e for e in events if e.event_type == "created"]

        deltas = [
            (e.entropy_after - e.entropy_before)
            for e in writes
            if e.entropy_before is not None and e.entropy_after is not None
        ]
        mean_delta = sum(deltas) / len(deltas) if deltas else 0.0
        max_delta = max(deltas) if deltas else 0.0

        ext_changes = sum(1 for e in renames if e.ext_before and e.ext_before != e.ext_after)
        ext_change_rate = ext_changes / len(renames) if renames else 0.0

        high_entropy_writes = sum(
            1 for e in writes if e.entropy_after is not None and e.entropy_after >= 7.5
        )
        high_entropy_rate = high_entropy_writes / len(writes) if writes else 0.0

        start = events[0].timestamp
        duration = max(events[-1].timestamp - start, 1.0)
        unique_dirs = len({e.path.rsplit("/", 1)[0] for e in events})

        return WindowFeatures(
            actor_id=actor_id,
            window_start=start,
            window_seconds=duration,
            files_touched=len({e.path for e in events}),
            writes=len(writes),
            renames=len(renames),
            deletes=len(deletes),
            creates=len(creates),
            mean_entropy_delta=mean_delta,
            max_entropy_delta=max_delta,
            ext_change_rate=ext_change_rate,
            unique_dirs_touched=unique_dirs,
            events_per_second=len(events) / duration,
            high_entropy_write_rate=high_entropy_rate,
        )
