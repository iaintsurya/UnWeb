"""Small per-process sliding-window limiter for preview scan requests."""
from collections import OrderedDict, deque
from collections.abc import Callable
import time


class SlidingWindowLimiter:
    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        max_keys: int = 2048,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_requests < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("Rate limit settings must be positive.")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.clock = clock
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()

    def check(self, key: str) -> float:
        """Return 0 when allowed, otherwise seconds until the oldest hit expires."""
        now = self.clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = deque()
            self._buckets[key] = bucket
        self._buckets.move_to_end(key)

        cutoff = now - self.window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= self.max_requests:
            return max(0.1, bucket[0] + self.window_seconds - now)

        bucket.append(now)
        while len(self._buckets) > self.max_keys:
            self._buckets.popitem(last=False)
        return 0.0
