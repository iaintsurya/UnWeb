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


class RedisSlidingWindowLimiter:
    """Atomic sliding-window limiter shared by all API workers through Redis."""

    _SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local maximum = tonumber(ARGV[3])
    local member = ARGV[4]
    redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
    local count = redis.call('ZCARD', key)
    if count >= maximum then
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        if oldest[2] then
            return math.max(1, tonumber(oldest[2]) + window - now)
        end
        return window
    end
    redis.call('ZADD', key, now, member)
    redis.call('PEXPIRE', key, window)
    return 0
    """

    def __init__(self, client, max_requests: int, window_seconds: float, namespace: str):
        if max_requests < 1 or window_seconds <= 0:
            raise ValueError("Rate limit settings must be positive.")
        self.client = client
        self.max_requests = max_requests
        self.window_ms = int(window_seconds * 1000)
        self.namespace = namespace

    def check(self, key: str) -> float:
        import hashlib
        import uuid

        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        redis_key = f"unweb:ratelimit:{self.namespace}:{digest}"
        retry_ms = self.client.eval(
            self._SCRIPT,
            1,
            redis_key,
            int(time.time() * 1000),
            self.window_ms,
            self.max_requests,
            uuid.uuid4().hex,
        )
        return max(0.0, float(retry_ms) / 1000.0)
