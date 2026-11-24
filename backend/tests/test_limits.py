from app.limits import SlidingWindowLimiter


def test_sliding_window_limiter_allows_then_blocks():
    now = [100.0]
    limiter = SlidingWindowLimiter(2, 60, clock=lambda: now[0])

    assert limiter.check("client-a") == 0
    assert limiter.check("client-a") == 0
    assert limiter.check("client-a") > 0

    now[0] = 161.0
    assert limiter.check("client-a") == 0


def test_sliding_window_limits_are_independent_per_key():
    limiter = SlidingWindowLimiter(1, 60, clock=lambda: 100.0)
    assert limiter.check("client-a") == 0
    assert limiter.check("client-b") == 0
    assert limiter.check("client-a") > 0


def test_limiter_bounds_number_of_client_buckets():
    limiter = SlidingWindowLimiter(1, 60, max_keys=2, clock=lambda: 100.0)
    limiter.check("one")
    limiter.check("two")
    limiter.check("three")

    assert len(limiter._buckets) == 2
    assert "one" not in limiter._buckets


class FakeRedis:
    def __init__(self, retry_ms=0):
        self.retry_ms = retry_ms
        self.calls = []

    def eval(self, script, key_count, key, window, maximum, member):
        self.calls.append((script, key_count, key, window, maximum, member))
        return self.retry_ms


def test_redis_limiter_uses_atomic_script_and_returns_retry_seconds():
    from app.limits import RedisSlidingWindowLimiter

    client = FakeRedis(retry_ms=2750)
    limiter = RedisSlidingWindowLimiter(client, 10, 60, "website-scan")

    assert limiter.check("user-123") == 2.75
    assert len(client.calls) == 1
    script, key_count, key, window, maximum, member = client.calls[0]
    assert "TIME" in script
    assert "ZREMRANGEBYSCORE" in script
    assert "ZADD" in script
    assert key_count == 1
    assert key.startswith("unweb:ratelimit:website-scan:")
    assert "user-123" not in key
    assert window == 60000
    assert maximum == 10
    assert member


def test_redis_limiter_allows_when_redis_reports_zero_delay():
    from app.limits import RedisSlidingWindowLimiter

    assert RedisSlidingWindowLimiter(FakeRedis(), 2, 60, "test").check("alice") == 0
