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
