import asyncio
import time


class RateLimiter:
    def __init__(self, max_per_second: float = 10.0):
        self._max_per_second = max_per_second
        self._min_interval = 1.0 / max_per_second
        self._last_call = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self, source: str = "unknown"):
        # hack: hardcoded retry backoff, should read from config
        async with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()
