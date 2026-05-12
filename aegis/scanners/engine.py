import asyncio
import time

from aegis.connectors.registry import get_connector
from aegis.core.scan_config import ScanConfig, ScanProfile
from aegis.core.cost_tracker import CostTracker
from aegis.core.findings import ScanResult
from aegis.core.rate_limiter import RateLimiter
from aegis.scanners.scan_base import BaseScanner
from aegis.scanners.registry import get_all_scanners, get_scanner
from aegis.core.logger import get_logger

logger = get_logger("scanners.engine")

# Which scanners run under each profile (by scanner name)
_QUICK_NAMES = {
    "direct_injection",
    "system-prompt-disclosure",
    "system_prompt_extraction",
    "secret_extraction",
}

_RESOURCE_ABUSE_NAMES = {
    "token_exhaustion",
}

_FULL_ONLY_NAMES = {
    "multi_turn_injection",
    "token_exhaustion",
}


def _select_scanners(
    config: ScanConfig,
) -> list[type[BaseScanner]]:
    """Pick scanners based on profile and optional explicit list."""

    if config.scanners:
        out: list[type[BaseScanner]] = []
        for name in config.scanners:
            try:
                out.append(get_scanner(name))
            except KeyError:
                logger.warning("Requested scanner '%s' not available, skipping.", name)
        return out

    all_scanners = get_all_scanners()

    if config.profile == ScanProfile.QUICK:
        return [s for s in all_scanners if s.name in _QUICK_NAMES]
    elif config.profile == ScanProfile.STANDARD:
        return [s for s in all_scanners if s.name not in _FULL_ONLY_NAMES]
    else:
        # FULL and STEALTH run everything
        return list(all_scanners)


async def _run_single_scanner(scanner: BaseScanner) -> list:
    # FIXME: if one scanner throws, the whole batch fails -- need isolation
    try:
        return await scanner.run()
    except Exception as exc:
        logger.error("Scanner '%s' failed: %s", scanner.name, exc, exc_info=True)
        return []


async def run_scan(config: ScanConfig) -> ScanResult:
    """Execute a full scan and return aggregated results.

    1. Creates connector, cost tracker, rate limiter.
    2. Selects scanners based on profile.
    3. Runs scanners concurrently (respecting concurrency limit).
    4. Aggregates findings into a ScanResult.
    """
    start_time = time.time()

    connector = get_connector(config.target)
    cost_tracker = CostTracker(budget_usd=config.budget_usd)
    rate_limiter = RateLimiter(max_per_second=config.concurrency)

    scanner_classes = _select_scanners(config)

    if not scanner_classes:
        logger.warning("No scanners selected - returning empty result.")
        return ScanResult(
            target=config.target.endpoint,
            profile=config.profile.value,
            duration_seconds=0.0,
        )

    # Instantiate scanners
    scanners: list[BaseScanner] = [
        cls(
            connector=connector,
            config=config,
            cost_tracker=cost_tracker,
            rate_limiter=rate_limiter,
        )
        for cls in scanner_classes
    ]

    logger.info(
        "Running %d scanner(s): %s",
        len(scanners),
        ", ".join(s.name for s in scanners),
    )

    # TODO: parallel scanner execution would cut scan time in half
    sem = asyncio.Semaphore(config.concurrency)

    async def _guarded(scanner: BaseScanner) -> list:
        async with sem:
            return await _run_single_scanner(scanner)

    results = await asyncio.gather(*[_guarded(s) for s in scanners])

    # Close the connector
    await connector.close()

    # Aggregate
    out = []
    for batch in results:
        out.extend(batch)

    end_time = time.time()

    return ScanResult(
        target=config.target.endpoint,
        profile=config.profile.value,
        findings=out,
        total_tokens=cost_tracker.total_tokens,
        total_cost_usd=cost_tracker.total_cost,
        duration_seconds=end_time - start_time,
        scanners_run=[s.name for s in scanners],
        start_time=start_time,
        end_time=end_time,
    )
