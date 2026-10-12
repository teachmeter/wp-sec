<?php

namespace App\Vulnerabilities\Sources;

/**
 * A source whose upstream only allows one download per interval. The syncer
 * skips it (without logging a sync) until that interval has passed since its
 * last attempt, so vuln:sync can run more often than the slowest source allows.
 */
interface RateLimitedSource extends VulnerabilitySource
{
    public function minimumIntervalMinutes(): int;
}
