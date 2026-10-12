<?php

namespace App\Vulnerabilities;

use App\Models\Vulnerability;
use Illuminate\Support\Facades\Http;

/**
 * Cross-references CVE ids already stored against CISA's Known Exploited
 * Vulnerabilities catalog, so a vulnerability known to be exploited in the
 * wild is forced to high priority regardless of its CVSS score.
 *
 * @see https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 */
class CisaKevEnricher
{
    private const FEED_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    public function run(): int
    {
        $cveIds = $this->fetchKevCveIds();

        if ($cveIds === []) {
            return 0;
        }

        return Vulnerability::query()
            ->whereIn('cve_id', $cveIds)
            ->where('is_kev_exploited', false)
            ->update(['is_kev_exploited' => true]);
    }

    /**
     * @return array<int, string>
     */
    private function fetchKevCveIds(): array
    {
        $response = Http::timeout(30)->get(self::FEED_URL);
        $response->throw();

        $vulnerabilities = $response->json('vulnerabilities');

        if (! is_array($vulnerabilities)) {
            return [];
        }

        return array_values(array_filter(array_map(
            static fn (mixed $entry): ?string => is_array($entry) && is_string($entry['cveID'] ?? null)
                ? $entry['cveID']
                : null,
            $vulnerabilities,
        )));
    }
}
