<?php

namespace App\Vulnerabilities\Sources;

use App\Enums\ComponentType;
use App\Enums\SeverityLabel;
use App\Enums\VulnerabilitySourceName;
use App\Vulnerabilities\NormalizedVulnerability;
use App\Vulnerabilities\SeverityNormalizer;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * NIST's National Vulnerability Database, searched for every WordPress
 * plugin/theme CVE published in the last LOOKBACK_DAYS. Free and keyless, so
 * it is the broad, news-feed style baseline that keeps the dashboard populated
 * even without a Wordfence key or tracked plugin slugs.
 *
 * Keyless access is limited to 5 requests per 30 seconds, which a single
 * vuln:sync run stays well under.
 *
 * @see https://nvd.nist.gov/developers/vulnerabilities
 */
class NvdSource implements VulnerabilitySource
{
    private const ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

    private const LOOKBACK_DAYS = 30;

    private const PAGE_SIZE = 2000;

    private const MAX_PAGES = 5;

    private const METRIC_KEYS = ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30'];

    /**
     * Reference URLs that name the affected WordPress.org slug, mapped to the
     * capture group holding the component type ("plugin"/"theme") and the slug.
     */
    private const SLUG_PATTERNS = [
        '~patchstack\.com/database/(?:wordpress/)?(?:vulnerability/)?(plugin|theme)s?/([a-z0-9-]+)~i',
        '~wordfence\.com/threat-intel/vulnerabilities/wordpress-(plugin|theme)s/([a-z0-9-]+)~i',
        '~(plugin|theme)s\.trac\.wordpress\.org/(?:browser|changeset/\d+)/([a-z0-9-]+)~i',
        '~wordpress\.org/(plugin|theme)s/([a-z0-9-]+)~i',
    ];

    public function name(): VulnerabilitySourceName
    {
        return VulnerabilitySourceName::Nvd;
    }

    public function fetch(): array
    {
        $vulnerabilities = [];

        foreach ($this->fetchCves() as $cve) {
            $vulnerability = $this->normalize($cve);

            if ($vulnerability !== null) {
                $vulnerabilities[] = $vulnerability;
            }
        }

        return $vulnerabilities;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function fetchCves(): array
    {
        $end = Date::now()->utc();
        $start = $end->copy()->subDays(self::LOOKBACK_DAYS);
        $cves = [];

        for ($page = 0; $page < self::MAX_PAGES; $page++) {
            $response = Http::timeout(90)->get(self::ENDPOINT, [
                'keywordSearch' => 'WordPress',
                'pubStartDate' => $start->format('Y-m-d\TH:i:s.v\Z'),
                'pubEndDate' => $end->format('Y-m-d\TH:i:s.v\Z'),
                'noRejected' => '',
                'resultsPerPage' => self::PAGE_SIZE,
                'startIndex' => $page * self::PAGE_SIZE,
            ]);

            $response->throw();

            $items = $response->json('vulnerabilities');

            if (! is_array($items)) {
                throw new RuntimeException('NVD response did not contain a vulnerabilities list.');
            }

            foreach ($items as $item) {
                if (is_array($item) && is_array($item['cve'] ?? null)) {
                    $cves[] = $item['cve'];
                }
            }

            if (count($cves) >= (int) $response->json('totalResults', 0)) {
                break;
            }
        }

        return $cves;
    }

    /**
     * @param  array<string, mixed>  $cve
     */
    private function normalize(array $cve): ?NormalizedVulnerability
    {
        $cveId = $cve['id'] ?? null;

        if (! is_string($cveId) || $cveId === '') {
            return null;
        }

        $description = $this->englishDescription($cve);
        $referenceUrls = $this->referenceUrls($cve);
        $component = $this->component($description, $referenceUrls);

        if ($component === null) {
            return null;
        }

        [$severity, $score, $vector] = $this->severity($cve['metrics'] ?? null);
        $nvdUrl = "https://nvd.nist.gov/vuln/detail/{$cveId}";

        return new NormalizedVulnerability(
            source: $this->name(),
            externalId: $cveId,
            cveId: $cveId,
            title: $this->title($description, $cveId),
            componentType: $component['type'],
            componentSlug: $component['slug'],
            componentName: $component['name'] ?? $component['slug'],
            severityLabel: $severity,
            cvssScore: $score,
            cvssVector: $vector,
            patchedVersion: null,
            description: $description,
            referenceUrl: $referenceUrls[0] ?? $nvdUrl,
            sourceUrl: $nvdUrl,
            publishedAt: $this->parseDate($cve['published'] ?? null),
        );
    }

    /**
     * Work out which WordPress plugin/theme a CVE affects. The slug comes from
     * reference URLs when one points at WordPress.org or a WordPress-specific
     * advisory; the display name comes from the description wording the main
     * WordPress CNAs use. CVEs matching neither are not WordPress components
     * (the keyword search also hits anything that merely mentions WordPress),
     * so they are dropped.
     *
     * @param  array<int, string>  $referenceUrls
     * @return array{type: ComponentType, slug: ?string, name: ?string}|null
     */
    private function component(?string $description, array $referenceUrls): ?array
    {
        $type = null;
        $slug = null;
        $name = null;

        foreach ($referenceUrls as $url) {
            foreach (self::SLUG_PATTERNS as $pattern) {
                if (preg_match($pattern, $url, $matches) === 1) {
                    $type = strtolower($matches[1]) === 'theme' ? ComponentType::Theme : ComponentType::Plugin;
                    $slug = strtolower($matches[2]);

                    break 2;
                }
            }
        }

        $namePattern = '~^(?:The\s+)?(.+?)\s+(?:(plugin|theme)\s+for\s+WordPress|WordPress\s+(plugin|theme))\b~i';

        if ($description !== null && preg_match($namePattern, $description, $matches) === 1) {
            $name = trim($matches[1]);
            $type ??= strtolower($matches[2] ?: $matches[3]) === 'theme' ? ComponentType::Theme : ComponentType::Plugin;
        }

        // Patchstack's wording: "... This issue affects Plugin Name: from n/a through 1.2.3."
        if ($name === null && $description !== null && preg_match('~This issue affects\s+(.+?):\s*from\b~i', $description, $matches) === 1) {
            $name = trim($matches[1]);
        }

        if ($type === null) {
            return null;
        }

        return ['type' => $type, 'slug' => $slug, 'name' => $name];
    }

    /**
     * Prefers CVSS v3.1, then v4.0, then v3.0, and within a version the NVD's
     * own "Primary" score over the reporting CNA's "Secondary" one.
     *
     * @return array{0: SeverityLabel, 1: ?float, 2: ?string}
     */
    private function severity(mixed $metrics): array
    {
        if (! is_array($metrics)) {
            return [SeverityLabel::None, null, null];
        }

        foreach (self::METRIC_KEYS as $key) {
            $entries = is_array($metrics[$key] ?? null) ? $metrics[$key] : [];

            usort($entries, static fn (mixed $entry): int => is_array($entry) && ($entry['type'] ?? null) === 'Primary' ? -1 : 1);

            foreach ($entries as $entry) {
                $data = is_array($entry) && is_array($entry['cvssData'] ?? null) ? $entry['cvssData'] : null;

                if ($data === null) {
                    continue;
                }

                [$severity, $score] = SeverityNormalizer::fromScoreAndRating(
                    $data['baseScore'] ?? null,
                    is_string($data['baseSeverity'] ?? null) ? $data['baseSeverity'] : null,
                );

                return [$severity, $score, is_string($data['vectorString'] ?? null) ? $data['vectorString'] : null];
            }
        }

        return [SeverityLabel::None, null, null];
    }

    /**
     * @param  array<string, mixed>  $cve
     */
    private function englishDescription(array $cve): ?string
    {
        foreach (is_array($cve['descriptions'] ?? null) ? $cve['descriptions'] : [] as $description) {
            if (is_array($description) && ($description['lang'] ?? null) === 'en' && is_string($description['value'] ?? null)) {
                return trim($description['value']);
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $cve
     * @return array<int, string>
     */
    private function referenceUrls(array $cve): array
    {
        $urls = [];

        foreach (is_array($cve['references'] ?? null) ? $cve['references'] : [] as $reference) {
            if (is_array($reference) && is_string($reference['url'] ?? null)) {
                $urls[] = $reference['url'];
            }
        }

        return $urls;
    }

    /**
     * NVD records have no title, so the description's first sentence stands in.
     */
    private function title(?string $description, string $cveId): string
    {
        if ($description === null || $description === '') {
            return $cveId;
        }

        $firstSentence = preg_split('/(?<=\.)\s+/', $description, 2)[0] ?? $description;

        return Str::limit($firstSentence, 160);
    }

    private function parseDate(mixed $value): ?Carbon
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        try {
            return Carbon::parse($value, 'UTC');
        } catch (\Throwable) {
            return null;
        }
    }
}
