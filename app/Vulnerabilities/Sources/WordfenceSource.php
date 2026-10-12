<?php

namespace App\Vulnerabilities\Sources;

use App\Enums\ComponentType;
use App\Enums\SeverityLabel;
use App\Enums\VulnerabilitySourceName;
use App\Vulnerabilities\NormalizedVulnerability;
use App\Vulnerabilities\SeverityNormalizer;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use RuntimeException;

/**
 * Wordfence Intelligence v3 production feed: WordPress core/plugin/theme
 * vulnerabilities with CVSS scores. Free, but needs an API key generated
 * from a free Wordfence account (wordfence.com/threat-intel/) and is rate
 * limited to one download every 30 minutes, so vuln:sync must not run more
 * often than that.
 *
 * @see https://www.wordfence.com/help/wordfence-intelligence/v2-accessing-and-consuming-the-vulnerability-data-feed/
 */
class WordfenceSource implements VulnerabilitySource
{
    private const FEED_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';

    private const TYPE_MAP = [
        'core' => ComponentType::Core,
        'plugin' => ComponentType::Plugin,
        'theme' => ComponentType::Theme,
    ];

    public function name(): VulnerabilitySourceName
    {
        return VulnerabilitySourceName::Wordfence;
    }

    public function fetch(): array
    {
        $apiKey = config('services.wordfence.api_key');

        if (! is_string($apiKey) || $apiKey === '') {
            throw new RuntimeException('WORDFENCE_API_KEY is not configured.');
        }

        $response = Http::withHeaders([
            'Authorization' => "Bearer {$apiKey}",
            'Accept' => 'application/json',
        ])->timeout(120)->get(self::FEED_URL);

        $response->throw();

        $entries = $response->json();

        if (! is_array($entries)) {
            throw new RuntimeException('Wordfence feed did not return a JSON object.');
        }

        $vulnerabilities = [];

        foreach ($entries as $entry) {
            if (! is_array($entry) || ! is_array($entry['software'] ?? null)) {
                continue;
            }

            foreach ($entry['software'] as $software) {
                $vulnerability = $this->normalize($entry, $software);

                if ($vulnerability !== null) {
                    $vulnerabilities[] = $vulnerability;
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * @param  array<string, mixed>  $entry
     * @param  array<string, mixed>  $software
     */
    private function normalize(array $entry, array $software): ?NormalizedVulnerability
    {
        $type = self::TYPE_MAP[$software['type'] ?? ''] ?? null;
        $slug = $software['slug'] ?? null;

        if ($type === null || ! is_string($slug) || $slug === '') {
            return null;
        }

        $cve = is_string($entry['cve'] ?? null) ? $entry['cve'] : null;
        [$severity, $score] = $this->severity($entry['cvss'] ?? null);

        $patchedVersions = $software['patched_versions'] ?? null;
        $patchedVersion = is_array($patchedVersions) && is_string($patchedVersions[0] ?? null)
            ? $patchedVersions[0]
            : null;

        $referenceUrl = is_string($entry['cve_link'] ?? null)
            ? $entry['cve_link']
            : ($cve !== null ? "https://www.cve.org/CVERecord?id={$cve}" : null);

        $vulnerabilityId = is_string($entry['id'] ?? null) ? $entry['id'] : '';

        return new NormalizedVulnerability(
            source: $this->name(),
            externalId: $vulnerabilityId !== '' ? "{$vulnerabilityId}:{$slug}" : $slug,
            cveId: $cve,
            title: is_string($entry['title'] ?? null) ? $entry['title'] : 'Untitled vulnerability',
            componentType: $type,
            componentSlug: $slug,
            componentName: is_string($software['name'] ?? null) ? $software['name'] : $slug,
            severityLabel: $severity,
            cvssScore: $score,
            cvssVector: is_string($entry['cvss']['vector'] ?? null) ? $entry['cvss']['vector'] : null,
            patchedVersion: $patchedVersion,
            description: is_string($entry['description'] ?? null) ? $entry['description'] : null,
            referenceUrl: $referenceUrl,
            sourceUrl: $referenceUrl,
            publishedAt: $this->parseDate($entry['published'] ?? null),
        );
    }

    /**
     * Sources disagree on where the score/rating live; the feed has used
     * "score"/"base_score"/"baseScore" and "rating"/"severity" across versions.
     *
     * @return array{0: SeverityLabel, 1: ?float}
     */
    private function severity(mixed $cvss): array
    {
        if (is_numeric($cvss)) {
            return SeverityNormalizer::fromScoreAndRating((float) $cvss, null);
        }

        if (! is_array($cvss)) {
            return SeverityNormalizer::fromScoreAndRating(null, null);
        }

        $score = $cvss['score'] ?? $cvss['base_score'] ?? $cvss['baseScore'] ?? null;
        $rating = $cvss['rating'] ?? $cvss['severity'] ?? null;

        return SeverityNormalizer::fromScoreAndRating($score, is_string($rating) ? $rating : null);
    }

    private function parseDate(mixed $value): ?Carbon
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        try {
            return Carbon::parse($value);
        } catch (\Throwable) {
            return null;
        }
    }
}
