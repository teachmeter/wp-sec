<?php

namespace Tests\Feature;

use App\Enums\ComponentType;
use App\Enums\SeverityLabel;
use App\Vulnerabilities\Sources\NvdSource;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class NvdSourceTest extends TestCase
{
    public function test_it_normalizes_wordpress_plugin_and_theme_cves_of_every_severity(): void
    {
        Http::fake(['services.nvd.nist.gov/*' => Http::response([
            'totalResults' => 4,
            'vulnerabilities' => [
                ['cve' => $this->cve(
                    'CVE-2026-10001',
                    'The Contact Form 7 plugin for WordPress is vulnerable to SQL Injection in all versions up to 5.9. This makes it possible to read the database.',
                    ['https://plugins.trac.wordpress.org/browser/contact-form-7/trunk/includes/form.php'],
                    9.8,
                )],
                ['cve' => $this->cve(
                    'CVE-2026-10002',
                    'The Astra WordPress theme before 4.1 does not escape a setting.',
                    ['https://wpscan.com/vulnerability/abc/'],
                    5.4,
                )],
                ['cve' => $this->cve(
                    'CVE-2026-10004',
                    'Cross-Site Request Forgery (CSRF) vulnerability in Patreon Patreon WordPress patreon-connect allows Cross Site Request Forgery.This issue affects Patreon WordPress: from n/a through 1.9.0.',
                    ['https://patchstack.com/database/wordpress/plugin/patreon-connect/vulnerability/wordpress-patreon-wordpress-plugin-1-9-0-csrf'],
                    8.1,
                )],
                ['cve' => $this->cve(
                    'CVE-2026-10003',
                    'A buffer overflow in some router firmware, unrelated to WordPress.',
                    ['https://example.com/advisory'],
                    9.1,
                )],
            ],
        ])]);

        $vulnerabilities = (new NvdSource)->fetch();

        $this->assertCount(3, $vulnerabilities);

        [$plugin, $theme, $patchstack] = $vulnerabilities;

        $this->assertSame('CVE-2026-10001', $plugin->cveId);
        $this->assertSame(ComponentType::Plugin, $plugin->componentType);
        $this->assertSame('contact-form-7', $plugin->componentSlug);
        $this->assertSame('Contact Form 7', $plugin->componentName);
        $this->assertSame(SeverityLabel::Critical, $plugin->severityLabel);
        $this->assertSame(9.8, $plugin->cvssScore);
        $this->assertSame('The Contact Form 7 plugin for WordPress is vulnerable to SQL Injection in all versions up to 5.9.', $plugin->title);
        $this->assertSame('https://nvd.nist.gov/vuln/detail/CVE-2026-10001', $plugin->sourceUrl);

        $this->assertSame(ComponentType::Theme, $theme->componentType);
        $this->assertNull($theme->componentSlug);
        $this->assertSame('Astra', $theme->componentName);
        $this->assertSame(SeverityLabel::Medium, $theme->severityLabel);

        $this->assertSame('patreon-connect', $patchstack->componentSlug);
        $this->assertSame('Patreon WordPress', $patchstack->componentName);
    }

    /**
     * @param  array<int, string>  $referenceUrls
     * @return array<string, mixed>
     */
    private function cve(string $id, string $description, array $referenceUrls, float $score): array
    {
        return [
            'id' => $id,
            'published' => '2026-10-01T10:00:00.000',
            'descriptions' => [['lang' => 'en', 'value' => $description]],
            'references' => array_map(fn (string $url): array => ['url' => $url], $referenceUrls),
            'metrics' => [
                'cvssMetricV31' => [[
                    'type' => 'Secondary',
                    'cvssData' => ['baseScore' => $score, 'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
                ]],
            ],
        ];
    }
}
