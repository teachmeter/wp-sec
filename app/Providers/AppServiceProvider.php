<?php

namespace App\Providers;

use App\Vulnerabilities\CisaKevEnricher;
use App\Vulnerabilities\Sources\NvdSource;
use App\Vulnerabilities\Sources\VulnerabilitySource;
use App\Vulnerabilities\Sources\WordfenceSource;
use App\Vulnerabilities\Sources\WpVulnerabilitySource;
use App\Vulnerabilities\VulnerabilitySyncer;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // NVD runs first so the richer Wordfence/WPVulnerability records overwrite its shared CVEs.
        $this->app->tag([NvdSource::class, WordfenceSource::class, WpVulnerabilitySource::class], VulnerabilitySource::class);

        $this->app->bind(VulnerabilitySyncer::class, function ($app): VulnerabilitySyncer {
            return new VulnerabilitySyncer(
                $app->tagged(VulnerabilitySource::class),
                $app->make(CisaKevEnricher::class),
            );
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
