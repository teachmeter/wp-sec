<?php

namespace App\Providers;

use App\Vulnerabilities\CisaKevEnricher;
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
        $this->app->tag([WordfenceSource::class, WpVulnerabilitySource::class], VulnerabilitySource::class);

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
