<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Wordfence's free feed is rate limited to one download every 30 minutes,
// so this must not run more often than that.
Schedule::command('vuln:sync')->everyThirtyMinutes()->withoutOverlapping();
