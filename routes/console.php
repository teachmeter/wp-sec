<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Wordfence's free feed is rate limited to one download every 30 minutes;
// the syncer skips it on runs in between, while the other sources sync every time.
Schedule::command('vuln:sync')->everyFifteenMinutes()->withoutOverlapping();
