# WP Vulnerability Triage Newshub

Self-hosted dashboard that polls WordPress vulnerability feeds, flags high-risk CVEs (CVSS ≥ 7, or known exploited in the wild per CISA KEV), and surfaces them via a news ticker + filterable table so you can triage them as they land.

## Stack

- Laravel 13 (PHP 8.3), SQLite
- Vite + TypeScript + Tailwind v4 for the frontend (no SPA framework)
- No user accounts — single shared dashboard, in-app only (no email yet)

## Requirements

- PHP 8.3+, Composer
- Node 20+, npm
- A free [Wordfence Intelligence](https://www.wordfence.com/threat-intel/) account (for the API key below)

## Setup

```bash
composer install
npm install

cp .env.example .env
php artisan key:generate

touch database/database.sqlite
php artisan migrate
```

Then edit `.env` and set:

| Variable | What it's for |
|---|---|
| `WORDFENCE_API_KEY` | Free key from wordfence.com/threat-intel → Integrations page. Required for the Wordfence source — without it, that source just logs a failed sync and the rest of the app still works. |
| `TRACKED_PLUGIN_SLUGS` | Comma-separated WordPress.org plugin slugs your company actually runs, e.g. `contact-form-7,yoast-seo,woocommerce`. Drives the WPVulnerability lookups and the "affects our stack" flag/filter. |

## Running locally

```bash
composer run dev
```

This runs the PHP dev server, queue listener, log viewer, and Vite dev server together. Visit `http://127.0.0.1:8000`.

Pull in vulnerability data manually with:

```bash
php artisan vuln:sync
```

In production this is scheduled automatically (see `routes/console.php`) — every 30 minutes, matching Wordfence's rate limit.

## Testing

```bash
php artisan test
npm run typecheck
```

## How it works

- `App\Vulnerabilities\Sources\*` — one class per feed (Wordfence Intelligence, WPVulnerability.com), each implementing `VulnerabilitySource::fetch()` and returning normalized records.
- `App\Vulnerabilities\CisaKevEnricher` — cross-references stored CVEs against CISA's Known Exploited Vulnerabilities catalog and flags matches as high-priority regardless of CVSS score.
- `App\Vulnerabilities\VulnerabilitySyncer` — orchestrates all sources, dedupes by CVE id (or source id, or a title hash as last resort), and logs each run to `source_syncs` so a dead feed is visible instead of silently missing data.
- `vuln:sync` artisan command — runs the syncer; wired into the scheduler in `routes/console.php`.
- `GET /api/vulnerabilities` — filterable list (`severity`, `source`, `component_type`, `status`, `q`, `affects_our_stack`, `high_risk_only`, `from`/`to`, `per_page`).
- `GET /api/vulnerabilities/ticker` — latest high-risk items for the dashboard ticker.
- `PATCH /api/vulnerabilities/{id}` — update an item's triage `status` (new/reviewing/patched/not_applicable/ignored).

## Deploying

Built to deploy via [Laravel Forge](https://forge.laravel.com/) onto a DigitalOcean droplet:

1. Create the site in Forge, point it at this repo, deploy as usual (Forge handles nginx, PHP, SSL, and the scheduler cron automatically).
2. Set `WORDFENCE_API_KEY` and `TRACKED_PLUGIN_SLUGS` as environment variables on the Forge site (or in its `.env`).
3. Run the deploy script's `php artisan migrate --force` (Forge's default deploy script already does this).
4. Confirm the scheduler is running: check the `source_syncs` table after ~30 minutes for fresh rows.

SQLite is the default DB — it's a single file (`database/database.sqlite`), so back it up like any other file (Forge's backup tooling, or a simple cron `cp`).
