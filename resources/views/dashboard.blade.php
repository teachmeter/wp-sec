<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>{{ config('app.name', 'WP Vuln Triage') }}</title>
    @vite(['resources/css/app.css', 'resources/js/app.ts'])
</head>
<body class="min-h-screen bg-slate-950 text-slate-200 antialiased">
    <header class="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/85 backdrop-blur">
        <div class="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3">
            <div class="flex items-center gap-3">
                <span class="grid size-8 place-items-center rounded-lg bg-red-500/15 text-red-400 ring-1 ring-red-500/30">
                    <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
                </span>
                <div>
                    <h1 class="text-base font-semibold text-white">WP Vulnerability Feed</h1>
                    <p class="text-xs text-slate-500">
                        <span class="inline-block size-1.5 animate-pulse rounded-full bg-emerald-400 align-middle"></span>
                        Live · refreshes every 10 min · <span id="last-updated">—</span>
                    </p>
                </div>
            </div>
            <div class="flex items-center gap-2">
            <button id="watched-btn" type="button" aria-pressed="false" class="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-300 transition hover:border-amber-400/50 hover:text-white aria-pressed:border-amber-400/60 aria-pressed:bg-amber-400/10 aria-pressed:text-amber-200">
                <svg class="size-4 text-amber-400" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2.5l2.9 6.1 6.6.8-4.9 4.6 1.3 6.5L12 17.3l-5.9 3.2 1.3-6.5L2.5 9.4l6.6-.8L12 2.5z"/></svg>
                Watched
                <span id="watched-count" class="rounded-full bg-slate-800 px-1.5 text-xs tabular-nums text-slate-300">0</span>
            </button>
            <button id="mark-seen-btn" type="button" class="relative rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white">
                Mark all seen
                <span id="unread-badge" class="absolute -right-2 -top-2 hidden min-w-5 rounded-full bg-red-500 px-1.5 py-0.5 text-center text-xs font-bold text-white shadow-lg shadow-red-500/30">0</span>
            </button>
            </div>
        </div>
    </header>

    <div id="ticker" class="cursor-pointer overflow-hidden border-b border-slate-800 bg-slate-900/60 py-2 text-sm" title="Click to mark all current high-risk items as seen">
        <div id="ticker-track" class="animate-marquee flex w-max">
            <span class="px-4 text-slate-500">Loading…</span>
        </div>
    </div>

    <main class="mx-auto max-w-7xl space-y-5 px-4 py-6">
        <section class="flex flex-wrap gap-2">
            <button type="button" data-stat-preset="high-risk" class="stat-pill" title="Show high-risk items from the last 7 days">
                <span class="size-2 rounded-full bg-red-500"></span>
                High-risk · 7d
                <span id="stat-high-risk" class="font-semibold text-white tabular-nums">—</span>
            </button>
            <button type="button" data-stat-preset="watched" class="stat-pill" title="Show watched items">
                <span class="size-2 rounded-full bg-amber-400"></span>
                Watched
                <span id="stat-watched" class="font-semibold text-white tabular-nums">—</span>
            </button>
            <button type="button" data-stat-preset="all" class="stat-pill" title="Show everything">
                <span class="size-2 rounded-full bg-slate-500"></span>
                Total
                <span id="stat-total" class="font-semibold text-white tabular-nums">—</span>
            </button>
        </section>

        <section id="filters" class="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
            <div class="flex flex-col gap-2 sm:flex-row sm:items-center">
                <div class="relative flex-1">
                    <svg class="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
                    <input id="filter-q" type="search" placeholder="Search title, plugin, slug or CVE…" autocomplete="off"
                           class="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-12 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/30">
                    <kbd class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded border border-slate-700 px-1.5 text-xs text-slate-500">/</kbd>
                </div>
                <button id="filters-toggle" type="button" aria-expanded="false" aria-controls="filters-panel"
                        class="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-300 transition hover:border-slate-500 hover:text-white">
                    <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M7 12h10M10 18h4"/></svg>
                    Filters
                    <span id="filters-count" class="hidden rounded-full bg-sky-500/20 px-1.5 text-xs font-semibold text-sky-300 tabular-nums">0</span>
                    <svg id="filters-chevron" class="size-4 text-slate-500 transition" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 9l6 6 6-6"/></svg>
                </button>
            </div>

            <div id="filters-panel" class="mt-3 hidden space-y-4 border-t border-slate-800 pt-3">
            <div class="flex flex-wrap items-center gap-2">
                <label class="toggle">
                    <input type="checkbox" id="filter-high-risk" autocomplete="off" class="peer sr-only">
                    <span class="toggle-track"></span>
                    High-risk only
                </label>
                <label class="toggle">
                    <input type="checkbox" id="filter-watched" autocomplete="off" class="peer sr-only">
                    <span class="toggle-track"></span>
                    Watched only
                </label>
                {{-- Hidden for now: TRACKED_PLUGIN_SLUGS isn't set up yet. --}}
                <label class="toggle hidden">
                    <input type="checkbox" id="filter-our-stack" autocomplete="off" class="peer sr-only">
                    <span class="toggle-track"></span>
                    Our stack only
                </label>
            </div>

            <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <div>
                    <div class="filter-label">Severity</div>
                    <div class="flex flex-wrap gap-1.5" data-chip-group="severity">
                        <button type="button" class="chip" data-value="critical"><span class="size-2 rounded-full bg-red-500"></span>Critical</button>
                        <button type="button" class="chip" data-value="high"><span class="size-2 rounded-full bg-orange-500"></span>High</button>
                        <button type="button" class="chip" data-value="medium"><span class="size-2 rounded-full bg-amber-400"></span>Medium</button>
                        <button type="button" class="chip" data-value="low"><span class="size-2 rounded-full bg-sky-400"></span>Low</button>
                        <button type="button" class="chip" data-value="none"><span class="size-2 rounded-full bg-slate-500"></span>Unscored</button>
                    </div>
                </div>
                <div>
                    <div class="filter-label">Published</div>
                    <div class="flex flex-wrap gap-1.5" data-radio-group="range">
                        <button type="button" class="chip" data-value="1">24h</button>
                        <button type="button" class="chip" data-value="7">7 days</button>
                        <button type="button" class="chip" data-value="30">30 days</button>
                        <button type="button" class="chip" data-value="">Any time</button>
                    </div>
                </div>
                <div>
                    <div class="filter-label">Component</div>
                    <div class="flex flex-wrap gap-1.5" data-chip-group="component_type">
                        <button type="button" class="chip" data-value="core">Core</button>
                        <button type="button" class="chip" data-value="plugin">Plugin</button>
                        <button type="button" class="chip" data-value="theme">Theme</button>
                    </div>
                </div>
                <div>
                    <div class="filter-label">Source</div>
                    <div class="flex flex-wrap gap-1.5" data-chip-group="source">
                        <button type="button" class="chip" data-value="nvd">NVD</button>
                        <button type="button" class="chip" data-value="wordfence">Wordfence</button>
                        <button type="button" class="chip" data-value="wpvulnerability">WPVulnerability</button>
                    </div>
                </div>
            </div>

            </div>

            <div class="flex justify-end">
                <button id="clear-filters" type="button" class="hidden rounded-lg px-3 py-1.5 text-sm text-slate-400 transition hover:bg-slate-800 hover:text-white">
                    Clear all filters
                </button>
            </div>
        </section>

        <section class="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
            <div class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-4 py-3">
                <div class="text-sm text-slate-400"><span id="result-count" class="font-semibold text-white">—</span> results</div>
                <div id="active-pills" class="flex flex-wrap gap-1.5"></div>
            </div>

            <div class="overflow-x-auto">
                <table class="w-full min-w-[760px] text-left">
                    <thead class="bg-slate-900 text-xs uppercase tracking-wide text-slate-500">
                        <tr>
                            <th class="w-10 px-2 py-2.5"><span class="sr-only">Watch</span></th>
                            <th class="px-4 py-2.5 font-medium">Severity</th>
                            <th class="px-4 py-2.5 font-medium">Vulnerability</th>
                            <th class="px-4 py-2.5 font-medium">Source</th>
                            <th class="px-4 py-2.5 font-medium">Published</th>
                        </tr>
                    </thead>
                    <tbody id="results-body" class="divide-y divide-slate-800"></tbody>
                </table>
            </div>

            <div id="empty-state" class="hidden px-6 py-14 text-center">
                <div class="text-slate-300">No vulnerabilities match these filters.</div>
                <button type="button" data-action="clear-filters" class="mt-3 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-800">Clear filters</button>
            </div>
            <div id="error-state" class="hidden px-6 py-14 text-center">
                <div class="text-red-300">Couldn't load vulnerabilities.</div>
                <button type="button" data-action="retry" class="mt-3 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-800">Try again</button>
            </div>

            <div class="flex items-center justify-between border-t border-slate-800 px-4 py-3 text-sm text-slate-400">
                <button id="prev-page" type="button" class="pager-btn">← Previous</button>
                <span id="page-info" class="tabular-nums"></span>
                <button id="next-page" type="button" class="pager-btn">Next →</button>
            </div>
        </section>
    </main>

    <div id="toast" class="pointer-events-none fixed bottom-5 left-1/2 z-30 -translate-x-1/2 translate-y-4 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-sm text-slate-100 opacity-0 shadow-xl transition"></div>
</body>
</html>
