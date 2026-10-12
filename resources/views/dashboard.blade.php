<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ config('app.name', 'WP Vuln Triage') }}</title>
    @vite(['resources/css/app.css', 'resources/js/app.ts'])
</head>
<body class="min-h-screen bg-slate-50 text-slate-900">
    <header class="border-b bg-white">
        <div class="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
            <h1 class="text-lg font-semibold">WP Vulnerability Triage</h1>
            <button id="mark-seen-btn" type="button" class="relative rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100">
                Mark seen
                <span id="unread-badge" class="absolute -right-2 -top-2 hidden min-w-[1.25rem] rounded-full bg-red-600 px-1.5 py-0.5 text-center text-xs font-bold text-white">0</span>
            </button>
        </div>
    </header>

    <div id="ticker" class="cursor-pointer overflow-hidden border-b bg-slate-900 py-2 text-white" title="Click to mark all current high-risk items as seen">
        <div id="ticker-track" class="animate-marquee flex w-max">
            <span class="px-4 text-slate-400">Loading…</span>
        </div>
    </div>

    <main class="mx-auto max-w-6xl space-y-6 px-4 py-6">
        <section class="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div class="rounded border bg-white p-4">
                <div class="text-sm text-slate-500">High-risk, untriaged</div>
                <div id="stat-high-risk" class="text-2xl font-bold">—</div>
            </div>
            <div class="rounded border bg-white p-4">
                <div class="text-sm text-slate-500">Affects your stack, untriaged</div>
                <div id="stat-affects-stack" class="text-2xl font-bold">—</div>
            </div>
            <div class="rounded border bg-white p-4">
                <div class="text-sm text-slate-500">Total tracked</div>
                <div id="stat-total" class="text-2xl font-bold">—</div>
            </div>
        </section>

        <form id="filter-form" class="flex flex-wrap items-end gap-3 rounded border bg-white p-4">
            <div>
                <label class="block text-xs font-medium text-slate-500" for="filter-q">Search</label>
                <input id="filter-q" name="q" type="text" placeholder="title, plugin, CVE…" class="mt-1 rounded border-slate-300 text-sm">
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-500" for="filter-severity">Severity</label>
                <select id="filter-severity" name="severity" multiple size="5" class="mt-1 rounded border-slate-300 text-sm">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="none">None</option>
                </select>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-500" for="filter-source">Source</label>
                <select id="filter-source" name="source" multiple size="2" class="mt-1 rounded border-slate-300 text-sm">
                    <option value="wordfence">Wordfence</option>
                    <option value="wpvulnerability">WPVulnerability</option>
                </select>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-500" for="filter-component-type">Component</label>
                <select id="filter-component-type" name="component_type" multiple size="3" class="mt-1 rounded border-slate-300 text-sm">
                    <option value="core">Core</option>
                    <option value="plugin">Plugin</option>
                    <option value="theme">Theme</option>
                </select>
            </div>
            <div>
                <label class="block text-xs font-medium text-slate-500" for="filter-status">Status</label>
                <select id="filter-status" name="status" class="mt-1 rounded border-slate-300 text-sm">
                    <option value="">All</option>
                    <option value="new">New</option>
                    <option value="reviewing">Reviewing</option>
                    <option value="patched">Patched</option>
                    <option value="not_applicable">Not applicable</option>
                    <option value="ignored">Ignored</option>
                </select>
            </div>
            <label class="flex items-center gap-2 text-sm">
                <input type="checkbox" name="affects_our_stack" value="1">
                Affects our stack only
            </label>
            <label class="flex items-center gap-2 text-sm">
                <input type="checkbox" name="high_risk_only" value="1">
                High-risk only
            </label>
            <button type="submit" class="rounded bg-slate-900 px-3 py-1.5 text-sm text-white hover:bg-slate-700">Apply</button>
        </form>

        <section class="rounded border bg-white">
            <table class="w-full text-left">
                <thead class="border-b bg-slate-50 text-sm text-slate-500">
                    <tr>
                        <th class="px-3 py-2">Severity</th>
                        <th class="px-3 py-2">Vulnerability</th>
                        <th class="px-3 py-2">Type</th>
                        <th class="px-3 py-2">Source</th>
                        <th class="px-3 py-2">Published</th>
                        <th class="px-3 py-2">Status</th>
                    </tr>
                </thead>
                <tbody id="results-body"></tbody>
            </table>
            <div id="empty-state" class="hidden p-6 text-center text-slate-400">No vulnerabilities match these filters.</div>
            <div class="flex items-center justify-between border-t px-3 py-2 text-sm text-slate-500">
                <button id="prev-page" type="button" class="rounded border px-2 py-1 disabled:opacity-40">Previous</button>
                <span id="page-info"></span>
                <button id="next-page" type="button" class="rounded border px-2 py-1 disabled:opacity-40">Next</button>
            </div>
        </section>
    </main>
</body>
</html>
