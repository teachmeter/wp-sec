type SeverityLabel = 'none' | 'low' | 'medium' | 'high' | 'critical';
type ComponentType = 'core' | 'plugin' | 'theme';
type SourceName = 'wordfence' | 'wpvulnerability' | 'cisa_kev' | 'nvd';

interface Vulnerability {
    id: number;
    source: SourceName;
    cve_id: string | null;
    title: string;
    component_type: ComponentType;
    component_slug: string | null;
    component_name: string | null;
    severity_label: SeverityLabel;
    cvss_score: number | null;
    is_kev_exploited: boolean;
    is_high_risk: boolean;
    patched_version: string | null;
    description: string | null;
    reference_url: string | null;
    published_at: string | null;
    first_seen_at: string;
    affects_our_stack: boolean;
    is_watched: boolean;
}

interface PaginatedResponse {
    data: Vulnerability[];
    meta: {
        current_page: number;
        last_page: number;
        per_page: number;
        total: number;
    };
}

type MultiFilterKey = 'severity' | 'component_type' | 'source';
type SingleFilterKey = 'range';

interface Filters {
    q: string;
    severity: Set<string>;
    component_type: Set<string>;
    source: Set<string>;
    range: string;
    high_risk_only: boolean;
    affects_our_stack: boolean;
    watched: boolean;
}

const PER_PAGE = 25;

const TICKER_PIXELS_PER_SECOND = 35;

const REFRESH_INTERVAL_MS = 10 * 60_000;

/** Hidden until TRACKED_PLUGIN_SLUGS is configured; flip to bring back the "our stack" tag. */
const SHOW_OUR_STACK = false;

const SEVERITY_STYLES: Record<SeverityLabel, string> = {
    critical: 'bg-red-500/15 text-red-300 ring-red-500/40',
    high: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
    medium: 'bg-amber-400/15 text-amber-200 ring-amber-400/40',
    low: 'bg-sky-400/10 text-sky-300 ring-sky-400/30',
    none: 'bg-slate-500/10 text-slate-400 ring-slate-500/30',
};

const SOURCE_LABELS: Record<SourceName, string> = {
    wordfence: 'Wordfence',
    wpvulnerability: 'WPVulnerability',
    cisa_kev: 'CISA KEV',
    nvd: 'NVD',
};

const FILTER_LABELS: Record<string, Record<string, string>> = {
    severity: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'Unscored' },
    component_type: { core: 'Core', plugin: 'Plugin', theme: 'Theme' },
    source: SOURCE_LABELS,
    range: { '1': 'Last 24h', '7': 'Last 7 days', '30': 'Last 30 days' },
};

const STAR_ICON = '<svg class="size-4" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M12 2.5l2.9 6.1 6.6.8-4.9 4.6 1.3 6.5L12 17.3l-5.9 3.2 1.3-6.5L2.5 9.4l6.6-.8L12 2.5z"/></svg>';

const LAST_SEEN_KEY = 'wpSecLastSeenHighRiskAt';

const FILTERS_OPEN_KEY = 'wpSecFiltersOpen';

function severityBadge(vuln: Vulnerability): string {
    const score = vuln.cvss_score !== null ? `<span class="opacity-80">${vuln.cvss_score.toFixed(1)}</span>` : '';
    const exploited = vuln.is_kev_exploited
        ? '<span class="rounded bg-red-500 px-1 text-[10px] font-bold text-white" title="Known exploited in the wild (CISA KEV)">EXPLOITED</span>'
        : '';

    return `<span class="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-semibold uppercase ring-1 ring-inset ${SEVERITY_STYLES[vuln.severity_label]}">${vuln.severity_label === 'none' ? 'n/a' : vuln.severity_label}${score}${exploited}</span>`;
}

/**
 * The plugin/theme name to headline a row with. Some sources only know the
 * slug, so it gets title-cased ("contact-form-7" → "Contact Form 7").
 */
function componentLabel(vuln: Vulnerability): string {
    if (vuln.component_name && vuln.component_name !== vuln.component_slug) {
        return vuln.component_name;
    }

    if (vuln.component_slug) {
        return vuln.component_slug
            .split('-')
            .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    return vuln.component_type === 'core' ? 'WordPress core' : 'Unknown component';
}

function escapeHtml(value: string): string {
    const div = document.createElement('div');
    div.textContent = value;

    return div.innerHTML;
}

function relativeTime(iso: string): string {
    const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
    const format = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
    const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
        ['year', 31_536_000],
        ['month', 2_592_000],
        ['week', 604_800],
        ['day', 86_400],
        ['hour', 3_600],
        ['minute', 60],
    ];

    for (const [unit, size] of units) {
        if (Math.abs(seconds) >= size) {
            return format.format(-Math.round(seconds / size), unit);
        }
    }

    return 'just now';
}

function debounce<Args extends unknown[]>(fn: (...args: Args) => void, wait: number): (...args: Args) => void {
    let timeout: ReturnType<typeof setTimeout>;

    return (...args: Args) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => fn(...args), wait);
    };
}

async function fetchJson<T>(url: string): Promise<T> {
    const response = await fetch(url, { headers: { Accept: 'application/json' } });

    if (!response.ok) {
        throw new Error(`Request to ${url} failed with ${response.status}`);
    }

    return response.json() as Promise<T>;
}

function emptyFilters(): Filters {
    return {
        q: '',
        severity: new Set(),
        component_type: new Set(),
        source: new Set(),
        range: '',
        high_risk_only: false,
        affects_our_stack: false,
        watched: false,
    };
}

class Dashboard {
    private page = 1;
    private filters: Filters = emptyFilters();
    private requestId = 0;
    private readonly expanded = new Set<number>();
    private items: Vulnerability[] = [];
    private toastTimeout: ReturnType<typeof setTimeout> | undefined;

    private readonly search = document.querySelector<HTMLInputElement>('#filter-q')!;
    private readonly highRiskToggle = document.querySelector<HTMLInputElement>('#filter-high-risk')!;
    private readonly ourStackToggle = document.querySelector<HTMLInputElement>('#filter-our-stack')!;
    private readonly watchedToggle = document.querySelector<HTMLInputElement>('#filter-watched')!;
    private readonly watchedButton = document.querySelector<HTMLButtonElement>('#watched-btn')!;
    private readonly tbody = document.querySelector<HTMLTableSectionElement>('#results-body')!;
    private readonly emptyState = document.querySelector<HTMLElement>('#empty-state')!;
    private readonly errorState = document.querySelector<HTMLElement>('#error-state')!;
    private readonly resultCount = document.querySelector<HTMLElement>('#result-count')!;
    private readonly activePills = document.querySelector<HTMLElement>('#active-pills')!;
    private readonly clearButton = document.querySelector<HTMLButtonElement>('#clear-filters')!;
    private readonly pageInfo = document.querySelector<HTMLElement>('#page-info')!;
    private readonly prevButton = document.querySelector<HTMLButtonElement>('#prev-page')!;
    private readonly nextButton = document.querySelector<HTMLButtonElement>('#next-page')!;
    private readonly ticker = document.querySelector<HTMLElement>('#ticker-track')!;
    private readonly badge = document.querySelector<HTMLElement>('#unread-badge')!;
    private readonly toast = document.querySelector<HTMLElement>('#toast')!;
    private readonly filtersToggle = document.querySelector<HTMLButtonElement>('#filters-toggle')!;
    private readonly filtersPanel = document.querySelector<HTMLElement>('#filters-panel')!;
    private readonly filtersCount = document.querySelector<HTMLElement>('#filters-count')!;

    constructor() {
        this.readFiltersFromUrl();
        this.setFiltersOpen(this.storedFiltersOpen());
        this.syncControls();
        this.bindEvents();
    }

    async boot(): Promise<void> {
        await Promise.all([this.loadResults(), this.loadTicker(), this.loadStats()]);

        setInterval(() => {
            void this.loadTicker();
            void this.loadStats();

            // Keep the feed live, but don't yank rows away while someone is reading or paging.
            if (this.page === 1 && this.expanded.size === 0) {
                void this.loadResults();
            }
        }, REFRESH_INTERVAL_MS);
    }

    private bindEvents(): void {
        this.filtersToggle.addEventListener('click', () => {
            const open = this.filtersPanel.classList.contains('hidden');
            this.setFiltersOpen(open);

            try {
                localStorage.setItem(FILTERS_OPEN_KEY, open ? '1' : '0');
            } catch {
                // Storage unavailable (private mode etc.) — the panel just won't be remembered.
            }
        });

        this.search.addEventListener(
            'input',
            debounce(() => {
                this.filters.q = this.search.value.trim();
                this.applyFilters();
            }, 300),
        );

        this.highRiskToggle.addEventListener('change', () => {
            this.filters.high_risk_only = this.highRiskToggle.checked;
            this.applyFilters();
        });

        this.ourStackToggle.addEventListener('change', () => {
            this.filters.affects_our_stack = this.ourStackToggle.checked;
            this.applyFilters();
        });

        this.watchedToggle.addEventListener('change', () => {
            this.filters.watched = this.watchedToggle.checked;
            this.applyFilters();
        });

        this.watchedButton.addEventListener('click', () => {
            const showingWatched = this.filters.watched;
            this.filters = emptyFilters();
            this.filters.watched = !showingWatched;
            this.applyFilters();
        });

        document.querySelectorAll<HTMLElement>('[data-chip-group]').forEach((group) => {
            const key = group.dataset.chipGroup as MultiFilterKey;

            group.addEventListener('click', (event) => {
                const chip = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-value]');

                if (!chip) {
                    return;
                }

                const value = chip.dataset.value!;
                const values = this.filters[key];
                values.has(value) ? values.delete(value) : values.add(value);
                this.applyFilters();
            });
        });

        document.querySelectorAll<HTMLElement>('[data-radio-group]').forEach((group) => {
            const key = group.dataset.radioGroup as SingleFilterKey;

            group.addEventListener('click', (event) => {
                const option = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-value]');

                if (option) {
                    this.filters[key] = option.dataset.value!;
                    this.applyFilters();
                }
            });
        });

        document.querySelectorAll<HTMLElement>('[data-stat-preset]').forEach((card) => {
            card.addEventListener('click', () => {
                this.filters = emptyFilters();

                if (card.dataset.statPreset === 'high-risk') {
                    this.filters.high_risk_only = true;
                    this.filters.range = '7';
                } else if (card.dataset.statPreset === 'watched') {
                    this.filters.watched = true;
                }

                this.applyFilters();
            });
        });

        this.activePills.addEventListener('click', (event) => {
            const pill = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-remove]');

            if (pill) {
                this.removeFilter(pill.dataset.remove!, pill.dataset.value ?? '');
            }
        });

        this.clearButton.addEventListener('click', () => this.clearFilters());
        document.querySelector('[data-action="clear-filters"]')?.addEventListener('click', () => this.clearFilters());
        document.querySelector('[data-action="retry"]')?.addEventListener('click', () => void this.loadResults());

        this.prevButton.addEventListener('click', () => this.goToPage(this.page - 1));
        this.nextButton.addEventListener('click', () => this.goToPage(this.page + 1));

        this.tbody.addEventListener('click', (event) => {
            const target = event.target as HTMLElement;

            const star = target.closest<HTMLButtonElement>('[data-watch-for]');

            if (star) {
                void this.toggleWatch(Number(star.dataset.watchFor));

                return;
            }

            if (target.closest('a')) {
                return;
            }

            const row = target.closest<HTMLElement>('[data-row-id]');

            if (row) {
                this.toggleDetails(Number(row.dataset.rowId));
            }
        });

        document.addEventListener('keydown', (event) => {
            const typing = (event.target as HTMLElement).closest('input, select, textarea');

            if (event.key === '/' && !typing) {
                event.preventDefault();
                this.search.focus();
            } else if (event.key === 'Escape' && document.activeElement === this.search) {
                this.search.value = '';
                this.filters.q = '';
                this.search.blur();
                this.applyFilters();
            }
        });

        document.querySelector('#ticker')?.addEventListener('click', () => this.markSeen());
        document.querySelector('#mark-seen-btn')?.addEventListener('click', () => this.markSeen());
    }

    /**
     * The filter panel starts collapsed and remembers whichever state the
     * viewer last left it in.
     */
    private storedFiltersOpen(): boolean {
        try {
            return localStorage.getItem(FILTERS_OPEN_KEY) === '1';
        } catch {
            return false;
        }
    }

    private setFiltersOpen(open: boolean): void {
        this.filtersPanel.classList.toggle('hidden', !open);
        this.filtersToggle.setAttribute('aria-expanded', String(open));
        document.querySelector('#filters-chevron')?.classList.toggle('rotate-180', open);
    }

    private applyFilters(): void {
        this.page = 1;
        this.expanded.clear();
        this.syncControls();
        this.writeFiltersToUrl();
        void this.loadResults();
    }

    private clearFilters(): void {
        this.filters = emptyFilters();
        this.applyFilters();
    }

    private removeFilter(key: string, value: string): void {
        if (key === 'severity' || key === 'component_type' || key === 'source') {
            this.filters[key].delete(value);
        } else if (key === 'range' || key === 'q') {
            this.filters[key] = '';
        } else if (key === 'high_risk_only' || key === 'affects_our_stack' || key === 'watched') {
            this.filters[key] = false;
        }

        this.applyFilters();
    }

    private goToPage(page: number): void {
        this.page = Math.max(1, page);
        this.expanded.clear();
        this.writeFiltersToUrl();
        void this.loadResults();
        document.querySelector('#results-body')?.closest('section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    /**
     * Reflects the filter state onto every control, so chips, toggles, the
     * search box and the active-filter pills always agree with each other.
     */
    private syncControls(): void {
        if (this.search.value.trim() !== this.filters.q) {
            this.search.value = this.filters.q;
        }

        this.highRiskToggle.checked = this.filters.high_risk_only;
        this.ourStackToggle.checked = this.filters.affects_our_stack;
        this.watchedToggle.checked = this.filters.watched;
        this.watchedButton.setAttribute('aria-pressed', String(this.filters.watched));

        document.querySelectorAll<HTMLElement>('[data-chip-group]').forEach((group) => {
            const values = this.filters[group.dataset.chipGroup as MultiFilterKey];

            group.querySelectorAll<HTMLElement>('[data-value]').forEach((chip) => {
                chip.setAttribute('aria-pressed', String(values.has(chip.dataset.value!)));
            });
        });

        document.querySelectorAll<HTMLElement>('[data-radio-group]').forEach((group) => {
            const value = this.filters[group.dataset.radioGroup as SingleFilterKey];

            group.querySelectorAll<HTMLElement>('[data-value]').forEach((option) => {
                option.setAttribute('aria-pressed', String(option.dataset.value === value));
            });
        });

        const pills = this.activeFilterPills();
        this.activePills.innerHTML = pills.join('');
        this.clearButton.classList.toggle('hidden', pills.length === 0);

        // The search box stays visible, so only count what's tucked inside the collapsed panel.
        const panelFilterCount = pills.length - (this.filters.q !== '' ? 1 : 0);
        this.filtersCount.textContent = String(panelFilterCount);
        this.filtersCount.classList.toggle('hidden', panelFilterCount === 0);
    }

    private activeFilterPills(): string[] {
        const pill = (key: string, value: string, label: string): string => `
            <button type="button" data-remove="${key}" data-value="${escapeHtml(value)}"
                    class="inline-flex items-center gap-1 rounded-full bg-slate-800 px-2.5 py-0.5 text-xs text-slate-300 transition hover:bg-slate-700 hover:text-white"
                    title="Remove filter">
                ${escapeHtml(label)} <span aria-hidden="true" class="text-slate-500">✕</span>
            </button>`;
        const pills: string[] = [];

        if (this.filters.q !== '') {
            pills.push(pill('q', '', `“${this.filters.q}”`));
        }

        for (const key of ['severity', 'component_type', 'source'] as const) {
            this.filters[key].forEach((value) => pills.push(pill(key, value, FILTER_LABELS[key][value] ?? value)));
        }

        if (this.filters.range !== '') {
            pills.push(pill('range', '', FILTER_LABELS.range[this.filters.range] ?? this.filters.range));
        }

        if (this.filters.watched) {
            pills.push(pill('watched', '', '★ Watched'));
        }

        if (this.filters.high_risk_only) {
            pills.push(pill('high_risk_only', '', 'High-risk'));
        }

        if (this.filters.affects_our_stack) {
            pills.push(pill('affects_our_stack', '', 'Our stack'));
        }

        return pills;
    }

    private readFiltersFromUrl(): void {
        const params = new URLSearchParams(window.location.search);
        const list = (key: string): Set<string> => new Set((params.get(key) ?? '').split(',').filter(Boolean));

        this.filters = {
            q: params.get('q') ?? '',
            severity: list('severity'),
            component_type: list('component_type'),
            source: list('source'),
            range: params.get('range') ?? '',
            high_risk_only: params.get('high_risk_only') === '1',
            affects_our_stack: params.get('affects_our_stack') === '1',
            watched: params.get('watched') === '1',
        };
        this.page = Math.max(1, Number(params.get('page')) || 1);
    }

    private writeFiltersToUrl(): void {
        const params = this.filterParams();

        params.delete('from');

        if (this.filters.range !== '') {
            params.set('range', this.filters.range);
        }

        if (this.page > 1) {
            params.set('page', String(this.page));
        }

        const query = params.toString();
        history.replaceState(null, '', query === '' ? window.location.pathname : `?${query}`);
    }

    private filterParams(): URLSearchParams {
        const params = new URLSearchParams();

        if (this.filters.q !== '') {
            params.set('q', this.filters.q);
        }

        for (const key of ['severity', 'component_type', 'source'] as const) {
            if (this.filters[key].size > 0) {
                params.set(key, [...this.filters[key]].join(','));
            }
        }

        if (this.filters.range !== '') {
            const from = new Date(Date.now() - Number(this.filters.range) * 86_400_000);
            params.set('from', from.toISOString());
        }

        if (this.filters.high_risk_only) {
            params.set('high_risk_only', '1');
        }

        if (this.filters.affects_our_stack) {
            params.set('affects_our_stack', '1');
        }

        if (this.filters.watched) {
            params.set('watched', '1');
        }

        return params;
    }

    async loadResults(): Promise<void> {
        const requestId = ++this.requestId;
        const params = this.filterParams();
        params.set('page', String(this.page));
        params.set('per_page', String(PER_PAGE));

        this.renderSkeleton();
        this.errorState.classList.add('hidden');

        try {
            const response = await fetchJson<PaginatedResponse>(`/api/vulnerabilities?${params.toString()}`);

            if (requestId !== this.requestId) {
                return;
            }

            this.items = response.data;
            this.renderTable();
            this.renderPagination(response.meta);
            this.markUpdated();
        } catch {
            if (requestId !== this.requestId) {
                return;
            }

            this.tbody.innerHTML = '';
            this.emptyState.classList.add('hidden');
            this.errorState.classList.remove('hidden');
            this.resultCount.textContent = '—';
        }
    }

    private renderSkeleton(): void {
        if (this.tbody.children.length > 0 && this.items.length > 0) {
            this.tbody.classList.add('opacity-50');

            return;
        }

        this.tbody.innerHTML = Array.from({ length: 6 }, () => `
            <tr>
                <td class="px-2 py-3"><div class="mx-auto size-4 animate-pulse rounded bg-slate-800"></div></td>
                <td class="px-4 py-3"><div class="h-5 w-20 animate-pulse rounded bg-slate-800"></div></td>
                <td class="px-4 py-3"><div class="h-4 w-3/4 animate-pulse rounded bg-slate-800"></div><div class="mt-2 h-3 w-1/3 animate-pulse rounded bg-slate-800/70"></div></td>
                <td class="px-4 py-3"><div class="h-4 w-16 animate-pulse rounded bg-slate-800"></div></td>
                <td class="px-4 py-3"><div class="h-4 w-20 animate-pulse rounded bg-slate-800"></div></td>
            </tr>`).join('');
    }

    private renderTable(): void {
        this.tbody.classList.remove('opacity-50');
        this.emptyState.classList.toggle('hidden', this.items.length > 0);
        this.tbody.innerHTML = this.items.map((vuln) => this.row(vuln)).join('');
    }

    private renderPagination(meta: PaginatedResponse['meta']): void {
        const first = meta.total === 0 ? 0 : (meta.current_page - 1) * meta.per_page + 1;
        const last = Math.min(meta.current_page * meta.per_page, meta.total);

        this.resultCount.textContent = meta.total.toLocaleString();
        this.pageInfo.textContent = meta.total === 0
            ? ''
            : `${first.toLocaleString()}–${last.toLocaleString()} of ${meta.total.toLocaleString()} · page ${meta.current_page} of ${Math.max(meta.last_page, 1)}`;
        this.prevButton.disabled = meta.current_page <= 1;
        this.nextButton.disabled = meta.current_page >= meta.last_page;
    }

    private row(vuln: Vulnerability): string {
        const isExpanded = this.expanded.has(vuln.id);
        const stackTag = SHOW_OUR_STACK && vuln.affects_our_stack
            ? '<span class="rounded bg-indigo-500/20 px-1.5 py-0.5 text-[11px] font-medium text-indigo-300 ring-1 ring-inset ring-indigo-500/30">our stack</span>'
            : '';
        const cve = vuln.cve_id
            ? `<span class="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-xs text-slate-300 ring-1 ring-inset ring-slate-700">${escapeHtml(vuln.cve_id)}</span>`
            : '<span class="text-xs text-slate-600">no CVE</span>';
        const published = vuln.published_at
            ? `<span title="${escapeHtml(new Date(vuln.published_at).toLocaleString())}">${relativeTime(vuln.published_at)}</span>`
            : '—';

        return `
            <tr data-row-id="${vuln.id}" class="cursor-pointer transition hover:bg-slate-800/40 ${isExpanded ? 'bg-slate-800/40' : ''}">
                <td class="px-2 py-3 text-center align-top">${this.watchButton(vuln)}</td>
                <td class="px-4 py-3 align-top">${severityBadge(vuln)}</td>
                <td class="px-4 py-3">
                    <div class="flex items-start gap-2">
                        <span class="mt-0.5 text-slate-600 transition ${isExpanded ? 'rotate-90' : ''}">›</span>
                        <div class="min-w-0">
                            <div class="flex flex-wrap items-center gap-2">
                                <span class="font-medium text-slate-100">${escapeHtml(componentLabel(vuln))}</span>
                                ${cve}
                                ${stackTag}
                            </div>
                            <div class="mt-0.5 text-sm capitalize text-slate-500">${vuln.component_type}${vuln.component_slug ? ` · <span class="normal-case font-mono text-xs">${escapeHtml(vuln.component_slug)}</span>` : ''}</div>
                        </div>
                    </div>
                </td>
                <td class="px-4 py-3 align-top text-sm text-slate-400">${SOURCE_LABELS[vuln.source] ?? escapeHtml(vuln.source)}</td>
                <td class="whitespace-nowrap px-4 py-3 align-top text-sm text-slate-400">${published}</td>
            </tr>
            ${isExpanded ? this.detailsRow(vuln) : ''}
        `;
    }

    private watchButton(vuln: Vulnerability): string {
        const label = vuln.is_watched ? 'Remove from watched' : 'Add to watched';

        return `
            <button type="button" data-watch-for="${vuln.id}" aria-pressed="${vuln.is_watched}" title="${label}" aria-label="${label}"
                    class="rounded p-1 transition ${vuln.is_watched ? 'fill-amber-400 text-amber-400' : 'fill-transparent text-slate-600 hover:text-amber-300'}">
                ${STAR_ICON}
            </button>`;
    }

    private detailsRow(vuln: Vulnerability): string {
        const fact = (label: string, value: string): string => `
            <div>
                <dt class="text-xs uppercase tracking-wide text-slate-500">${label}</dt>
                <dd class="mt-0.5 text-sm text-slate-200">${value}</dd>
            </div>`;
        const links = [
            vuln.reference_url ? [vuln.reference_url, 'Advisory'] : null,
            vuln.cve_id ? [`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`, 'NVD'] : null,
            vuln.component_slug && vuln.component_type !== 'core'
                ? [`https://wordpress.org/${vuln.component_type}s/${vuln.component_slug}/`, 'WordPress.org']
                : null,
        ].filter((link): link is string[] => link !== null);

        return `
            <tr class="bg-slate-950/60">
                <td colspan="5" class="px-4 pb-5 pt-2">
                    <div class="ml-0 space-y-4 border-l-2 border-slate-700 pl-4 md:ml-36">
                        ${this.detailsHeading(vuln)}
                        <p class="max-w-3xl whitespace-pre-line text-sm leading-relaxed text-slate-300">${escapeHtml(vuln.description ?? 'No description provided.')}</p>
                        <dl class="grid grid-cols-2 gap-4 sm:grid-cols-4">
                            ${fact('CVSS', vuln.cvss_score !== null ? vuln.cvss_score.toFixed(1) : '—')}
                            ${fact('Fixed in', vuln.patched_version ? escapeHtml(vuln.patched_version) : '<span class="text-slate-500">unknown</span>')}
                            ${fact('Slug', vuln.component_slug ? `<span class="font-mono text-xs">${escapeHtml(vuln.component_slug)}</span>` : '—')}
                            ${fact('First seen', relativeTime(vuln.first_seen_at))}
                        </dl>
                        <div class="flex flex-wrap gap-2">
                            ${links.map(([url, label]) => `
                                <a href="${escapeHtml(url)}" target="_blank" rel="noopener"
                                   class="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-1 text-sm text-sky-300 transition hover:border-sky-500/50 hover:bg-sky-500/10">
                                    ${label} <span aria-hidden="true">↗</span>
                                </a>`).join('')}
                        </div>
                    </div>
                </td>
            </tr>
        `;
    }

    private toggleDetails(id: number): void {
        this.expanded.has(id) ? this.expanded.delete(id) : this.expanded.add(id);
        this.renderTable();
    }

    /**
     * Sources with a real advisory title (Wordfence, WPVulnerability) get it as
     * a heading; NVD's "title" is just the description's first sentence, so it
     * would only repeat the paragraph below.
     */
    private detailsHeading(vuln: Vulnerability): string {
        const title = vuln.title.replace(/\.{3}$|…$/, '');

        if (vuln.description && vuln.description.startsWith(title)) {
            return '';
        }

        return `<h3 class="font-medium text-slate-100">${escapeHtml(vuln.title)}</h3>`;
    }

    private async toggleWatch(id: number): Promise<void> {
        const vuln = this.items.find((item) => item.id === id);

        if (!vuln) {
            return;
        }

        const watch = !vuln.is_watched;
        vuln.is_watched = watch;
        this.renderTable();

        try {
            const response = await fetch(`/api/vulnerabilities/${id}/watch`, {
                method: watch ? 'PUT' : 'DELETE',
                headers: { Accept: 'application/json' },
            });

            if (!response.ok) {
                throw new Error(`Watch update failed with ${response.status}`);
            }

            this.showToast(watch ? `★ Watching ${componentLabel(vuln)}` : `Removed ${componentLabel(vuln)} from watched`);
            void this.loadStats();
        } catch {
            vuln.is_watched = !watch;
            this.renderTable();
            this.showToast('Could not update watched list — try again');
        }
    }

    private showToast(message: string): void {
        this.toast.textContent = message;
        this.toast.classList.remove('opacity-0', 'translate-y-4');
        clearTimeout(this.toastTimeout);
        this.toastTimeout = setTimeout(() => this.toast.classList.add('opacity-0', 'translate-y-4'), 2500);
    }

    private markUpdated(): void {
        document.querySelector('#last-updated')!.textContent = `updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
    }

    async loadTicker(): Promise<void> {
        const response = await fetchJson<{ data: Vulnerability[] }>('/api/vulnerabilities/ticker?limit=20');
        const items = response.data;

        if (items.length === 0) {
            this.ticker.innerHTML = '<span class="px-4 text-slate-500">No high-risk vulnerabilities right now.</span>';
            this.updateBadge(0);
            return;
        }

        const entries = items
            .map(
                (vuln) => `
                    <a href="${vuln.reference_url ? escapeHtml(vuln.reference_url) : '#'}" target="_blank" rel="noopener"
                       class="inline-flex items-center gap-2 whitespace-nowrap px-5 hover:underline">
                        ${severityBadge(vuln)}
                        <span class="font-medium text-slate-100">${escapeHtml(componentLabel(vuln))}</span>
                        ${vuln.cve_id ? `<span class="font-mono text-xs text-slate-400">${escapeHtml(vuln.cve_id)}</span>` : ''}
                        <span class="text-slate-700">◆</span>
                    </a>
                `,
            )
            .join('');

        // Duplicated so the CSS marquee animation (-50% translateX) loops seamlessly.
        this.ticker.innerHTML = entries + entries;

        // Pace by distance rather than a fixed duration, so a longer ticker doesn't scroll faster.
        this.ticker.style.animationDuration = `${Math.max(this.ticker.scrollWidth / 2 / TICKER_PIXELS_PER_SECOND, 20)}s`;

        const lastSeen = localStorage.getItem(LAST_SEEN_KEY);
        const unread = lastSeen
            ? items.filter((vuln) => vuln.published_at && vuln.published_at > lastSeen).length
            : items.length;
        this.updateBadge(unread);
    }

    private updateBadge(count: number): void {
        this.badge.textContent = String(count);
        this.badge.classList.toggle('hidden', count === 0);
    }

    private markSeen(): void {
        localStorage.setItem(LAST_SEEN_KEY, new Date().toISOString());
        this.updateBadge(0);
        this.showToast('All current high-risk items marked as seen');
    }

    async loadStats(): Promise<void> {
        const weekAgo = new Date(Date.now() - 7 * 86_400_000).toISOString();
        const [highRisk, watched, total] = await Promise.all([
            fetchJson<PaginatedResponse>(`/api/vulnerabilities?high_risk_only=1&from=${encodeURIComponent(weekAgo)}&per_page=1`),
            fetchJson<PaginatedResponse>('/api/vulnerabilities?watched=1&per_page=1'),
            fetchJson<PaginatedResponse>('/api/vulnerabilities?per_page=1'),
        ]);

        document.querySelector('#stat-high-risk')!.textContent = highRisk.meta.total.toLocaleString();
        document.querySelector('#stat-watched')!.textContent = watched.meta.total.toLocaleString();
        document.querySelector('#watched-count')!.textContent = watched.meta.total.toLocaleString();
        document.querySelector('#stat-total')!.textContent = total.meta.total.toLocaleString();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    void new Dashboard().boot();
});
