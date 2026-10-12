type SeverityLabel = 'none' | 'low' | 'medium' | 'high' | 'critical';
type ComponentType = 'core' | 'plugin' | 'theme';
type VulnerabilityStatus = 'new' | 'reviewing' | 'patched' | 'not_applicable' | 'ignored';
type SourceName = 'wordfence' | 'wpvulnerability' | 'cisa_kev';

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
    status: VulnerabilityStatus;
    affects_our_stack: boolean;
}

interface PaginatedResponse {
    data: Vulnerability[];
    meta: {
        current_page: number;
        last_page: number;
        total: number;
    };
}

const SEVERITY_STYLES: Record<SeverityLabel, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-amber-400 text-black',
    low: 'bg-slate-300 text-black',
    none: 'bg-slate-200 text-slate-600',
};

const LAST_SEEN_KEY = 'wpSecLastSeenHighRiskAt';

function severityBadge(vuln: Vulnerability): string {
    const score = vuln.cvss_score !== null ? ` ${vuln.cvss_score.toFixed(1)}` : '';
    const exploited = vuln.is_kev_exploited ? ' ⚠ exploited' : '';

    return `<span class="inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEVERITY_STYLES[vuln.severity_label]}">${vuln.severity_label}${score}${exploited}</span>`;
}

function escapeHtml(value: string): string {
    const div = document.createElement('div');
    div.textContent = value;

    return div.innerHTML;
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

class Dashboard {
    private page = 1;
    private readonly form: HTMLFormElement;
    private readonly tbody: HTMLTableSectionElement;
    private readonly emptyState: HTMLElement;
    private readonly pageInfo: HTMLElement;
    private readonly prevButton: HTMLButtonElement;
    private readonly nextButton: HTMLButtonElement;
    private readonly ticker: HTMLElement;
    private readonly badge: HTMLElement;

    constructor() {
        this.form = document.querySelector<HTMLFormElement>('#filter-form')!;
        this.tbody = document.querySelector<HTMLTableSectionElement>('#results-body')!;
        this.emptyState = document.querySelector<HTMLElement>('#empty-state')!;
        this.pageInfo = document.querySelector<HTMLElement>('#page-info')!;
        this.prevButton = document.querySelector<HTMLButtonElement>('#prev-page')!;
        this.nextButton = document.querySelector<HTMLButtonElement>('#next-page')!;
        this.ticker = document.querySelector<HTMLElement>('#ticker-track')!;
        this.badge = document.querySelector<HTMLElement>('#unread-badge')!;

        this.form.addEventListener('submit', (event) => {
            event.preventDefault();
            this.page = 1;
            void this.loadResults();
        });

        this.form.querySelector('#filter-q')?.addEventListener(
            'input',
            debounce(() => {
                this.page = 1;
                void this.loadResults();
            }, 400),
        );

        this.form.querySelectorAll('select, input[type="checkbox"]').forEach((element) => {
            element.addEventListener('change', () => {
                this.page = 1;
                void this.loadResults();
            });
        });

        this.prevButton.addEventListener('click', () => {
            if (this.page > 1) {
                this.page--;
                void this.loadResults();
            }
        });

        this.nextButton.addEventListener('click', () => {
            this.page++;
            void this.loadResults();
        });

        document.querySelector('#ticker')?.addEventListener('click', () => this.markSeen());
        document.querySelector('#mark-seen-btn')?.addEventListener('click', () => this.markSeen());
    }

    async boot(): Promise<void> {
        await Promise.all([this.loadResults(), this.loadTicker(), this.loadStats()]);

        setInterval(() => {
            void this.loadTicker();
            void this.loadStats();
        }, 60_000);
    }

    private buildQuery(extra: Record<string, string> = {}): string {
        const params = new URLSearchParams(extra);
        const data = new FormData(this.form);

        for (const [key, value] of data.entries()) {
            if (typeof value === 'string' && value !== '') {
                params.set(key, value);
            }
        }

        this.form.querySelectorAll<HTMLInputElement>('input[type="checkbox"]').forEach((checkbox) => {
            if (checkbox.checked) {
                params.set(checkbox.name, '1');
            }
        });

        return params.toString();
    }

    async loadResults(): Promise<void> {
        const query = this.buildQuery({ page: String(this.page), per_page: '25' });
        const response = await fetchJson<PaginatedResponse>(`/api/vulnerabilities?${query}`);

        this.renderTable(response.data);
        this.pageInfo.textContent = `Page ${response.meta.current_page} of ${Math.max(response.meta.last_page, 1)} (${response.meta.total} total)`;
        this.prevButton.disabled = response.meta.current_page <= 1;
        this.nextButton.disabled = response.meta.current_page >= response.meta.last_page;
    }

    private renderTable(items: Vulnerability[]): void {
        this.emptyState.classList.toggle('hidden', items.length > 0);
        this.tbody.innerHTML = items.map((vuln) => this.row(vuln)).join('');

        this.tbody.querySelectorAll<HTMLSelectElement>('select[data-status-for]').forEach((select) => {
            select.addEventListener('change', () => void this.updateStatus(select));
        });
    }

    private row(vuln: Vulnerability): string {
        const link = vuln.reference_url
            ? `<a class="text-blue-600 underline hover:text-blue-800" href="${escapeHtml(vuln.reference_url)}" target="_blank" rel="noopener">${escapeHtml(vuln.title)}</a>`
            : escapeHtml(vuln.title);
        const component = vuln.component_name ?? vuln.component_slug ?? '—';
        const stackTag = vuln.affects_our_stack
            ? '<span class="ml-1 rounded bg-indigo-100 px-1.5 py-0.5 text-xs font-medium text-indigo-700">our stack</span>'
            : '';

        return `
            <tr class="border-b last:border-0">
                <td class="px-3 py-2">${severityBadge(vuln)}</td>
                <td class="px-3 py-2">
                    <div class="font-medium">${link}</div>
                    <div class="text-sm text-slate-500">${escapeHtml(component)} ${stackTag}</div>
                </td>
                <td class="px-3 py-2 text-sm text-slate-600">${vuln.component_type}</td>
                <td class="px-3 py-2 text-sm text-slate-600">${escapeHtml(vuln.source)}</td>
                <td class="px-3 py-2 text-sm text-slate-600">${vuln.published_at ? new Date(vuln.published_at).toLocaleDateString() : '—'}</td>
                <td class="px-3 py-2">
                    <select data-status-for="${vuln.id}" class="rounded border-slate-300 text-sm">
                        ${this.statusOptions(vuln.status)}
                    </select>
                </td>
            </tr>
        `;
    }

    private statusOptions(current: VulnerabilityStatus): string {
        const options: Array<[VulnerabilityStatus, string]> = [
            ['new', 'New'],
            ['reviewing', 'Reviewing'],
            ['patched', 'Patched'],
            ['not_applicable', 'Not applicable'],
            ['ignored', 'Ignored'],
        ];

        return options
            .map(([value, label]) => `<option value="${value}" ${value === current ? 'selected' : ''}>${label}</option>`)
            .join('');
    }

    private async updateStatus(select: HTMLSelectElement): Promise<void> {
        const id = select.dataset.statusFor;

        await fetch(`/api/vulnerabilities/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({ status: select.value }),
        });
    }

    async loadTicker(): Promise<void> {
        const response = await fetchJson<{ data: Vulnerability[] }>('/api/vulnerabilities/ticker?limit=20');
        const items = response.data;

        if (items.length === 0) {
            this.ticker.innerHTML = '<span class="px-4 text-slate-400">No high-risk vulnerabilities right now.</span>';
            this.updateBadge(0);
            return;
        }

        const entries = items
            .map(
                (vuln) => `
                    <a href="${vuln.reference_url ? escapeHtml(vuln.reference_url) : '#'}" target="_blank" rel="noopener"
                       class="inline-flex items-center gap-2 px-4 whitespace-nowrap hover:underline">
                        ${severityBadge(vuln)}
                        <span class="font-medium">${escapeHtml(vuln.component_name ?? vuln.component_slug ?? 'WordPress')}</span>
                        <span class="text-slate-500">— ${escapeHtml(vuln.title)}</span>
                    </a>
                `,
            )
            .join('');

        // Duplicated so the CSS marquee animation (-50% translateX) loops seamlessly.
        this.ticker.innerHTML = entries + entries;

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
    }

    async loadStats(): Promise<void> {
        const [highRisk, affectsStack, total] = await Promise.all([
            fetchJson<PaginatedResponse>('/api/vulnerabilities?high_risk_only=1&status=new&per_page=1'),
            fetchJson<PaginatedResponse>('/api/vulnerabilities?affects_our_stack=1&status=new&per_page=1'),
            fetchJson<PaginatedResponse>('/api/vulnerabilities?per_page=1'),
        ]);

        document.querySelector('#stat-high-risk')!.textContent = String(highRisk.meta.total);
        document.querySelector('#stat-affects-stack')!.textContent = String(affectsStack.meta.total);
        document.querySelector('#stat-total')!.textContent = String(total.meta.total);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    void new Dashboard().boot();
});
