import { CheckCircle2, Server, ShieldAlert, ShieldCheck } from 'lucide-react'

function StatCard({ icon: Icon, label, value, unit, tone }) {
    return (
        <div className="group relative overflow-hidden rounded-xl border border-border bg-card p-5 transition-all duration-200 hover:border-primary/30 hover:shadow-md">
            <div className="pointer-events-none absolute -right-3 -top-3 opacity-[0.06] transition-opacity group-hover:opacity-[0.12]">
                <Icon className="h-20 w-20" />
            </div>
            <div className="flex items-center gap-2">
                <span className={`inline-flex h-1.5 w-1.5 rounded-full ${tone}`} />
                <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                    {label}
                </p>
            </div>
            <div className="mt-3 flex items-baseline gap-2">
                <span className="text-3xl font-bold tabular-nums tracking-tight text-foreground">
                    {value}
                </span>
                <span className="text-xs text-muted-foreground">{unit}</span>
            </div>
        </div>
    )
}

function formatDeadline(raw) {
    if (!raw) return '--'
    const d = new Date(raw)
    if (Number.isNaN(d.getTime())) return '--'
    const hour = String(d.getHours()).padStart(2, '0')
    const min = String(d.getMinutes()).padStart(2, '0')
    return `${hour}:${min}`
}

/**
 * Account pool summary.
 *
 * The breaker banner is the important part: when upstream refuses every sign-in
 * for this deployment, "0 available" alone looks like a configuration mistake,
 * and an operator's first instinct is to retry — which is exactly what keeps the
 * block alive. The banner names the cause and offers the one useful action.
 */
export default function QueueCards({ queueStatus, riskStatus, onClearRisk, clearingRisk, t }) {
    if (!queueStatus) {
        return null
    }

    return (
        <div className="space-y-4">
            {riskStatus?.active && (
                <div className="flex flex-col gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-700 md:flex-row md:items-center md:justify-between dark:text-amber-300">
                    <div className="flex items-start gap-3">
                        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0" />
                        <div>
                            <p className="font-medium">{t('accountManager.riskCooldownTitle')}</p>
                            <p className="mt-1 text-xs opacity-90">
                                {t('accountManager.riskCooldownDesc', {
                                    time: formatDeadline(riskStatus.until),
                                    strikes: riskStatus.strikes ?? 0,
                                })}
                            </p>
                        </div>
                    </div>
                    <button
                        onClick={onClearRisk}
                        disabled={clearingRisk}
                        className="shrink-0 self-start rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-medium transition-colors hover:bg-amber-500/20 disabled:opacity-50 md:self-auto"
                    >
                        {clearingRisk ? t('accountManager.riskCooldownClearing') : t('accountManager.riskCooldownRetry')}
                    </button>
                </div>
            )}
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                <StatCard
                    icon={CheckCircle2}
                    label={t('accountManager.available')}
                    value={queueStatus.available}
                    unit={t('accountManager.accountsUnit')}
                    tone="bg-emerald-500"
                />
                <StatCard
                    icon={Server}
                    label={t('accountManager.inUse')}
                    value={queueStatus.in_use}
                    unit={t('accountManager.threadsUnit')}
                    tone="bg-primary"
                />
                <StatCard
                    icon={ShieldCheck}
                    label={t('accountManager.totalPool')}
                    value={queueStatus.total}
                    unit={t('accountManager.accountsUnit')}
                    tone="bg-sky-500"
                />
            </div>
        </div>
    )
}
