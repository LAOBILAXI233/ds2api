import { X } from 'lucide-react'

/**
 * Import a browser session token for one account.
 *
 * Signing in with email+password goes through `POST /users/login`, which is the
 * endpoint upstream guards with its device/risk layer (`RISK_DEVICE_DETECTED`).
 * A token copied out of an already signed-in browser tab skips that call, so
 * this is the way to bring accounts back while the sign-in path is refused.
 * The backend still verifies the token against `GET /users/current` before it is
 * stored, so a stale or wrong token is rejected here rather than at request time.
 */
export default function ImportTokenModal({
    show,
    t,
    accountId,
    token,
    setToken,
    loading,
    onClose,
    onSubmit,
}) {
    if (!show) {
        return null
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4 animate-in fade-in">
            <div className="bg-card w-full max-w-lg rounded-xl border border-border shadow-2xl overflow-hidden animate-in zoom-in-95">
                <div className="p-4 border-b border-border flex justify-between items-center">
                    <h3 className="font-semibold">{t('accountManager.importTokenTitle')}</h3>
                    <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
                        <X className="w-5 h-5" />
                    </button>
                </div>
                <div className="p-6 space-y-4">
                    {accountId ? (
                        <div className="text-sm">
                            <span className="text-muted-foreground">{t('accountManager.importTokenAccount')}</span>{' '}
                            <span className="font-mono">{accountId}</span>
                        </div>
                    ) : (
                        <div className="rounded-lg border border-border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
                            {t('accountManager.importTokenAccountAuto')}
                        </div>
                    )}
                    <div className="rounded-lg border border-border bg-muted/40 p-3 text-xs text-muted-foreground space-y-1">
                        <p className="font-medium text-foreground">{t('accountManager.importTokenHowTo')}</p>
                        <p>{t('accountManager.importTokenHowToStep1')}</p>
                        <p>{t('accountManager.importTokenHowToStep2')}</p>
                    </div>
                    <div>
                        <label className="block text-sm font-medium mb-1.5">
                            {t('accountManager.importTokenLabel')} <span className="text-destructive">*</span>
                        </label>
                        <textarea
                            className="input-field font-mono text-xs h-28 resize-y"
                            placeholder="userToken..."
                            value={token}
                            onChange={e => setToken(e.target.value)}
                            spellCheck={false}
                        />
                        <p className="mt-1.5 text-xs text-muted-foreground">{t('accountManager.importTokenHint')}</p>
                    </div>
                    <div className="flex justify-end gap-2 pt-2">
                        <button onClick={onClose} className="px-4 py-2 rounded-lg border border-border hover:bg-secondary transition-colors text-sm font-medium">
                            {t('actions.cancel')}
                        </button>
                        <button
                            onClick={onSubmit}
                            disabled={loading || !String(token || '').trim()}
                            className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors text-sm font-medium disabled:opacity-50"
                        >
                            {loading ? t('accountManager.importTokenLoading') : t('accountManager.importTokenAction')}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    )
}
