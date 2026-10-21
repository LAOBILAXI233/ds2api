import { useState } from 'react'

export function useAccountActions({ apiFetch, t, onMessage, onRefresh, config, fetchAccounts, resolveAccountIdentifier, fetchRiskStatus }) {
    const [showAddKey, setShowAddKey] = useState(false)
    const [editingKey, setEditingKey] = useState(null)
    const [showAddAccount, setShowAddAccount] = useState(false)
    const [showEditAccount, setShowEditAccount] = useState(false)
    const [editingAccount, setEditingAccount] = useState(null)
    const [newKey, setNewKey] = useState({ key: '', name: '', remark: '', tools_enabled: false })
    const [copiedKey, setCopiedKey] = useState(null)
    const [newAccount, setNewAccount] = useState({ name: '', remark: '', email: '', mobile: '', password: '', pool_type: 'default' })
    const [editAccount, setEditAccount] = useState({ name: '', remark: '', pool_type: 'default' })
    const [loading, setLoading] = useState(false)
    const [testing, setTesting] = useState({})
    const [testingAll, setTestingAll] = useState(false)
    const [batchProgress, setBatchProgress] = useState({ current: 0, total: 0, results: [] })
    const [sessionCounts, setSessionCounts] = useState({})
    const [deletingSessions, setDeletingSessions] = useState({})
    const [updatingProxy, setUpdatingProxy] = useState({})
    const [togglingEnabled, setTogglingEnabled] = useState({})
    const [togglingAllEnabled, setTogglingAllEnabled] = useState(false)
    const [showElasticPool, setShowElasticPool] = useState(false)
    const [elasticPool, setElasticPool] = useState({ enabled: false, per_pool: false, global_count: 3, default_count: 3, no_tools_count: 3, tools_only_count: 3 })
    const [savingElasticPool, setSavingElasticPool] = useState(false)
    const [showImportToken, setShowImportToken] = useState(false)
    const [importTokenAccountId, setImportTokenAccountId] = useState('')
    const [importTokenValue, setImportTokenValue] = useState('')
    const [importingToken, setImportingToken] = useState(false)
    const [relogining, setRelogining] = useState({})
    const [reloginingAll, setReloginingAll] = useState(false)
    const [clearingRisk, setClearingRisk] = useState(false)

    const openAddKey = () => {
        setEditingKey(null)
        setNewKey({ key: '', name: '', remark: '', tools_enabled: false })
        setShowAddKey(true)
    }

    const openEditKey = (item) => {
        if (!item?.key) return
        setEditingKey(item)
        setNewKey({
            key: item.key || '',
            name: item.name || '',
            remark: item.remark || '',
            tools_enabled: item.tools_enabled || false,
        })
        setShowAddKey(true)
    }

    const closeKeyModal = () => {
        setShowAddKey(false)
        setEditingKey(null)
        setNewKey({ key: '', name: '', remark: '', tools_enabled: false })
    }

    const openAddAccount = () => {
        setShowEditAccount(false)
        setEditingAccount(null)
        setEditAccount({ name: '', remark: '', pool_type: 'default' })
        setNewAccount({ name: '', remark: '', email: '', mobile: '', password: '', pool_type: 'default' })
        setShowAddAccount(true)
    }

    const closeAddAccount = () => {
        setShowAddAccount(false)
        setNewAccount({ name: '', remark: '', email: '', mobile: '', password: '', pool_type: 'default' })
    }

    const openEditAccount = (account) => {
        const identifier = resolveAccountIdentifier(account)
        if (!identifier) {
            onMessage('error', t('accountManager.invalidIdentifier'))
            return
        }
        setShowAddAccount(false)
        setEditingAccount({
            identifier,
        })
        setEditAccount({
            name: account?.name || '',
            remark: account?.remark || '',
            pool_type: account?.pool_type || 'default',
        })
        setShowEditAccount(true)
    }

    const closeEditAccount = () => {
        setShowEditAccount(false)
        setEditingAccount(null)
        setEditAccount({ name: '', remark: '', pool_type: 'default' })
    }

    const addKey = async () => {
        const isEditing = Boolean(editingKey?.key)
        if (!isEditing && !newKey.key.trim()) {
            return
        }
        setLoading(true)
        try {
            const endpoint = isEditing
                ? `/admin/keys/${encodeURIComponent(editingKey.key)}`
                : '/admin/keys'
            const method = isEditing ? 'PUT' : 'POST'
            const payload = isEditing
                ? { name: newKey.name, remark: newKey.remark, tools_enabled: newKey.tools_enabled }
                : { key: newKey.key.trim(), name: newKey.name, remark: newKey.remark, tools_enabled: newKey.tools_enabled }
            if (!isEditing && !payload.key) {
                return
            }
            const res = await apiFetch(endpoint, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            })
            if (res.ok) {
                onMessage('success', isEditing ? t('accountManager.updateKeySuccess') : t('accountManager.addKeySuccess'))
                closeKeyModal()
                onRefresh()
            } else {
                const data = await res.json()
                onMessage('error', data.detail || (isEditing ? t('messages.requestFailed') : t('messages.failedToAdd')))
            }
        } catch (e) {
            onMessage('error', t('messages.networkError'))
        } finally {
            setLoading(false)
        }
    }

    const deleteKey = async (key) => {
        if (!confirm(t('accountManager.deleteKeyConfirm'))) return
        try {
            const res = await apiFetch(`/admin/keys/${encodeURIComponent(key)}`, { method: 'DELETE' })
            if (res.ok) {
                onMessage('success', t('messages.deleted'))
                onRefresh()
            } else {
                onMessage('error', t('messages.deleteFailed'))
            }
        } catch (e) {
            onMessage('error', t('messages.networkError'))
        }
    }

    const addAccount = async () => {
        if (!newAccount.password || (!newAccount.email && !newAccount.mobile)) {
            onMessage('error', t('accountManager.requiredFields'))
            return
        }
        setLoading(true)
        try {
            const res = await apiFetch('/admin/accounts', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newAccount),
            })
            if (res.ok) {
                onMessage('success', t('accountManager.addAccountSuccess'))
                closeAddAccount()
                fetchAccounts(1)
                onRefresh()
            } else {
                const data = await res.json()
                onMessage('error', data.detail || t('messages.failedToAdd'))
            }
        } catch (e) {
            onMessage('error', t('messages.networkError'))
        } finally {
            setLoading(false)
        }
    }

    const updateAccount = async () => {
        const identifier = String(editingAccount?.identifier || '').trim()
        if (!identifier) {
            onMessage('error', t('accountManager.invalidIdentifier'))
            return
        }
        setLoading(true)
        try {
            const res = await apiFetch(`/admin/accounts/${encodeURIComponent(identifier)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(editAccount),
            })
            if (res.ok) {
                onMessage('success', t('accountManager.updateAccountSuccess'))
                closeEditAccount()
                fetchAccounts()
                onRefresh()
            } else {
                const data = await res.json()
                onMessage('error', data.detail || t('messages.requestFailed'))
            }
        } catch (e) {
            onMessage('error', t('messages.networkError'))
        } finally {
            setLoading(false)
        }
    }

    const deleteAccount = async (id) => {
        const identifier = String(id || '').trim()
        if (!identifier) {
            onMessage('error', t('accountManager.invalidIdentifier'))
            return
        }
        if (!confirm(t('accountManager.deleteAccountConfirm'))) return
        try {
            const res = await apiFetch(`/admin/accounts/${encodeURIComponent(identifier)}`, { method: 'DELETE' })
            if (res.ok) {
                onMessage('success', t('messages.deleted'))
                fetchAccounts()
                onRefresh()
            } else {
                onMessage('error', t('messages.deleteFailed'))
            }
        } catch (e) {
            onMessage('error', t('messages.networkError'))
        }
    }

    const testAccount = async (identifier) => {
        const accountID = String(identifier || '').trim()
        if (!accountID) {
            onMessage('error', t('accountManager.invalidIdentifier'))
            return
        }
        setTesting(prev => ({ ...prev, [accountID]: true }))
        try {
            const res = await apiFetch('/admin/accounts/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier: accountID }),
            })
            const data = await res.json()
            
            // 更新会话数
            if (data.session_count !== undefined) {
                setSessionCounts(prev => ({ ...prev, [accountID]: data.session_count }))
            }
            
            const statusMessage = data.success
                ? t('apiTester.testSuccess', { account: accountID, time: data.response_time })
                : `${accountID}: ${data.message}`
            onMessage(data.success ? 'success' : 'error', statusMessage)
            fetchAccounts()
            onRefresh()
        } catch (e) {
            onMessage('error', t('accountManager.testFailed', { error: e.message }))
        } finally {
            setTesting(prev => ({ ...prev, [accountID]: false }))
        }
    }

    const testAllAccounts = async () => {
        if (!confirm(t('accountManager.testAllConfirm'))) return
        const allAccounts = config.accounts || []
        if (allAccounts.length === 0) return

        setTestingAll(true)
        setBatchProgress({ current: 0, total: allAccounts.length, results: [] })

        let successCount = 0
        const results = []

        for (let i = 0; i < allAccounts.length; i++) {
            const acc = allAccounts[i]
            const id = resolveAccountIdentifier(acc)
            if (!id) {
                results.push({ id: '-', success: false, message: t('accountManager.invalidIdentifier') })
                setBatchProgress({ current: i + 1, total: allAccounts.length, results: [...results] })
                continue
            }

            try {
                const res = await apiFetch('/admin/accounts/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ identifier: id }),
                })
                const data = await res.json()
                results.push({ id, success: data.success, message: data.message, time: data.response_time })
                if (data.success) successCount++
            } catch (e) {
                results.push({ id, success: false, message: e.message })
            }

            setBatchProgress({ current: i + 1, total: allAccounts.length, results: [...results] })
        }

        onMessage('success', t('accountManager.testAllCompleted', { success: successCount, total: allAccounts.length }))
        fetchAccounts()
        onRefresh()
        setTestingAll(false)
    }

    const deleteAllSessions = async (identifier) => {
        const accountID = String(identifier || '').trim()
        if (!accountID) {
            onMessage('error', t('accountManager.invalidIdentifier'))
            return
        }
        if (!confirm(t('accountManager.deleteAllSessionsConfirm'))) return
        
        setDeletingSessions(prev => ({ ...prev, [accountID]: true }))
        try {
            const res = await apiFetch('/admin/accounts/sessions/delete-all', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier: accountID }),
            })
            const data = await res.json()
            
            if (data.success) {
                onMessage('success', t('accountManager.deleteAllSessionsSuccess'))
                // 清除会话数显示
                setSessionCounts(prev => {
                    const newCounts = { ...prev }
                    delete newCounts[accountID]
                    return newCounts
                })
            } else {
                onMessage('error', data.message || t('messages.requestFailed'))
            }
        } catch (e) {
            onMessage('error', t('messages.networkError'))
        } finally {
            setDeletingSessions(prev => ({ ...prev, [accountID]: false }))
        }
    }

    const updateAccountProxy = async (identifier, proxyID) => {
        const accountID = String(identifier || '').trim()
        if (!accountID) {
            onMessage('error', t('accountManager.invalidIdentifier'))
            return
        }
        setUpdatingProxy(prev => ({ ...prev, [accountID]: true }))
        try {
            const res = await apiFetch(`/admin/accounts/${encodeURIComponent(accountID)}/proxy`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ proxy_id: proxyID || '' }),
            })
            const data = await res.json()
            if (!res.ok) {
                onMessage('error', data.detail || t('messages.requestFailed'))
                return
            }
            onMessage('success', t('accountManager.proxyUpdateSuccess'))
            fetchAccounts()
            onRefresh()
        } catch (_err) {
            onMessage('error', t('messages.networkError'))
        } finally {
            setUpdatingProxy(prev => ({ ...prev, [accountID]: false }))
        }
    }

    const toggleAccountEnabled = async (identifier, enabled) => {
        const accountID = String(identifier || '').trim()
        if (!accountID) {
            onMessage('error', t('accountManager.invalidIdentifier'))
            return
        }
        if (!enabled && !confirm(t('accountManager.disableAccountConfirm'))) return
        setTogglingEnabled(prev => ({ ...prev, [accountID]: true }))
        try {
            const res = await apiFetch(`/admin/accounts/${encodeURIComponent(accountID)}/enabled`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled }),
            })
            const data = await res.json()
            if (!res.ok) {
                onMessage('error', data.detail || t('messages.requestFailed'))
                return
            }
            onMessage('success', enabled ? t('accountManager.enableAccountSuccess') : t('accountManager.disableAccountSuccess'))
            fetchAccounts()
            onRefresh()
        } catch (_err) {
            onMessage('error', t('messages.networkError'))
        } finally {
            setTogglingEnabled(prev => ({ ...prev, [accountID]: false }))
        }
    }

    const toggleAllAccountsEnabled = async (enabled) => {
        if (!enabled && !confirm(t('accountManager.disableAllAccountsConfirm'))) return
        const allAccounts = config.accounts || []
        if (allAccounts.length === 0) return

        setTogglingAllEnabled(true)
        try {
            const res = await apiFetch('/admin/accounts/enabled/batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled }),
            })
            const data = await res.json()
            if (!res.ok) {
                onMessage('error', data.detail || t('messages.requestFailed'))
                return
            }
            onMessage(
                'success',
                enabled
                    ? t('accountManager.enableAllAccountsSuccess', { success: data.total, total: data.total })
                    : t('accountManager.disableAllAccountsSuccess', { success: data.total, total: data.total })
            )
            fetchAccounts()
            onRefresh()
        } catch (_err) {
            onMessage('error', t('messages.networkError'))
        } finally {
            setTogglingAllEnabled(false)
        }
    }

    // ---- Session token import -------------------------------------------------
    // The password sign-in path is the one upstream guards with its risk layer
    // (RISK_DEVICE_DETECTED). Pasting a token from an already signed-in browser
    // skips that call entirely, which is what makes an account usable again
    // while sign-ins are being refused.

    const openImportToken = (account) => {
        setImportTokenAccountId(resolveAccountIdentifier(account) || '')
        setImportTokenValue('')
        setShowImportToken(true)
    }

    const closeImportToken = () => {
        setShowImportToken(false)
        setImportTokenAccountId('')
        setImportTokenValue('')
    }

    const submitImportToken = async () => {
        const token = String(importTokenValue || '').trim()
        if (!token) return
        setImportingToken(true)
        try {
            // Send the account the operator opened the dialog for: upstream masks
            // the address it reports back, so the target is the only reliable way
            // to tell "re-token this account" from "add a new one".
            const payload = { token }
            if (importTokenAccountId) payload.identifier = importTokenAccountId
            const res = await apiFetch('/admin/accounts/import-token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            })
            const data = await res.json().catch(() => ({}))
            if (!res.ok) {
                onMessage('error', data.detail || t('messages.requestFailed'))
                return
            }
            onMessage('success', t('accountManager.importTokenSuccess', { identifier: data.identifier || importTokenAccountId }))
            closeImportToken()
            fetchAccounts()
            onRefresh()
        } catch (_err) {
            onMessage('error', t('messages.networkError'))
        } finally {
            setImportingToken(false)
        }
    }

    // ---- Manual re-login -----------------------------------------------------

    // Lift the sign-in breaker so the next attempt actually reaches upstream.
    // Worth doing right after the accounts were pointed at a different exit IP.
    const clearRiskCooldown = async () => {
        setClearingRisk(true)
        try {
            const res = await apiFetch('/admin/signin-risk/clear', { method: 'POST' })
            const data = await res.json().catch(() => ({}))
            if (!res.ok) {
                onMessage('error', data.detail || t('messages.requestFailed'))
                return
            }
            onMessage('success', t('accountManager.riskCooldownCleared'))
            fetchRiskStatus?.()
        } catch (_err) {
            onMessage('error', t('messages.networkError'))
        } finally {
            setClearingRisk(false)
        }
    }

    const reloginAccount = async (identifier, options = {}) => {
        const silent = Boolean(options.silent)
        const accountID = String(identifier || '').trim()
        if (!accountID) {
            if (!silent) onMessage('error', t('accountManager.invalidIdentifier'))
            return false
        }
        setRelogining(prev => ({ ...prev, [accountID]: true }))
        try {
            const res = await apiFetch(`/admin/accounts/${encodeURIComponent(accountID)}/relogin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ clear: true }),
            })
            const data = await res.json().catch(() => ({}))
            if (!res.ok) {
                if (!silent) {
                    onMessage('error', data.risk_cooldown
                        ? t('accountManager.reloginRiskCooldown')
                        : (data.detail || t('messages.requestFailed')))
                }
                return false
            }
            if (!silent) onMessage('success', t('accountManager.reloginSuccess', { identifier: accountID }))
            return true
        } catch (_err) {
            if (!silent) onMessage('error', t('messages.networkError'))
            return false
        } finally {
            setRelogining(prev => ({ ...prev, [accountID]: false }))
        }
    }

    // Re-sign-in every account that currently has no usable session, one at a
    // time, and STOP at the first refusal: hammering the sign-in endpoint is what
    // turns a single refusal into a persistent risk block.
    const reloginUnavailableAccounts = async () => {
        const all = config.accounts || []
        const targets = all.filter(acc => {
            const id = resolveAccountIdentifier(acc)
            if (!id || acc.enabled === false || acc.banned === true || acc.muted === true) return false
            return Boolean(acc.refresh_error) || !acc.has_token
        })
        if (targets.length === 0) {
            onMessage('success', t('accountManager.reloginNoneNeeded'))
            return
        }
        if (!confirm(t('accountManager.reloginAllConfirm', { count: targets.length }))) return
        setReloginingAll(true)
        let success = 0
        let stopped = false
        try {
            for (const acc of targets) {
                const id = resolveAccountIdentifier(acc)
                if (await reloginAccount(id, { silent: true })) {
                    success++
                    continue
                }
                stopped = true
                break
            }
        } finally {
            setReloginingAll(false)
            fetchAccounts()
            onRefresh()
        }
        if (stopped) {
            onMessage('error', t('accountManager.reloginAllStopped', { success, total: targets.length }))
            return
        }
        onMessage('success', t('accountManager.reloginAllCompleted', { success, total: targets.length }))
    }

    const openElasticPool = () => {
        const ep = config?.elastic_pool || {}
        setElasticPool({
            enabled: ep.enabled || false,
            per_pool: ep.per_pool || false,
            global_count: ep.global_count ?? 3,
            default_count: ep.default_count ?? 3,
            no_tools_count: ep.no_tools_count ?? 3,
            tools_only_count: ep.tools_only_count ?? 3,
        })
        setShowElasticPool(true)
    }

    const closeElasticPool = () => {
        setShowElasticPool(false)
    }

    const saveElasticPool = async () => {
        const parseCount = (value) => {
            if (value === '') {
                return null
            }
            const n = Number(value)
            if (Number.isNaN(n) || n < 0) {
                return null
            }
            return n
        }

        const gc = parseCount(elasticPool.global_count)
        const dc = parseCount(elasticPool.default_count)
        const nc = parseCount(elasticPool.no_tools_count)
        const tc = parseCount(elasticPool.tools_only_count)

        if (gc === null || dc === null || nc === null || tc === null) {
            return t('accountManager.elasticPoolCountInvalid')
        }

        const payload = {
            enabled: elasticPool.enabled,
            per_pool: elasticPool.per_pool,
            global_count: gc,
            default_count: dc,
            no_tools_count: nc,
            tools_only_count: tc,
        }
        if (!payload.per_pool) {
            payload.default_count = gc
            payload.no_tools_count = gc
            payload.tools_only_count = gc
        }

        setSavingElasticPool(true)
        try {
            const res = await apiFetch('/admin/accounts/elastic-pool', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            })
            const data = await res.json()
            if (!res.ok) {
                return data.detail || t('messages.requestFailed')
            }
            onMessage('success', t('accountManager.elasticPoolSaveSuccess'))
            await fetchAccounts()
            await onRefresh()
            setShowElasticPool(false)
            return null
        } catch (_err) {
            return t('messages.networkError')
        } finally {
            setSavingElasticPool(false)
        }
    }

    return {
        showAddKey,
        openAddKey,
        openEditKey,
        closeKeyModal,
        editingKey,
        showAddAccount,
        openAddAccount,
        closeAddAccount,
        showEditAccount,
        editingAccount,
        editAccount,
        setEditAccount,
        openEditAccount,
        closeEditAccount,
        newKey,
        setNewKey,
        copiedKey,
        setCopiedKey,
        newAccount,
        setNewAccount,
        loading,
        testing,
        testingAll,
        batchProgress,
        sessionCounts,
        deletingSessions,
        updatingProxy,
        togglingEnabled,
        togglingAllEnabled,
        addKey,
        deleteKey,
        addAccount,
        updateAccount,
        deleteAccount,
        testAccount,
        testAllAccounts,
        deleteAllSessions,
        updateAccountProxy,
        toggleAccountEnabled,
        toggleAllAccountsEnabled,
        showElasticPool,
        openElasticPool,
        closeElasticPool,
        elasticPool,
        setElasticPool,
        savingElasticPool,
        saveElasticPool,
        showImportToken,
        openImportToken,
        closeImportToken,
        importTokenAccountId,
        importTokenValue,
        setImportTokenValue,
        importingToken,
        submitImportToken,
        relogining,
        reloginingAll,
        reloginAccount,
        reloginUnavailableAccounts,
        clearingRisk,
        clearRiskCooldown,
    }
}
