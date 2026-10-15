import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  AlertOctagon,
  ArrowUpRight,
  Bell,
  Check,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  Clock3,
  Database,
  Github,
  LoaderCircle,
  LockKeyhole,
  MessageSquare,
  Radio,
  RefreshCw,
  Search,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Sun,
  Thermometer,
  X,
  Zap,
} from 'lucide-react'

const API = '/api'
const USER_ID = 'demo-user'

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers,
    },
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    throw new Error(payload.detail || payload.message || `Request failed (${response.status})`)
  }
  return payload
}

function cx(...values) {
  return values.filter(Boolean).join(' ')
}

function formatTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date)
}

function formatModelScore(value) {
  const score = Number(value)
  return value === null || value === undefined || !Number.isFinite(score)
    ? 'Unavailable'
    : `${score.toFixed(1)}/100`
}

function prettyName(value = '') {
  return value.replaceAll('_', ' ')
}

function TrustBadge({ zone }) {
  const level = (zone || 'unknown').toLowerCase()
  return <span className={`trust-badge trust-${level}`}>{zone || 'NOT SET'}</span>
}

function ClassificationBadge({ classification }) {
  const known = ['HIGH_TRUST', 'LOW_TRUST'].includes(classification)
  return (
    <span className={cx(
      'classification-badge',
      classification === 'HIGH_TRUST' && 'classification-high',
      classification === 'LOW_TRUST' && 'classification-low',
      !known && 'classification-unknown',
    )}>
      {known ? classification : 'UNAVAILABLE'}
    </span>
  )
}

function StatusDot({ online }) {
  return (
    <span className={cx('status-dot', online ? 'status-dot-on' : 'status-dot-off')} />
  )
}

function ActionStatus({ status }) {
  const normalized = (status || 'completed').toLowerCase()
  const tone = normalized === 'pending_approval'
    ? 'pending'
    : ['executed', 'completed'].includes(normalized)
      ? 'success'
      : ['rejected', 'failed', 'blocked', 'stale', 'expired'].includes(normalized)
        ? 'error'
        : 'neutral'
  return (
    <span className={`action-status action-status-${tone}`} role="status">
      <i />
      {prettyName(normalized)}
    </span>
  )
}

function ProvenanceDetails({ entries }) {
  if (!entries?.length) return null
  return (
    <details className="provenance-details">
      <summary>Tool provenance <span>{entries.length}</span></summary>
      <ol>
        {entries.map((entry, index) => {
          const sources = entry.inherited_sources || []
          const argumentFields = entry.argument_fields || []
          const resultFields = entry.result_fields || []
          return (
            <li key={`${entry.tool_call_id || entry.action_id || entry.tool_name}-${index}`}>
              <div className="provenance-title">
                <strong>{prettyName(entry.tool_name || 'tool')}</strong>
                <ActionStatus status={entry.status} />
              </div>
              {entry.tool_call_id && <code className="provenance-call-id">{entry.tool_call_id}</code>}
              {(argumentFields.length > 0 || resultFields.length > 0) && (
                <p>
                  {argumentFields.length > 0 && <span><b>Input fields</b> {argumentFields.join(', ')}</span>}
                  {resultFields.length > 0 && <span><b>Output fields</b> {resultFields.join(', ')}</span>}
                </p>
              )}
              {sources.length > 0 && (
                <div className="provenance-sources">
                  <b>Inherited from</b>
                  {sources.map((source) => (
                    <span key={`${source.tool_call_id}-${source.source_tool}`}>
                      {prettyName(source.source_tool || 'source')}
                      {source.tool_call_id ? ` · ${source.tool_call_id}` : ''}
                      {source.affected_fields?.length ? ` · ${source.affected_fields.join(', ')}` : ''}
                    </span>
                  ))}
                </div>
              )}
            </li>
          )
        })}
      </ol>
    </details>
  )
}

function App() {
  const [activeView, setActiveView] = useState('overview')
  const [health, setHealth] = useState('checking')
  const [socketStatus, setSocketStatus] = useState('connecting')
  const [integrations, setIntegrations] = useState([])
  const [approvals, setApprovals] = useState([])
  const [events, setEvents] = useState([])
  const [dataLoaded, setDataLoaded] = useState(false)
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: 'ShadowGuard is online. Ask me to inspect an integration or perform a database action.',
      time: new Date().toISOString(),
    },
  ])
  const [sessionId, setSessionId] = useState('')
  const [sessionState, setSessionState] = useState('CLEAN')
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [workingApproval, setWorkingApproval] = useState('')
  const [savingIntegration, setSavingIntegration] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [integrationFilter, setIntegrationFilter] = useState('ALL')
  const [eventTypeFilter, setEventTypeFilter] = useState('ALL')
  const [confirmAction, setConfirmAction] = useState(null)
  const [toast, setToast] = useState('')
  const chatEndRef = useRef(null)

  const refreshDashboard = useCallback(async () => {
    const results = await Promise.allSettled([
      request('/health'),
      request('/integrations'),
      request('/approvals/pending'),
      request('/security/events'),
    ])
    const [healthResult, integrationsResult, approvalsResult, eventsResult] = results
    setHealth(healthResult.status === 'fulfilled' ? 'online' : 'offline')
    if (integrationsResult.status === 'fulfilled') {
      setIntegrations(integrationsResult.value.tools || [])
    }
    if (approvalsResult.status === 'fulfilled') {
      setApprovals(approvalsResult.value.approvals || [])
    }
    if (eventsResult.status === 'fulfilled') {
      setEvents(eventsResult.value.events || [])
    }
    setDataLoaded(true)
    const failed = results.find((result) => result.status === 'rejected')
    if (failed) setError(failed.reason.message)
    else setError('')
  }, [])

  useEffect(() => {
    refreshDashboard()
    const interval = window.setInterval(refreshDashboard, 12000)
    return () => window.clearInterval(interval)
  }, [refreshDashboard])

  useEffect(() => {
    let socket
    let retryTimer
    let disposed = false
    let attempts = 0

    const connect = () => {
      if (disposed) return
      const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${scheme}//${window.location.host}/ws`)
      socket.onopen = () => {
        attempts = 0
        setSocketStatus('live')
      }
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data)
          setEvents((current) => {
            if (current.some((item) => item.event_id === event.event_id)) return current
            return [...current, event].slice(-100)
          })
          if (event.event_type === 'approval_required') refreshDashboard()
        } catch {
          setError('Received an unreadable event from the live feed.')
        }
      }
      socket.onerror = () => socket.close()
      socket.onclose = () => {
        setSocketStatus('reconnecting')
        if (!disposed) {
          const delay = Math.min(1000 * 2 ** attempts, 10000)
          attempts += 1
          retryTimer = window.setTimeout(connect, delay)
        }
      }
    }

    connect()
    return () => {
      disposed = true
      window.clearTimeout(retryTimer)
      socket?.close()
    }
  }, [refreshDashboard])

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [messages])

  const pendingCount = approvals.length
  const blockedCount = useMemo(
    () => events.filter((event) =>
      ['taint_blocked', 'security_error'].includes(event.event_type),
    ).length,
    [events],
  )
  const normalizedSearch = searchQuery.trim().toLowerCase()
  const filteredIntegrations = integrations.filter((integration) => {
    const matchesFilter = integrationFilter === 'ALL'
      || integration.trust_classification === integrationFilter
    const matchesSearch = !normalizedSearch
      || `${integration.name} ${integration.description || ''} ${integration.trust_zone || ''} ${integration.trust_classification || ''} ${integration.ml_classification || ''}`
        .toLowerCase().includes(normalizedSearch)
    return matchesFilter && matchesSearch
  })
  const filteredApprovals = approvals.filter((approval) =>
    !normalizedSearch
    || `${approval.tool_name || ''} ${approval.sql_text || ''} ${approval.user_objective || ''} ${approval.target_resource || ''} ${approval.operation || ''} ${approval.staged_json || ''}`
      .toLowerCase().includes(normalizedSearch),
  )
  const filteredEvents = [...events].reverse().filter((event) => {
    const detailText = JSON.stringify(event.details || {})
    const matchesSearch = !normalizedSearch
      || `${event.event_type || ''} ${event.summary || ''} ${event.tool_name || ''} ${event.policy_code || ''} ${detailText}`
        .toLowerCase().includes(normalizedSearch)
    const matchesType = eventTypeFilter === 'ALL'
      || (eventTypeFilter === 'BLOCKED' && ['taint_blocked', 'security_error'].includes(event.event_type))
      || (eventTypeFilter === 'APPROVAL' && event.event_type?.includes('approval'))
      || (eventTypeFilter === 'INTENT' && event.event_type?.toLowerCase().includes('intent'))
      || (eventTypeFilter === 'TRUST' && event.event_type?.toLowerCase().includes('trust'))
      || (eventTypeFilter === 'OTHER'
        && !['taint_blocked', 'security_error'].includes(event.event_type)
        && !event.event_type?.includes('approval')
        && !event.event_type?.toLowerCase().includes('intent')
        && !event.event_type?.toLowerCase().includes('trust'))
    return matchesSearch && matchesType
  })

  function startNewSession() {
    setSessionId('')
    setSessionState('CLEAN')
    setMessages([{
      role: 'assistant',
      content: 'A new isolated session is ready. The backend will create it when you send your next request.',
      time: new Date().toISOString(),
    }])
    setToast('Chat reset · backend session starts with your next request')
  }

  function requestApprovalDecision(approval, decision, options = {}) {
    setConfirmAction({ approval, decision, options })
  }

  async function confirmApprovalDecision(operatorToken) {
    if (!confirmAction) return
    const { approval, decision, options } = confirmAction
    setConfirmAction(null)
    await decideApproval(approval, decision, options, operatorToken)
  }

  useEffect(() => {
    if (!toast) return undefined
    const timer = window.setTimeout(() => setToast(''), 3200)
    return () => window.clearTimeout(timer)
  }, [toast])

  async function sendMessage(text = draft) {
    const message = text.trim()
    if (!message || busy) return
    setError('')
    setBusy(true)
    setDraft('')
    setMessages((current) => [
      ...current,
      { role: 'user', content: message, time: new Date().toISOString() },
    ])
    try {
      const result = await request('/chat', {
        method: 'POST',
        body: JSON.stringify({
          message,
          session_id: sessionId || null,
          user_id: USER_ID,
          authorized_capabilities: ['read', 'write', 'delete'],
        }),
      })
      setSessionId(result.session_id)
      setSessionState(result.state || 'CLEAN')
      setMessages((current) => [
        ...current,
        {
          role: 'assistant',
          content: result.response,
          time: new Date().toISOString(),
          actionStatus: result.status,
          approvalId: result.approval_id,
          provenance: result.provenance || [],
        },
      ])
      refreshDashboard()
    } catch (requestError) {
      setError(requestError.message)
      setMessages((current) => [
        ...current,
        {
          role: 'assistant',
          content: `The request could not be completed: ${requestError.message}`,
          time: new Date().toISOString(),
          failed: true,
        },
      ])
    } finally {
      setBusy(false)
    }
  }

  async function runScenario(name) {
    setError('')
    setBusy(true)
    try {
      const result = await request(`/demo/scenario-${name}`, { method: 'POST' })
      setSessionId(result.session_id)
      setSessionState(result.state || 'CLEAN')
      setMessages((current) => [
        ...current,
        {
          role: 'assistant',
          content: `Scenario ${name.toUpperCase()} completed. Session ${result.state}. Result: ${JSON.stringify(result.result)}`,
          time: new Date().toISOString(),
        },
      ])
      await refreshDashboard()
      setActiveView('overview')
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setBusy(false)
    }
  }

  async function decideApproval(approval, decision, options = {}, operatorToken) {
    setError('')
    setWorkingApproval(approval.id)
    try {
      const result = await request(`/approvals/${approval.id}/decision`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${operatorToken}` },
        body: JSON.stringify({
          decision,
          session_id: approval.session_id,
          user_id: approval.user_id || USER_ID,
          approval_kind: options.approvalKind || 'one_time',
          grant_duration_seconds: options.grantDurationSeconds || null,
        }),
      })
      if (result.response) {
        setMessages((current) => [...current, {
          role: 'assistant',
          content: result.response,
          time: new Date().toISOString(),
          actionStatus: result.status,
          approvalId: approval.id,
          provenance: result.provenance || [],
        }])
      } else {
        setMessages((current) => [...current, {
          role: 'assistant',
          content: result.message || 'The approval decision could not be completed.',
          time: new Date().toISOString(),
          actionStatus: result.status || 'failed',
          approvalId: approval.id,
          provenance: result.provenance || [],
          failed: result.isError || result.status !== 'REJECTED',
        }])
      }
      await refreshDashboard()
      if (result.isError && result.status !== 'REJECTED') {
        setError(result.message || 'The approval decision could not be completed.')
      } else if (result.continuation_error) {
        setError(`Action decision saved, but the assistant could not resume: ${result.continuation_error}`)
      }
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setWorkingApproval('')
    }
  }

  async function updateTrustZone(integration, trustZone) {
    setError('')
    setSavingIntegration(integration.name)
    try {
      const result = await request('/integrations', {
        method: 'POST',
        body: JSON.stringify({ name: integration.name, trust_zone: trustZone }),
      })
      setIntegrations((current) =>
        current.map((item) => item.name === integration.name ? result.tool : item),
      )
      setToast(`Trust zone saved for ${prettyName(integration.name)}`)
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setSavingIntegration('')
    }
  }

  const navItems = [
    { id: 'overview', label: 'Command center', icon: Activity },
    { id: 'approvals', label: 'Approvals', icon: LockKeyhole, count: pendingCount },
    { id: 'integrations', label: 'Integrations', icon: Zap },
    { id: 'events', label: 'Event stream', icon: Radio },
  ]

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" onClick={() => setActiveView('overview')}>
          <span className="brand-mark"><Shield size={20} strokeWidth={2.2} /></span>
          <span className="brand-copy">
            <strong>ShadowGuard</strong>
            <small>SECURITY GATEWAY</small>
          </span>
        </a>

        <div className="workspace-switch">
          <span className="workspace-icon">S</span>
          <span><strong>ShadowGuard Demo</strong><small>Local workspace</small></span>
          <ChevronDown size={15} />
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav className="main-nav" aria-label="Main navigation">
          {navItems.map(({ id, label, icon: Icon, count }) => (
            <button
              className={cx('nav-item', activeView === id && 'nav-item-active')}
              key={id}
              title={label}
              aria-current={activeView === id ? 'page' : undefined}
              onClick={() => setActiveView(id)}
            >
              <Icon size={17} />
              <span>{label}</span>
              {count !== undefined && <span className="nav-count">{count}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-help">
            <div className="help-icon"><CircleHelp size={17} /></div>
            <div><strong>Security first</strong><p>Tool calls are inspected before they reach integrations.</p></div>
          </div>
          <div className="profile-row">
            <div className="avatar">DG</div>
            <div><strong>Demo operator</strong><small>Administrator</small></div>
            <button className="icon-button profile-more" aria-label="Operator profile options"><ChevronDown size={16} /></button>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <svg className="ambient-ribbon" viewBox="0 0 520 300" fill="none" aria-hidden="true">
          <defs>
            <linearGradient id="ribbon-pearl" x1="48" y1="220" x2="452" y2="70" gradientUnits="userSpaceOnUse">
              <stop stopColor="#A7F3E5" stopOpacity=".05" />
              <stop offset=".48" stopColor="#B9B2FF" stopOpacity=".78" />
              <stop offset="1" stopColor="#9AD4FF" stopOpacity=".2" />
            </linearGradient>
            <linearGradient id="ribbon-glow" x1="110" y1="244" x2="464" y2="66" gradientUnits="userSpaceOnUse">
              <stop stopColor="#8DE5D6" stopOpacity=".12" />
              <stop offset=".55" stopColor="#D1B9FF" stopOpacity=".86" />
              <stop offset="1" stopColor="#A4C8FF" stopOpacity=".1" />
            </linearGradient>
            <filter id="ribbon-blur" x="0" y="0" width="520" height="300" filterUnits="userSpaceOnUse">
              <feGaussianBlur stdDeviation="8" />
            </filter>
          </defs>
          <path d="M66 228C154 66 257 32 362 85c70 36 38 112-26 87-47-18-18-70 30-64 49 7 89 51 75 91-16 45-81 55-142 35" stroke="url(#ribbon-glow)" strokeWidth="26" strokeLinecap="round" filter="url(#ribbon-blur)" />
          <path d="M66 228C154 66 257 32 362 85c70 36 38 112-26 87-47-18-18-70 30-64 49 7 89 51 75 91-16 45-81 55-142 35" stroke="url(#ribbon-pearl)" strokeWidth="9" strokeLinecap="round" />
          <path d="M108 248c86-87 155-158 231-150 44 5 47 45 18 54-26 8-44-18-29-35" stroke="white" strokeOpacity=".52" strokeWidth="2" strokeLinecap="round" />
        </svg>
        <header className="topbar">
          <div className="topbar-right">
            <label className="global-search">
              <Search size={15} aria-hidden="true" />
              <input
                aria-label={`Search ${navItems.find((item) => item.id === activeView)?.label || 'workspace'}`}
                placeholder="Search tools, events, or actions..."
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
              />
              {searchQuery && (
                <button type="button" onClick={() => setSearchQuery('')} aria-label="Clear search">
                  <X size={14} />
                </button>
              )}
            </label>
            <div className="connection-state">
              <StatusDot online={health === 'online'} />
              <span>{health === 'online' ? 'Gateway operational' : health === 'checking' ? 'Gateway connecting' : 'API offline'}</span>
            </div>
            <button className="topbar-icon-button notification-button" type="button" aria-label="Notifications">
              <Bell size={16} />
              {pendingCount > 0 && <i aria-hidden="true" />}
            </button>
            <button className="topbar-icon-button theme-button" type="button" aria-label="Theme">
              <Sun size={16} />
            </button>
            <div className="top-avatar">DG</div>
          </div>
        </header>

        <div className="page-content">
          {error && (
            <div className="error-banner" role="alert">
              <AlertOctagon size={17} /><span>{error}</span>
              <button className="icon-button" onClick={() => setError('')} aria-label="Dismiss error"><X size={16} /></button>
            </div>
          )}
          {toast && <div className="toast-notice" role="status"><CheckCircle2 size={16} />{toast}</div>}

          {activeView === 'overview' && (
            <>
              <div className="page-heading">
                <div>
                  <div className="eyebrow"><span className="eyebrow-line" /> REAL-TIME MONITORING</div>
                  <h1>Good afternoon, operator <span className="heading-spark" aria-hidden="true">👋</span></h1>
                  <p>Monitor your AI agents, integrations, and protected actions in one place.</p>
                </div>
                <div className="heading-actions">
                  <button className="button-secondary" onClick={startNewSession} disabled={busy}>
                    <RefreshCw size={14} /> Clean session
                  </button>
                  <button className="button-secondary button-primary" onClick={() => runScenario('a')} disabled={busy}>
                    <Sparkles size={15} /> Run demo scenario
                  </button>
                </div>
              </div>

              <section className="metric-grid" aria-label="Security summary">
                <MetricCard icon={ShieldCheck} label="Gateway status" value={health === 'online' ? 'Protected' : health === 'checking' ? 'Connecting' : 'Offline'} foot={health === 'online' ? 'Policy enforcement active' : 'Gateway health unavailable'} tone="green" />
                <MetricCard icon={LockKeyhole} label="Pending approvals" value={pendingCount} foot={pendingCount ? 'Needs operator review' : 'No actions waiting'} tone="amber" />
                <MetricCard icon={ShieldAlert} label="Blocked decisions" value={blockedCount} foot="In the recent gateway event feed" tone="red" />
                <MetricCard icon={Radio} label="Live event stream" value={socketStatus === 'live' ? 'Connected' : socketStatus === 'connecting' || socketStatus === 'reconnecting' ? 'Reconnecting' : 'Offline'} foot={socketStatus === 'live' ? `${events.length} recent events` : 'Live updates unavailable'} tone="violet" />
              </section>

              <div className="dashboard-grid">
                <section className="card chat-card">
                  <div className="card-heading">
                    <div className="heading-icon mint-icon"><MessageSquare size={17} /></div>
                    <div><h2>Agent console</h2><p>Send a request through the guarded gateway</p></div>
                    <span className={cx('live-tag', socketStatus !== 'live' && 'live-tag-offline')}>
                      <i /> {socketStatus === 'live' ? 'LIVE' : socketStatus === 'connecting' || socketStatus === 'reconnecting' ? 'RECONNECTING' : 'OFFLINE'}
                    </span>
                  </div>
                  <div className="chat-messages">
                    {messages.map((message, index) => (
                      <div className={cx('message-row', message.role === 'user' && 'message-user')} key={`${message.time}-${index}`}>
                        <div className={cx('message-avatar', message.role === 'user' ? 'user-avatar' : 'assistant-avatar')}>
                          {message.role === 'user' ? 'DG' : <Shield size={15} />}
                        </div>
                        <div className="message-body">
                          <div className="message-meta">
                            <strong>{message.role === 'user' ? 'You' : 'ShadowGuard AI'}</strong>
                            <time>{formatTime(message.time)}</time>
                          </div>
                          <p className={message.failed ? 'message-failed' : ''}>{message.content}</p>
                          {message.actionStatus && (
                            <div className="message-action-meta">
                              <ActionStatus status={message.actionStatus} />
                              {message.approvalId && <span>Approval {message.approvalId}</span>}
                            </div>
                          )}
                          <ProvenanceDetails entries={message.provenance} />
                        </div>
                      </div>
                    ))}
                    {busy && <div className="typing"><LoaderCircle size={14} className="spin" /> Checking policy and running request…</div>}
                    <div ref={chatEndRef} />
                  </div>
                  <div className="suggestions">
                    <button onClick={() => sendMessage('Check the weather in Seattle')}>Check weather <ArrowUpRight size={12} /></button>
                    <button onClick={() => sendMessage('Delete user with id 1')}>Review a database change <ArrowUpRight size={12} /></button>
                  </div>
                  <form className="chat-composer" onSubmit={(event) => { event.preventDefault(); sendMessage() }}>
                    <input
                      aria-label="Message ShadowGuard AI"
                      value={draft}
                      onChange={(event) => setDraft(event.target.value)}
                      placeholder="Ask ShadowGuard to do something…"
                      disabled={busy}
                    />
                    <span className="composer-shortcut">Enter ↵</span>
                    <button className="send-button" type="submit" disabled={busy || !draft.trim()} aria-label="Send message">
                      {busy ? <LoaderCircle size={16} className="spin" /> : <Send size={16} />}
                    </button>
                  </form>
                  <div className="composer-foot"><LockKeyhole size={12} /> All tool calls pass through policy inspection</div>
                </section>

                <section className="card posture-card">
                  <div className="card-heading">
                    <div className="heading-icon blue-icon"><ShieldCheck size={17} /></div>
                    <div><h2>Trust posture</h2><p>Registered tools and security classifications</p></div>
                    <button className="text-link" onClick={() => setActiveView('integrations')}>Manage <ArrowUpRight size={13} /></button>
                  </div>
                  <div className="posture-summary">
                    <div className="posture-score"><span>{integrations.length || '—'}</span><small>TOOLS</small></div>
                    <div><strong>Gateway is enforcing trust boundaries</strong><p>Low-trust data taints a session and blocks subsequent high-trust access.</p></div>
                  </div>
                  <div className="integration-list">
                    {integrations.map((integration) => (
                      <div className="integration-row" key={integration.name}>
                        <IntegrationIcon name={integration.name} />
                        <div className="integration-info"><strong>{prettyName(integration.name)}</strong><small>{integration.enabled ? 'Enabled at gateway' : 'Disabled'}</small></div>
                        <div className="posture-classification">
                          <ClassificationBadge classification={integration.trust_classification} />
                          <small>Zone <TrustBadge zone={integration.trust_zone} /></small>
                        </div>
                      </div>
                    ))}
                    {!integrations.length && <EmptyState title={dataLoaded ? 'No integrations loaded' : 'Loading integrations'} detail={dataLoaded ? 'Check that the API is running, then refresh.' : 'Fetching registered tools and trust evaluations.'} />}
                  </div>
                  <div className="posture-note"><LockKeyhole size={14} /><span>Destructive database changes require approval. High-trust actions in a tainted session are shown for review before execution.</span></div>
                </section>
              </div>

              <div className="lower-grid">
                <EventPanel events={filteredEvents.slice(0, 5)} onOpen={() => setActiveView('events')} socketStatus={socketStatus} />
                <section className="card quick-actions">
                  <div className="card-heading">
                    <div className="heading-icon amber-icon"><Zap size={17} /></div>
                    <div><h2>Scenario lab</h2><p>Try the guarded demo flows</p></div>
                  </div>
                  <button className="scenario-item" onClick={() => runScenario('a')} disabled={busy}>
                    <span className="scenario-number">01</span>
                    <span><strong>Authorized mistake</strong><small>Stage destructive SQL for approval</small></span>
                    <ArrowUpRight size={15} />
                  </button>
                  <button className="scenario-item" onClick={() => runScenario('b')} disabled={busy}>
                    <span className="scenario-number">02</span>
                    <span><strong>Cross-contamination block</strong><small>Low-trust data blocks a protected call</small></span>
                    <ArrowUpRight size={15} />
                  </button>
                </section>
              </div>
            </>
          )}

          {activeView === 'approvals' && (
            <PageSection
              eyebrow="HUMAN IN THE LOOP"
              title="Approval queue"
              subtitle="Review protected actions and taint sources before allowing them to run."
              icon={LockKeyhole}
              count={pendingCount}
            >
              {filteredApprovals.length ? (
                <div className="approval-list">
                  {filteredApprovals.map((approval) => (
                    <ApprovalCard
                      key={approval.id}
                      approval={approval}
                      busy={workingApproval === approval.id}
                      onDecision={(decision, options) => requestApprovalDecision(approval, decision, options)}
                    />
                  ))}
                </div>
              ) : approvals.length
                ? <EmptyState title="No matching approvals" detail="Try a different search term." large />
                : <EmptyState title={dataLoaded ? 'All clear' : 'Loading approval queue'} detail={dataLoaded ? 'There are no protected actions waiting for approval.' : 'Checking for pending protected actions.'} large />}
            </PageSection>
          )}

          {activeView === 'integrations' && (
            <PageSection
              eyebrow="TRUST CONFIGURATION"
              title="Integrations"
              subtitle="Assign a trust zone to each tool. High-trust resources are protected from tainted sessions."
              icon={Zap}
            >
              <div className="filter-toolbar" role="group" aria-label="Filter integrations by model classification">
                {['ALL', 'HIGH_TRUST', 'LOW_TRUST'].map((filter) => (
                  <button
                    key={filter}
                    className={cx('filter-chip', integrationFilter === filter && 'filter-chip-active')}
                    aria-pressed={integrationFilter === filter}
                    onClick={() => setIntegrationFilter(filter)}
                  >
                    {filter === 'ALL' ? 'All integrations' : filter.replace('_', ' ')}
                    {filter === 'ALL' && <span>{integrations.length}</span>}
                  </button>
                ))}
              </div>
              <div className="integration-cards">
                {filteredIntegrations.map((integration) => (
                  <IntegrationCard
                    key={integration.name}
                    integration={integration}
                    saving={savingIntegration === integration.name}
                    onChange={(zone) => updateTrustZone(integration, zone)}
                  />
                ))}
                {!filteredIntegrations.length && <EmptyState title={integrations.length ? 'No matching integrations' : dataLoaded ? 'No integrations available' : 'Loading integrations'} detail={integrations.length ? 'Try a different filter or search term.' : dataLoaded ? 'The backend did not return any registered tools.' : 'Fetching registered tools and trust evaluations.'} large />}
              </div>
              <div className="info-banner"><LockKeyhole size={16} /><span>Trust-zone changes are saved to the backend immediately. The gateway always applies session taint checks before a protected tool call.</span></div>
            </PageSection>
          )}

          {activeView === 'events' && (
            <PageSection
              eyebrow="REAL-TIME MONITORING"
              title="Security event stream"
              subtitle="Gateway policy decisions and integration activity from this runtime session."
              icon={Radio}
              action={<span className={cx('live-tag', socketStatus !== 'live' && 'live-tag-offline')}><i /> {socketStatus === 'live' ? 'LIVE' : socketStatus === 'connecting' || socketStatus === 'reconnecting' ? 'RECONNECTING' : 'OFFLINE'}</span>}
            >
              <EventPanel
                events={filteredEvents}
                expanded
                onRefresh={refreshDashboard}
                socketStatus={socketStatus}
                eventTypeFilter={eventTypeFilter}
                onEventTypeFilter={setEventTypeFilter}
                dataLoaded={dataLoaded}
              />
            </PageSection>
          )}

          <footer className="page-footer">
            <span>ShadowGuard AI <span className="footer-separator">·</span> Security gateway</span>
            <span><StatusDot online={health === 'online'} /> {health === 'online' ? 'All systems operational' : 'Gateway connection unavailable'}</span>
          </footer>
        </div>
      </main>
      {confirmAction && (
        <ConfirmationDialog
          approval={confirmAction.approval}
          decision={confirmAction.decision}
          busy={workingApproval === confirmAction.approval.id}
          onCancel={() => setConfirmAction(null)}
          onConfirm={confirmApprovalDecision}
        />
      )}
    </div>
  )
}

function MetricCard({ icon: Icon, label, value, foot, tone }) {
  const isLongValue = String(value).length > 9
  const gradientId = `spark-${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
  const sparkline = tone === 'green'
    ? 'M0 42 C18 40 23 34 38 36 S61 26 77 31 S101 27 116 20 S140 32 156 23 S180 28 198 10'
    : tone === 'amber'
      ? 'M0 43 C18 39 25 35 40 37 S61 32 78 34 S102 23 119 25 S140 16 157 20 S180 13 198 5'
      : tone === 'red'
        ? 'M0 42 C18 41 25 36 41 38 S61 28 78 33 S101 29 117 23 S140 29 157 18 S180 15 198 4'
        : 'M0 43 C18 38 25 40 40 34 S61 36 78 28 S101 31 118 22 S140 25 158 14 S181 19 198 3'
  return (
    <article className={`metric-card metric-card-${tone}`}>
      <div className={`metric-icon metric-${tone}`}><Icon size={21} /></div>
      <div className="metric-content">
        <span className="metric-label">{label}</span>
        <strong className={isLongValue ? 'metric-value-long' : undefined}>{value}</strong>
        <small>{foot}</small>
      </div>
      <svg className="metric-sparkline" viewBox="0 0 200 50" preserveAspectRatio="none" aria-hidden="true">
        <defs>
          <linearGradient id={gradientId} x1="100" y1="0" x2="100" y2="50" gradientUnits="userSpaceOnUse">
            <stop stopColor="currentColor" stopOpacity=".42" />
            <stop offset="1" stopColor="currentColor" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path className="spark-area" d={`${sparkline} L198 50 L0 50 Z`} fill={`url(#${gradientId})`} />
        <path className="spark-line" d={sparkline} />
      </svg>
    </article>
  )
}

function IntegrationIcon({ name }) {
  const Icon = name.includes('github') ? Github : name.includes('weather') ? Thermometer : Database
  return <div className={`integration-icon ${name.includes('weather') ? 'weather-icon' : name.includes('database') ? 'database-icon' : ''}`}><Icon size={17} /></div>
}

function EventPanel({
  events,
  onOpen,
  expanded = false,
  onRefresh,
  socketStatus = 'offline',
  eventTypeFilter = 'ALL',
  onEventTypeFilter,
  dataLoaded = true,
}) {
  const [autoScroll, setAutoScroll] = useState(true)
  const eventListRef = useRef(null)
  useEffect(() => {
    if (expanded && autoScroll && eventListRef.current) {
      eventListRef.current.scrollTop = 0
    }
  }, [autoScroll, events, expanded])
  return (
    <section className="card event-card">
      <div className="card-heading">
        <div className="heading-icon violet-icon"><Activity size={17} /></div>
        <div><h2>Recent activity</h2><p>Live policy decisions from the gateway</p></div>
        {expanded ? (
          <button className="icon-button" onClick={onRefresh} aria-label="Refresh events"><RefreshCw size={15} /></button>
        ) : (
          <button className="text-link" onClick={onOpen}>View all <ArrowUpRight size={13} /></button>
        )}
      </div>
      {expanded && (
        <div className="event-controls">
          <label>
            <span>Event type</span>
            <select value={eventTypeFilter} onChange={(event) => onEventTypeFilter(event.target.value)}>
              <option value="ALL">All events</option>
              <option value="BLOCKED">Blocked decisions</option>
              <option value="APPROVAL">Approvals</option>
              <option value="INTENT">Intent</option>
              <option value="TRUST">Trust</option>
              <option value="OTHER">Other activity</option>
            </select>
          </label>
          <span className={cx('stream-indicator', socketStatus === 'live' && 'stream-indicator-live')}>
            <StatusDot online={socketStatus === 'live'} />
            {socketStatus === 'live' ? 'Live connection' : socketStatus === 'connecting' || socketStatus === 'reconnecting' ? 'Reconnecting' : 'Disconnected'}
          </span>
          <label className="auto-scroll-control">
            <input type="checkbox" checked={autoScroll} onChange={(event) => setAutoScroll(event.target.checked)} />
            Auto-scroll
          </label>
        </div>
      )}
      <div className={cx('event-list', expanded && 'event-list-expanded')} ref={eventListRef}>
        {events.map((event) => (
          <EventRow event={event} key={event.event_id} />
        ))}
        {!events.length && <EmptyState title={!dataLoaded ? 'Loading events' : expanded ? 'No matching events' : 'Waiting for activity'} detail={!dataLoaded ? 'Fetching recent gateway activity.' : expanded ? 'Adjust the filters or search, or refresh the event feed.' : 'Gateway decisions will appear here as they happen.'} />}
      </div>
      {expanded && (
        <div className="event-connection">
          <span>{events.length} event{events.length === 1 ? '' : 's'} shown · newest first</span>
          {onRefresh && <button className="text-link" onClick={onRefresh}><RefreshCw size={13} /> Refresh feed</button>}
        </div>
      )}
    </section>
  )
}

function EventRow({ event }) {
  const blocked = event.event_type === 'taint_blocked' || event.event_type === 'security_error'
  const approved = event.event_type?.includes('approval') && event.event_type !== 'approval_required'
  const tone = blocked ? 'event-red' : approved ? 'event-green' : event.event_type === 'approval_required' ? 'event-amber' : 'event-blue'
  const Icon = blocked ? ShieldAlert : approved ? CheckCircle2 : event.event_type === 'approval_required' ? Clock3 : Activity
  const details = event.details || {}
  const isTrustEvent = event.event_type === 'trust_evaluated'
  const isIntentEvent = event.event_type?.includes('intent') || event.policy_code?.includes('INTENT')
  const reasonCodes = details.reason_codes || details.trust_reason_codes || details.intent_reason_codes || []
  return (
    <div className="event-row">
      <div className={`event-icon ${tone}`}><Icon size={15} /></div>
      <div className="event-copy">
        <div className="event-title-row"><strong>{event.summary || prettyName(event.event_type)}</strong><time>{formatTime(event.timestamp)}</time></div>
        <p>{prettyName(event.event_type)}{event.tool_name ? ` · ${prettyName(event.tool_name)}` : ''}{event.policy_code ? ` · ${event.policy_code}` : ''}</p>
        {(isTrustEvent || isIntentEvent) && (
          <div className="event-model-details">
            {isTrustEvent ? (
              <>
                <span>Model classification {details.classification || 'Unavailable'}</span>
                <span>ML class {details.ml_classification || 'Unavailable'}</span>
                <span>Weighted {formatModelScore(details.weighted_trust_score)}</span>
                <span>ML {formatModelScore(details.ml_trust_score)}</span>
                <span>Combined {formatModelScore(details.combined_trust_score)}</span>
                {details.mandatory_override && <strong>Mandatory policy override</strong>}
              </>
            ) : (
              <span>Intent {details.classification || details.intent_classification || 'UNCERTAIN'}{details.confidence != null ? ` · ${(details.confidence * 100).toFixed(0)}% confidence` : ''}</span>
            )}
            {reasonCodes.length > 0 && <small>{reasonCodes.join(' · ')}</small>}
          </div>
        )}
        {details.taint_state && <span className="event-detail-tag">Taint {details.taint_state}</span>}
        {details.required_capability && <span className="event-detail-tag">Capability {details.required_capability}</span>}
        {details.error && <span className="event-detail-tag event-detail-error">{details.error}</span>}
      </div>
    </div>
  )
}

function ApprovalCard({ approval, busy, onDecision }) {
  const [showDetails, setShowDetails] = useState(false)
  const [approvalKind, setApprovalKind] = useState('one_time')
  const [grantDuration, setGrantDuration] = useState(3600)
  let staged = {}
  try {
    staged = typeof approval.staged_json === 'string' ? JSON.parse(approval.staged_json) : approval.staged_json || {}
  } catch {
    staged = {}
  }
  const action = staged._action || {}
  const taintOverride = action.taint_override_required === true
  const isDatabaseAction = approval.tool_name === 'production_database'
  const impact = staged.affected_rows ?? '—'
  const tableNames = staged.tables?.join(', ') || 'Unknown table'
  const classification = staged.classification || action.classification || staged.action_type || 'REVIEW'
  const targetResource = approval.target_resource || action.target_resource || tableNames
  const destination = approval.destination_mcp || action.destination_mcp || approval.tool_name
  return (
    <article className="card approval-card">
      <div className="approval-top">
        <div className="approval-icon">{isDatabaseAction ? <Database size={19} /> : <ShieldAlert size={19} />}</div>
        <div className="approval-heading"><div><span className="eyebrow">{taintOverride ? 'TAINT OVERRIDE REVIEW' : 'DESTRUCTIVE ACTION'}</span><span className="approval-status"><i /> PENDING REVIEW</span></div>
          <h2>{prettyName(approval.tool_name || 'Protected action')}</h2>
          <p>Requested by {approval.user_id || USER_ID} · {formatTime(approval.created_at)}</p>
        </div>
        <span className="risk-pill">{classification}</span>
      </div>
      {taintOverride && (
        <div className="taint-override-notice" role="alert">
          This session contains untrusted data. Approval permits only the exact action shown below; review its sources before proceeding.
          {action.taint_sources?.length > 0 && (
            <ul>{action.taint_sources.map((source) => (
              <li key={`${source.tool_call_id}-${source.source_tool}`}>
                {prettyName(source.source_tool)} · {source.tool_call_id} · {(source.affected_fields || []).join(', ') || 'fields unavailable'}
              </li>
            ))}</ul>
          )}
        </div>
      )}
      {isDatabaseAction ? (
        <div className="sql-block"><span>SQL STATEMENT</span><code>{approval.sql_text || 'Statement unavailable'}</code></div>
      ) : (
        <div className="sql-block"><span>TOOL ARGUMENTS</span><code>{JSON.stringify(action.arguments || {}, null, 2)}</code></div>
      )}
      {isDatabaseAction && <div className="impact-grid">
        <div><small>Target tables</small><strong>{tableNames}</strong></div>
        <div><small>Rows affected</small><strong>{impact}</strong></div>
        <div><small>Blast radius</small><strong>{staged.percentage_affected ?? 0}%</strong></div>
        <div><small>Approval expires</small><strong>{formatTime(approval.expires_at)}</strong></div>
      </div>}
      <div className="approval-scope">
        <div><small>Operation</small><strong>{prettyName(approval.operation || action.operation || staged.action_type || 'tool call')}</strong></div>
        <div><small>Resource</small><strong>{targetResource}</strong></div>
        <div><small>Destination</small><strong>{prettyName(destination)}</strong></div>
        <div><small>Capabilities</small><strong>{(action.permitted_capabilities || []).join(', ') || 'exact action'}</strong></div>
      </div>
      {isDatabaseAction && <button className="details-toggle" onClick={() => setShowDetails(!showDetails)}>
        {showDetails ? 'Hide simulation details' : 'View shadow-state simulation'} <ChevronDown size={14} className={showDetails ? 'rotate' : ''} />
      </button>}
      {isDatabaseAction && showDetails && (
        <div className="simulation-details">
          {approval.snapshot_fingerprint && <p><strong>Snapshot fingerprint:</strong> <code>{approval.snapshot_fingerprint}</code></p>}
          <p><strong>Policy severity:</strong> {staged.severity || 'review'} <span>·</span> <strong>Action:</strong> {staged.action_type || 'tool call'}</p>
          {staged.policy_reasons?.length > 0 && <ul>{staged.policy_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
          {staged.before && <pre>{JSON.stringify(staged.before, null, 2)}</pre>}
        </div>
      )}
      <div className="approval-actions">
        <div className="approval-kind">
          <span><LockKeyhole size={13} /> This action has not run</span>
          <label>
            <input type="radio" name={`approval-kind-${approval.id}`} checked={approvalKind === 'one_time'} onChange={() => setApprovalKind('one_time')} />
            One-time exact action
          </label>
          <label>
            <input type="radio" name={`approval-kind-${approval.id}`} checked={approvalKind === 'persistent_grant'} onChange={() => setApprovalKind('persistent_grant')} />
            Scoped trust grant
          </label>
          {approvalKind === 'persistent_grant' && (
            <select value={grantDuration} onChange={(event) => setGrantDuration(Number(event.target.value))}>
              <option value={900}>15 minutes</option>
              <option value={3600}>1 hour</option>
              <option value={14400}>4 hours</option>
            </select>
          )}
        </div>
        <div>
          <button className="button-reject" onClick={() => onDecision('reject')} disabled={busy}>
            {busy ? <LoaderCircle size={15} className="spin" /> : <X size={15} />} Reject
          </button>
          <button className="button-approve" onClick={() => onDecision('approve', { approvalKind, grantDurationSeconds: grantDuration })} disabled={busy}>
            {busy ? <LoaderCircle size={15} className="spin" /> : <Check size={15} />} Approve action
          </button>
        </div>
      </div>
    </article>
  )
}

function IntegrationCard({ integration, saving, onChange }) {
  const descriptions = {
    github_reader: 'Read-only access to repository content and code fixtures.',
    weather_api: 'External data source. Responses may contain untrusted content.',
    production_database: 'Protected database. Destructive statements require explicit approval.',
  }
  return (
    <article className="card integration-card">
      <div className="integration-card-top">
        <IntegrationIcon name={integration.name} />
        <div className="integration-card-name"><strong>{prettyName(integration.name)}</strong><span><StatusDot online={Boolean(integration.enabled)} /> {integration.enabled ? 'Enabled at gateway' : 'Disabled'}</span></div>
        <span className="integration-managed">GATEWAY MANAGED</span>
      </div>
      <p className="integration-description">{integration.description || descriptions[integration.name] || 'Tool registered with the ShadowGuard gateway.'}</p>
      <div className="trust-score-row">
        <span>Gateway model classification</span>
        <ClassificationBadge classification={integration.trust_classification} />
        <small>ML prediction: {integration.ml_classification || 'Unavailable'}</small>
        <div className="trust-model-scores">
          <div><small>Weighted</small><strong>{formatModelScore(integration.weighted_trust_score)}</strong></div>
          <div><small>ML score</small><strong>{formatModelScore(integration.ml_trust_score)}</strong></div>
          <div><small>Combined</small><strong>{formatModelScore(integration.combined_trust_score)}</strong></div>
        </div>
        {integration.trust_reason_codes?.length > 0 && (
          <small>Reasons: {integration.trust_reason_codes.join(' · ')}</small>
        )}
        {integration.mandatory_override && (
          <span className="trust-model-override" role="status">Mandatory security check overrode the model score</span>
        )}
      </div>
      <div className="integration-card-footer">
        <label htmlFor={`zone-${integration.name}`}>Configured trust zone</label>
        <div className="select-wrap">
          <select
            id={`zone-${integration.name}`}
            value={integration.trust_zone}
            onChange={(event) => onChange(event.target.value)}
            disabled={saving}
          >
            <option value="HIGH">HIGH — trusted</option>
            <option value="MEDIUM">MEDIUM — guarded</option>
            <option value="LOW">LOW — untrusted</option>
          </select>
          {saving ? <LoaderCircle size={14} className="spin" /> : <ChevronDown size={14} />}
        </div>
      </div>
    </article>
  )
}

function PageSection({ eyebrow, title, subtitle, icon: Icon, count, action, children }) {
  return (
    <section className="page-section">
      <div className="page-heading">
        <div>
          <div className="eyebrow"><span className="eyebrow-line" /> {eyebrow}</div>
          <h1>{title}{Number.isInteger(count) && <span className="heading-count">{count}</span>}</h1>
          <p>{subtitle}</p>
        </div>
        {action || <div className="heading-icon page-title-icon"><Icon size={19} /></div>}
      </div>
      {children}
    </section>
  )
}

function EmptyState({ title, detail, large = false }) {
  return (
    <div className={cx('empty-state', large && 'empty-state-large')}>
      <span><CheckCircle2 size={20} /></span>
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  )
}

function ConfirmationDialog({ approval, decision, busy, onCancel, onConfirm }) {
  const [operatorToken, setOperatorToken] = useState('')
  const isApprove = decision === 'approve'
  useEffect(() => {
    function onKeyDown(event) {
      if (event.key === 'Escape' && !busy) onCancel()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [busy, onCancel])
  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => {
      if (event.target === event.currentTarget && !busy) onCancel()
    }}>
      <section className="confirmation-dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirmation-title">
        <div className={cx('dialog-icon', isApprove ? 'dialog-icon-approve' : 'dialog-icon-reject')}>
          {isApprove ? <ShieldCheck size={20} /> : <ShieldAlert size={20} />}
        </div>
        <p className="eyebrow">{isApprove ? 'HUMAN APPROVAL REQUIRED' : 'REJECTION CONFIRMATION'}</p>
        <h2 id="confirmation-title">{isApprove ? 'Approve this protected action?' : 'Reject this protected action?'}</h2>
        <p className="dialog-description">
          {isApprove
            ? 'The backend will revalidate this exact staged action before it can run. Review the operation and target before proceeding.'
            : 'The request will be rejected, and the staged operation will not be executed.'}
        </p>
        <div className="dialog-action-summary">
          <span>{prettyName(approval.tool_name || 'Protected action')}</span>
          <strong>{approval.operation || approval.target_resource || approval.sql_text || 'Staged operation'}</strong>
        </div>
        <label className="operator-token-field">
          <span>Approval operator token</span>
          <input
            type="password"
            autoComplete="new-password"
            value={operatorToken}
            onChange={(event) => setOperatorToken(event.target.value)}
            aria-required="true"
            placeholder="Enter the token configured in backend/.env"
          />
          <small>Sent only with this decision and kept in memory for this dialog.</small>
        </label>
        <div className="dialog-actions">
          <button className="button-secondary" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className={isApprove ? 'button-approve' : 'button-reject'} onClick={() => onConfirm(operatorToken)} disabled={busy || !operatorToken.trim()}>
            {busy ? <LoaderCircle size={15} className="spin" /> : isApprove ? <Check size={15} /> : <X size={15} />}
            {isApprove ? 'Confirm approval' : 'Confirm rejection'}
          </button>
        </div>
      </section>
    </div>
  )
}

export default App
