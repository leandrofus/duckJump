import { t } from '../i18n'
import { useEffect, useState } from 'react'
import { ScrollText, ShieldCheck, ShieldAlert, RefreshCw, Search, X } from 'lucide-react'
import { api } from '../lib/api'
import type { AuditEvent } from '../lib/api'
import { ago, dateTime } from '../lib/format'
import { href } from '../lib/router'
import { DataTable, Spinner, Tag } from '../ui/common'
import { Modal, openDialog, toast } from '../ui/overlays'

type Verify = { events: number; ok: boolean; broken_at?: number; reason?: string }

const ACTION_TONE: Record<string, string> = {
  'auth.login_failed': 'bad', 'auth.totp_failed': 'bad', 'session.denied': 'bad',
  'session.start': 'ok', 'auth.login': 'ok', 'recording.view': 'info',
}
const tone = (a: string) => ACTION_TONE[a] ?? (a.endsWith('.delete') || a.endsWith('_reset') ? 'warn' : undefined)

function objectLink(e: AuditEvent) {
  const map: Record<string, string> = { user: 'users', group: 'groups', connection: 'connections', site: 'sites', session: 'sessions' }
  return map[e.object_type] && e.object_id ? href(map[e.object_type], e.object_id) : undefined
}

export function AuditLog() {
  const [rows, setRows] = useState<AuditEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [more, setMore] = useState(true)
  const [action, setAction] = useState('')
  const [verify, setVerify] = useState<Verify | null>(null)
  const load = async (reset: boolean) => {
    setLoading(true)
    try {
      const q = new URLSearchParams({ limit: '100' })
      if (action) q.set('action', action)
      if (!reset && rows.length) q.set('before_id', String(rows[rows.length - 1].id))
      const page = await api.get<AuditEvent[]>(`/audit/events?${q}`)
      setRows(reset ? page : [...rows, ...page])
      setMore(page.length === 100)
    } catch (e) {
      toast.err(e)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => void load(true), [action])
  const runVerify = () => api.get<Verify>('/audit/verify').then(setVerify, toast.err)
  useEffect(() => void runVerify(), [])
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <ScrollText size={20} />
          <h1>{t('Audit log')}</h1>
          {loading && <Spinner />}
        </div>
        <div className="page-actions">
          {verify && (
            verify.ok
              ? <span className="tag tag-ok" title={t('Every event hash recomputed and matched.')}><ShieldCheck size={13} /> {t('Chain intact · {0} events', verify.events)}</span>
              : <span className="tag tag-bad" title={verify.reason}><ShieldAlert size={13} /> {t('Chain broken at event #{0}', verify.broken_at)}</span>
          )}
          <button className="btn btn-sm" onClick={runVerify}><ShieldCheck size={14} /> {t('Verify')}</button>
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Filter by action (e.g. auth.login_failed)')} value={action} onChange={(e) => setAction(e.target.value.trim())} />
            {action && <button className="icon-btn" onClick={() => setAction('')}><X size={13} /></button>}
          </div>
          <button className="icon-btn" title={t('Reload')} onClick={() => load(true)}><RefreshCw size={15} /></button>
        </div>
      </div>
      <div className="page-body">
        {verify && !verify.ok && <div className="alert alert-bad">{t('The audit chain does not verify from event #{0}: {1}. Someone altered or removed records.', verify.broken_at, verify.reason)}</div>}
        <DataTable
          rows={rows}
          rowKey={(e) => String(e.id)}
          onOpen={(e) => openDialog((c) => <EventDialog e={e} onClose={c} />)}
          rowMenu={(e) => [
            { header: `#${e.id} ${e.action}` },
            { label: t('Details'), onClick: () => openDialog((c) => <EventDialog e={e} onClose={c} />) },
            { label: t('Only this action'), onClick: () => setAction(e.action) },
          ]}
          columns={[
            { key: 'ts', label: t('When'), render: (e) => <span className="small" title={dateTime(e.ts)}>{ago(e.ts)}</span> },
            { key: 'actor', label: t('Who'), render: (e) => <span><strong>{e.actor_name || '—'}</strong> <span className="muted small mono">{e.actor_ip}</span></span> },
            { key: 'action', label: t('Action'), render: (e) => <Tag tone={tone(e.action)} mono>{e.action}</Tag> },
            { key: 'object', label: t('Object'), render: (e) => { const l = objectLink(e); const label = (e.details as any)?.name || (e.details as any)?.connection || (e.details as any)?.username || e.object_id; return l ? <a href={l}>{label}</a> : <span className="muted">{label}</span> } },
            { key: 'details', label: t('Details'), render: (e) => <span className="muted small mono ellipsis audit-details">{summarize(e.details)}</span> },
          ]}
        />
        {more && rows.length > 0 && <button className="btn" disabled={loading} onClick={() => load(false)}>{t('Load older')}</button>}
      </div>
    </div>
  )
}

function summarize(d: unknown) {
  if (!d || typeof d !== 'object') return ''
  return Object.entries(d as Record<string, unknown>)
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
    .join(' ')
}

function EventDialog({ e, onClose }: { e: AuditEvent; onClose: () => void }) {
  return (
    <Modal wide title={`#${e.id} · ${e.action}`} onClose={onClose}>
      <pre className="mono code-block">{JSON.stringify(e, null, 2)}</pre>
    </Modal>
  )
}
