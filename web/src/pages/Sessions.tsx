import { t } from '../i18n'
import { useEffect, useState } from 'react'
import { History, RefreshCw, ChevronRight, PlayCircle, Trash2 } from 'lucide-react'
import { api, enc } from '../lib/api'
import type { Session } from '../lib/api'
import { useResource } from '../lib/store'
import { ago, bytes, dateTime, duration } from '../lib/format'
import { go, href } from '../lib/router'
import { DataTable, Pill, Props, Section, Spinner, Tag } from '../ui/common'
import { toast } from '../ui/overlays'
import { RecordingPlayer } from '../components/RecordingPlayer'
import { GfxPlayer } from '../components/GfxPlayer'

const conn = (s: Session) => s.connection as { name?: string; host?: string; port?: number; account?: string; protocol?: string; record_input?: boolean }

export function Sessions({ id }: { id?: string }) {
  if (id) return <SessionRecord id={id} />
  return <SessionList />
}

function SessionList() {
  const [rows, setRows] = useState<Session[]>([])
  const [active, setActive] = useState(false)
  const [loading, setLoading] = useState(false)
  const [more, setMore] = useState(true)
  const load = async (reset: boolean) => {
    setLoading(true)
    try {
      const q = new URLSearchParams({ limit: '100' })
      if (active) q.set('active', 'true')
      if (!reset && rows.length) q.set('before', rows[rows.length - 1].started_at)
      const page = await api.get<Session[]>(`/audit/sessions?${q}`)
      setRows(reset ? page : [...rows, ...page])
      setMore(page.length === 100)
    } catch (e) {
      toast.err(e)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => void load(true), [active])
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <History size={20} />
          <h1>{t('Sessions')}</h1>
          {loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="seg seg-text">
            <button className={!active ? 'on' : ''} onClick={() => setActive(false)}>{t('All')}</button>
            <button className={active ? 'on' : ''} onClick={() => setActive(true)}>{t('Active now')}</button>
          </div>
          <button className="icon-btn" title={t('Reload')} onClick={() => load(true)}><RefreshCw size={15} /></button>
        </div>
      </div>
      <div className="page-body">
        <DataTable
          rows={rows}
          rowKey={(s) => s.id}
          onOpen={(s) => go('sessions', s.id)}
          columns={[
            { key: 'start', label: t('Started'), render: (s) => <span className="small" title={dateTime(s.started_at)}>{ago(s.started_at)}</span> },
            { key: 'user', label: t('User'), render: (s) => <span><strong>{s.username}</strong> <span className="muted small mono">{s.client_ip}</span></span> },
            { key: 'conn', label: t('Connection'), render: (s) => <span><strong>{conn(s).name}</strong> <span className="muted small mono">{conn(s).account}@{conn(s).host}</span></span> },
            { key: 'site', label: t('Site'), render: (s) => s.site || <span className="muted">—</span> },
            { key: 'dur', label: t('Duration'), render: (s) => duration(s.started_at, s.ended_at) },
            { key: 'state', label: t('Status'), render: (s) => (s.ended_at ? <span className="muted small">{s.end_reason}</span> : <Pill state="active" />) },
            { key: 'rec', label: '', render: (s) => (s.has_recording ? <PlayCircle size={15} className="muted" aria-label={t('recorded')} /> : s.recording_purged_at ? <span title={t('Recording deleted by the retention policy')}><Trash2 size={14} className="muted" /></span> : null) },
          ]}
        />
        {more && rows.length > 0 && <button className="btn" disabled={loading} onClick={() => load(false)}>{t('Load older')}</button>}
      </div>
    </div>
  )
}

function SessionRecord({ id }: { id: string }) {
  const { data: s, error } = useResource<Session>(`/audit/sessions/${enc(id)}`)
  if (error) return <div className="page"><div className="alert alert-bad">{error.message}</div></div>
  if (!s) return <div className="center page"><Spinner /></div>
  const c = conn(s)
  return (
    <div className="page record">
      <div className="breadcrumbs">
        <a href={href('sessions')}>{t('Sessions')}</a>
        <ChevronRight size={13} />
        <span>{c.name} · {s.username}</span>
      </div>
      <header className="record-head">
        <div className="record-title">
          <h1>{c.name}</h1>
          <div className="row gap wrap">
            {s.ended_at ? <Tag>{t('ended: {0}', s.end_reason ?? '')}</Tag> : <Pill state="active" />}
            <span className="muted small">{dateTime(s.started_at)} · {duration(s.started_at, s.ended_at)}</span>
          </div>
        </div>
      </header>
      <div className="record-body">
        <aside className="record-side">
          <Section title={t('Session')}>
            <Props items={[
              [t('User'), s.user_id ? <a href={href('users', s.user_id)}>{s.username}</a> : s.username],
              [t('From'), <span className="mono small">{s.client_ip}</span>],
              [t('Target'), <span className="mono small">{c.account}@{c.host}:{c.port}</span>],
              [t('Site'), s.site || t('direct')],
              [t('Started'), dateTime(s.started_at)],
              [t('Ended'), s.ended_at ? dateTime(s.ended_at) : t('still open')],
              [t('Keystrokes'), c.record_input ? t('recorded') : t('not recorded')],
              s.recording_expires_at && [t('Recording kept until'), <span title={t('Retention policy: see Settings')}>{dateTime(s.recording_expires_at)}</span>],
              s.recording_bytes != null && [t('Recording size'), bytes(s.recording_bytes)],
              ['ID', <span className="mono small">{s.id}</span>],
            ]} />
          </Section>
          <p className="help">{t('The connection as it was when the session started is kept with the session, so later edits do not change this record.')}</p>
        </aside>
        <main className="record-main">
          {s.has_recording ? (
            c.protocol === 'vnc' || c.protocol === 'rdp' ? <GfxPlayer session={s} /> : <RecordingPlayer session={s} />
          ) : s.recording_purged_at ? (
            <div className="alert alert-warn">{t('The recording was deleted on {0} by the retention policy.', dateTime(s.recording_purged_at))}</div>
          ) : (
            <div className="muted">{t('This session was not recorded.')}</div>
          )}
        </main>
      </div>
    </div>
  )
}
