import { t } from '../i18n'
import { useEffect, useMemo, useState } from 'react'
import {
  Ticket, Plus, Search, X, Check, Trash2, Clock, Calendar,
  Server, Folder as FolderIcon, Tag as TagIcon, CheckCircle2, XCircle, AlertCircle, MessageSquare
} from 'lucide-react'
import { api } from '../lib/api'
import type { AccessRequest, AccessRequestTargets, CreateAccessRequest } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { ago, dateTime } from '../lib/format'
import { isAdmin, getMe } from '../lib/session'
import { DataTable, Empty, Spinner, Tag, Avatar } from '../ui/common'
import type { Column } from '../ui/common'
import { Modal, confirm, openDialog, toast } from '../ui/overlays'
import { Field } from '../components/FormBits'

function toLocalDatetimeInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function Perms({ r }: { r: AccessRequest }) {
  return (
    <span className="tags">
      {r.can_connect && <Tag tone="ok">{t('connect')}</Tag>}
      {r.can_view_recordings && <Tag>{t('recordings')}</Tag>}
      {r.can_upload && <Tag>{t('upload files')}</Tag>}
      {r.can_download && <Tag tone="warn">{t('download files')}</Tag>}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case 'pending':
      return <Tag tone="warn"><Clock size={11} /> {t('Pending')}</Tag>
    case 'approved':
      return <Tag tone="ok"><CheckCircle2 size={11} /> {t('Approved')}</Tag>
    case 'rejected':
      return <Tag tone="bad"><XCircle size={11} /> {t('Rejected')}</Tag>
    case 'canceled':
      return <Tag><AlertCircle size={11} /> {t('Canceled')}</Tag>
    default:
      return <Tag>{status}</Tag>
  }
}

export function RequestAccessDialog({ onClose, defaultTarget }: { onClose: () => void; defaultTarget?: { type: 'connection' | 'folder' | 'tag'; ref: string } }) {
  const [targets, setTargets] = useState<AccessRequestTargets | null>(null)
  const [loadingTargets, setLoadingTargets] = useState(true)
  const [type, setType] = useState<'connection' | 'folder' | 'tag'>(defaultTarget?.type ?? 'connection')
  const [ref, setRef] = useState(defaultTarget?.ref ?? '')
  const [ticket, setTicket] = useState('')
  const [reason, setReason] = useState('')
  const now = useMemo(() => new Date(), [])
  const defaultEnd = useMemo(() => new Date(now.getTime() + 4 * 3600 * 1000), [now])
  const [startsAt, setStartsAt] = useState(toLocalDatetimeInput(now))
  const [endsAt, setEndsAt] = useState(toLocalDatetimeInput(defaultEnd))
  const [connect, setConnect] = useState(true)
  const [recordings, setRecordings] = useState(false)
  const [upload, setUpload] = useState(false)
  const [download, setDownload] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.get<AccessRequestTargets>('/access-requests/targets')
      .then((res) => {
        setTargets(res)
        if (!ref) {
          if (type === 'connection' && res.connections.length > 0) setRef(res.connections[0].id)
          else if (type === 'folder' && res.folders.length > 0) setRef(res.folders[0].id)
          else if (type === 'tag' && res.tags.length > 0) setRef(res.tags[0])
        }
      })
      .catch((e) => toast.err(e))
      .finally(() => setLoadingTargets(false))
  }, [])

  const applyOffset = (hours: number) => {
    const s = startsAt ? new Date(startsAt) : new Date()
    const e = new Date(s.getTime() + hours * 3600 * 1000)
    setEndsAt(toLocalDatetimeInput(e))
  }

  const save = async () => {
    if (!reason.trim()) {
      toast.err(t('Please provide a reason for the access request.'))
      return
    }
    const sDate = new Date(startsAt)
    const eDate = new Date(endsAt)
    if (isNaN(sDate.getTime()) || isNaN(eDate.getTime())) {
      toast.err(t('Please specify valid start and end dates.'))
      return
    }
    if (eDate <= sDate) {
      toast.err(t('End date must be after start date.'))
      return
    }
    if (eDate <= new Date()) {
      toast.err(t('End date cannot be in the past.'))
      return
    }

    setBusy(true)
    try {
      const payload: CreateAccessRequest = {
        object_type: type,
        object_ref: ref,
        ticket: ticket.trim(),
        reason: reason.trim(),
        starts_at: sDate.toISOString(),
        ends_at: eDate.toISOString(),
        can_connect: connect,
        can_view_recordings: recordings,
        can_upload: upload,
        can_download: download,
      }
      await api.post('/access-requests', payload)
      invalidate('/access-requests')
      toast.ok(t('Access request submitted'))
      onClose()
    } catch (e) {
      toast.err(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal wide title={t('Request access')} icon={<Ticket size={18} />} onClose={onClose}
      footer={<>
        <button className="btn" onClick={onClose}>{t('Cancel')}</button>
        <button className="btn btn-primary" disabled={busy || loadingTargets || !ref || !reason.trim() || (!connect && !recordings && !upload && !download)} onClick={save}>
          {t('Submit request')}
        </button>
      </>}>
      <div className="grid-2">
        <Field label={t('Target type')}>
          <div className="seg seg-text">
            {(['connection', 'folder', 'tag'] as const).map((k) => (
              <button key={k} type="button" className={type === k ? 'on' : ''} onClick={() => {
                setType(k)
                if (targets) {
                  if (k === 'connection' && targets.connections.length > 0) setRef(targets.connections[0].id)
                  else if (k === 'folder' && targets.folders.length > 0) setRef(targets.folders[0].id)
                  else if (k === 'tag' && targets.tags.length > 0) setRef(targets.tags[0])
                  else setRef('')
                }
              }}>
                {k === 'connection' ? t('Connection') : k === 'folder' ? t('Folder') : t('Tag')}
              </button>
            ))}
          </div>
        </Field>

        <Field label={type === 'connection' ? t('Connection') : type === 'folder' ? t('Folder (and everything inside)') : t('Tag')}>
          {loadingTargets ? <Spinner /> : (
            <select value={ref} onChange={(e) => setRef(e.target.value)}>
              {type === 'connection' && targets?.connections.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.protocol.toUpperCase()}{c.environment ? ` · ${c.environment}` : ''})
                </option>
              ))}
              {type === 'folder' && targets?.folders.map((f) => (
                <option key={f.id} value={f.id}>{f.name}</option>
              ))}
              {type === 'tag' && targets?.tags.map((tg) => (
                <option key={tg} value={tg}>#{tg}</option>
              ))}
            </select>
          )}
        </Field>

        <Field label={t('Start date and time')}>
          <input type="datetime-local" value={startsAt} onChange={(e) => setStartsAt(e.target.value)} />
        </Field>

        <Field label={t('End date and time')} help={
          <div className="row gap" style={{ marginTop: '0.25rem' }}>
            <span className="muted small">{t('Quick add:')}</span>
            <button type="button" className="btn btn-sm" onClick={() => applyOffset(2)}>+2h</button>
            <button type="button" className="btn btn-sm" onClick={() => applyOffset(8)}>+8h</button>
            <button type="button" className="btn btn-sm" onClick={() => applyOffset(24)}>+1d</button>
            <button type="button" className="btn btn-sm" onClick={() => applyOffset(168)}>+7d</button>
          </div>
        }>
          <input type="datetime-local" value={endsAt} onChange={(e) => setEndsAt(e.target.value)} />
        </Field>

        <Field label={t('Ticket / Issue ID')} span help={t('Optional reference (e.g. JIRA-1234, INC-567, #42)')}>
          <input
            placeholder={t('e.g. JIRA-1024, INC-555')}
            value={ticket}
            onChange={(e) => setTicket(e.target.value)}
          />
        </Field>

        <Field label={t('Reason')} span help={t('Explain why access is needed (e.g. scheduled maintenance, incident resolution).')}>
          <textarea
            autoFocus
            rows={3}
            placeholder={t('Reason for the access request…')}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </Field>

        <Field label={t('Permissions requested')} span>
          <div className="checks">
            <label><input type="checkbox" checked={connect} onChange={(e) => setConnect(e.target.checked)} /> {t('Connect')}</label>
            <label><input type="checkbox" checked={recordings} onChange={(e) => setRecordings(e.target.checked)} /> {t('View recordings')}</label>
            <label><input type="checkbox" checked={upload} onChange={(e) => setUpload(e.target.checked)} /> {t('Upload files')}</label>
            <label><input type="checkbox" checked={download} onChange={(e) => setDownload(e.target.checked)} /> {t('Download files')}</label>
          </div>
        </Field>
      </div>
    </Modal>
  )
}

function ReviewDialog({ req, action, onClose }: { req: AccessRequest; action: 'approve' | 'reject'; onClose: () => void }) {
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  const isApprove = action === 'approve'

  const submit = async () => {
    setBusy(true)
    try {
      await api.post(`/access-requests/${req.id}/${action}`, { comment: comment.trim() })
      invalidate('/access-requests', '/policies', '/access', '/portal')
      toast.ok(isApprove ? t('Access request approved') : t('Access request rejected'))
      onClose()
    } catch (e) {
      toast.err(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title={isApprove ? t('Approve access request') : t('Reject access request')}
      icon={isApprove ? <CheckCircle2 size={18} className="tone-ok" /> : <XCircle size={18} className="tone-bad" />}
      onClose={onClose}
      footer={<>
        <button className="btn" onClick={onClose}>{t('Cancel')}</button>
        <button className={`btn ${isApprove ? 'btn-primary' : 'btn-danger'}`} disabled={busy} onClick={submit}>
          {isApprove ? t('Approve and grant access') : t('Reject request')}
        </button>
      </>}
    >
      <div className="grid">
        <div className="card" style={{ padding: '0.75rem', background: 'var(--bg-subtle)' }}>
          <div className="row gap" style={{ marginBottom: '0.5rem' }}>
            <Avatar name={req.user_username} size={22} />
            <strong>{req.user_display_name || req.user_username}</strong>
            <span className="muted">→</span>
            <strong>{req.object_name}</strong>
            <Tag>{req.object_type}</Tag>
          </div>
          {req.ticket && (
            <div className="small" style={{ marginBottom: '0.5rem' }}>
              <Tag tone="accent">
                <Ticket size={11} style={{ display: 'inline', marginRight: 4 }} />
                {req.ticket}
              </Tag>
            </div>
          )}
          <div className="small muted" style={{ marginBottom: '0.5rem' }}>
            <Calendar size={12} style={{ display: 'inline', marginRight: 4 }} />
            {dateTime(req.starts_at)} → {dateTime(req.ends_at)}
          </div>
          <div className="small">
            <strong>{t('Reason')}:</strong> {req.reason}
          </div>
        </div>

        <Field label={isApprove ? t('Review note (optional)') : t('Rejection reason (optional)')}>
          <textarea
            autoFocus
            rows={2}
            placeholder={isApprove ? t('Approval comments or references…') : t('Reason for rejection…')}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
        </Field>
      </div>
    </Modal>
  )
}

export function AccessRequests() {
  const admin = isAdmin()
  const me = getMe()
  const { data, loading, error } = useResource<AccessRequest[]>('/access-requests')
  const [q, setQ] = useState('')
  const [tab, setTab] = useState<'pending' | 'approved' | 'rejected' | 'canceled' | 'all'>('pending')
  const [mineOnly, setMineOnly] = useState(false)

  const all = data || []
  const pendingCount = all.filter((r) => r.status === 'pending').length

  const filtered = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return all.filter((r) => {
      if (tab !== 'all' && r.status !== tab) return false
      if (admin && mineOnly && r.user_id !== me?.user.id) return false
      if (words.length === 0) return true
      const text = `${r.user_username} ${r.user_display_name} ${r.object_name} ${r.ticket || ''} ${r.reason} ${r.review_comment}`.toLowerCase()
      return words.every((w) => text.includes(w))
    })
  }, [all, tab, mineOnly, q, admin, me])

  const cancel = async (req: AccessRequest) => {
    if (!(await confirm({
      title: t('Cancel access request?'),
      body: t('The request will be canceled and no access will be granted.'),
      danger: true,
      confirm: t('Cancel request')
    }))) return
    try {
      await api.post(`/access-requests/${req.id}/cancel`)
      invalidate('/access-requests')
      toast.ok(t('Access request canceled'))
    } catch (e) {
      toast.err(e)
    }
  }

  const columns: Column<AccessRequest>[] = [
    ...(admin ? [{
      key: 'user',
      label: t('Requester'),
      render: (r: AccessRequest) => (
        <div className="row gap">
          <Avatar name={r.user_username} size={24} />
          <div>
            <strong>{r.user_display_name || r.user_username}</strong>
            {r.user_display_name && r.user_display_name !== r.user_username && (
              <span className="muted small" style={{ display: 'block' }}>{r.user_username}</span>
            )}
          </div>
        </div>
      )
    }] : []),
    {
      key: 'target',
      label: t('Target'),
      render: (r: AccessRequest) => {
        const Icon = r.object_type === 'connection' ? Server : r.object_type === 'folder' ? FolderIcon : TagIcon
        return (
          <div className="row gap">
            <Icon size={14} className="muted" />
            <div>
              <strong>{r.object_name}</strong>
              <span className="muted small" style={{ display: 'block' }}>{r.object_type}</span>
            </div>
          </div>
        )
      }
    },
    {
      key: 'window',
      label: t('Access window'),
      render: (r: AccessRequest) => (
        <div className="small">
          <div><Clock size={11} className="muted" style={{ display: 'inline', marginRight: 4 }} /><strong>{dateTime(r.starts_at)}</strong></div>
          <div className="muted">{t('until')} {dateTime(r.ends_at)}</div>
        </div>
      )
    },
    {
      key: 'reason',
      label: t('Reason'),
      render: (r: AccessRequest) => (
        <div style={{ maxWidth: 280 }}>
          {r.ticket && (
            <div style={{ marginBottom: 4 }}>
              <Tag tone="accent">
                <Ticket size={11} style={{ display: 'inline', marginRight: 4 }} />
                {r.ticket}
              </Tag>
            </div>
          )}
          <div className="ellipsis" title={r.reason}>
            {r.reason}
          </div>
        </div>
      )
    },
    {
      key: 'perms',
      label: t('Permissions'),
      render: (r: AccessRequest) => <Perms r={r} />
    },
    {
      key: 'status',
      label: t('Status'),
      render: (r: AccessRequest) => (
        <div>
          <StatusBadge status={r.status} />
          {r.reviewed_at && (
            <div className="muted small" style={{ marginTop: 2 }}>
              {r.reviewer_username ? t('by {0}', r.reviewer_username) : ''} · {ago(r.reviewed_at)}
            </div>
          )}
          {r.review_comment && (
            <div className="muted small" style={{ marginTop: 2, fontStyle: 'italic' }}>
              <MessageSquare size={10} style={{ display: 'inline', marginRight: 3 }} />
              {r.review_comment}
            </div>
          )}
        </div>
      )
    },
    {
      key: 'created',
      label: t('Created'),
      render: (r: AccessRequest) => <span className="muted small" title={dateTime(r.created_at)}>{ago(r.created_at)}</span>
    },
    {
      key: 'actions',
      label: '',
      render: (r: AccessRequest) => {
        if (r.status !== 'pending') return null
        return (
          <div className="row gap" style={{ justifyContent: 'flex-end' }}>
            {admin && (
              <>
                <button
                  className="btn btn-sm btn-primary"
                  title={t('Approve')}
                  onClick={() => openDialog((c) => <ReviewDialog req={r} action="approve" onClose={c} />)}
                >
                  <Check size={13} /> {t('Approve')}
                </button>
                <button
                  className="btn btn-sm btn-danger"
                  title={t('Reject')}
                  onClick={() => openDialog((c) => <ReviewDialog req={r} action="reject" onClose={c} />)}
                >
                  <X size={13} /> {t('Reject')}
                </button>
              </>
            )}
            {(!admin || r.user_id === me?.user.id) && (
              <button
                className="btn btn-sm"
                title={t('Cancel request')}
                onClick={() => cancel(r)}
              >
                <Trash2 size={13} /> {t('Cancel')}
              </button>
            )}
          </div>
        )
      }
    }
  ]

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <Ticket size={20} />
          <h1>{t('Access requests')}</h1>
          <span className="count">{filtered.length}</span>
          {loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="search">
            <Search size={14} />
            <input autoFocus placeholder={t('Search requests…')} value={q} onChange={(e) => setQ(e.target.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>
          <button className="btn btn-primary" onClick={() => openDialog((c) => <RequestAccessDialog onClose={c} />)}>
            <Plus size={14} /> {t('Request access')}
          </button>
        </div>
      </div>

      <div className="subbar">
        <div className="seg seg-text">
          <button className={tab === 'pending' ? 'on' : ''} onClick={() => setTab('pending')}>
            {t('Pending')} {pendingCount > 0 && <span className="badge-counter">{pendingCount}</span>}
          </button>
          <button className={tab === 'approved' ? 'on' : ''} onClick={() => setTab('approved')}>{t('Approved')}</button>
          <button className={tab === 'rejected' ? 'on' : ''} onClick={() => setTab('rejected')}>{t('Rejected')}</button>
          <button className={tab === 'canceled' ? 'on' : ''} onClick={() => setTab('canceled')}>{t('Canceled')}</button>
          <button className={tab === 'all' ? 'on' : ''} onClick={() => setTab('all')}>{t('All')}</button>
        </div>

        {admin && (
          <label className="row gap small muted" style={{ cursor: 'pointer' }}>
            <input type="checkbox" checked={mineOnly} onChange={(e) => setMineOnly(e.target.checked)} />
            {t('Only my requests')}
          </label>
        )}
      </div>

      <div className="page-body">
        {error && <div className="alert alert-bad">{error.message}</div>}
        {data && all.length === 0 && (
          <Empty icon={<Ticket size={28} />} title={t('No access requests')}>
            {t('You can request temporary access to hosts or folders with a specific reason and duration.')}
            <div style={{ marginTop: '1rem' }}>
              <button className="btn btn-primary" onClick={() => openDialog((c) => <RequestAccessDialog onClose={c} />)}>
                <Plus size={14} /> {t('Request access')}
              </button>
            </div>
          </Empty>
        )}
        {all.length > 0 && filtered.length === 0 && (
          <div className="muted">{t('No access requests match the current filter.')}</div>
        )}
        {filtered.length > 0 && (
          <DataTable rows={filtered} columns={columns} rowKey={(r) => r.id} />
        )}
      </div>
    </div>
  )
}
