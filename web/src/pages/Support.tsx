import { t } from '../i18n'
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  LifeBuoy, Plus, Search, Check, Clock, CheckCircle2,
  XCircle, Copy, Shield, X, Monitor, KeyRound, RefreshCw
} from 'lucide-react'
import { api, wsURL } from '../lib/api'
import type { SupportSession } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { ago, dateTime, copy } from '../lib/format'
import { DataTable, Empty, Spinner, Tag } from '../ui/common'
import type { Column } from '../ui/common'
import { Modal, confirm, toast } from '../ui/overlays'
import { Field } from '../components/FormBits'
import { Painter, parseDisplay, pointerEvent, keyEvent, ackEvent, buttonMask, keysymFor, scancodeFor } from '../lib/gfx'

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case 'pending':
      return <Tag tone="warn"><Clock size={11} /> {t('Waiting for user...')}</Tag>
    case 'connected':
      return <Tag tone="accent"><KeyRound size={11} /> {t('Agent connected (needs code)')}</Tag>
    case 'active':
      return <Tag tone="ok"><CheckCircle2 size={11} /> {t('Active')}</Tag>
    case 'ended':
      return <Tag><XCircle size={11} /> {t('Ended')}</Tag>
    case 'expired':
      return <Tag><Clock size={11} /> {t('Expired')}</Tag>
    default:
      return <Tag>{status}</Tag>
  }
}

function formatJoinUrl(url?: string): string {
  if (!url) return ''
  if (url.startsWith('/')) {
    return `${window.location.origin}${url}`
  }
  return url
}

export function CreateSupportDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (s: SupportSession) => void }) {
  const [targetName, setTargetName] = useState('')
  const [reason, setReason] = useState('')
  const [ticket, setTicket] = useState('')
  const [ttl, setTtl] = useState(30)
  const [saving, setSaving] = useState(false)
  const [created, setCreated] = useState<SupportSession | null>(null)
  const [copied, setCopied] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!targetName.trim()) return
    setSaving(true)
    try {
      const res = await api.post<SupportSession>('/support/sessions', {
        target_name: targetName.trim(),
        reason: reason.trim(),
        ticket: ticket.trim(),
        ttl_minutes: ttl,
      })
      invalidate('/support/sessions')
      setCreated(res)
      onCreated(res)
      toast.ok(t('Support session link generated'))
    } catch (err: any) {
      toast.err(err.message || t('Failed to create support session'))
    } finally {
      setSaving(false)
    }
  }

  const copyLink = () => {
    if (!created) return
    copy(formatJoinUrl(created.join_url))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
    toast.ok(t('Link copied to clipboard'))
  }

  if (created) {
    return (
      <Modal title={t('Support Session Ready')} onClose={onClose}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <p className="muted" style={{ margin: 0 }}>
            {t('Send this link to the remote user. They will run the lightweight assistant agent:')}
          </p>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input
              type="text"
              readOnly
              value={formatJoinUrl(created.join_url)}
              style={{ flex: 1, padding: '8px 12px', borderRadius: 4, border: '1px solid var(--border)' }}
            />
            <button className="btn btn-primary" onClick={copyLink} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? t('Copied') : t('Copy')}
            </button>
          </div>
          <div className="callout" style={{ padding: '12px 16px', background: 'var(--bg-subtle)', borderRadius: 6, fontSize: 13 }}>
            <strong>{t('Next step:')}</strong> {t('When the user runs the agent, they will see a 6-digit verification code on their screen. Ask them to dictate it to you.')}
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
            <button className="btn" onClick={onClose}>{t('Done')}</button>
          </div>
        </div>
      </Modal>
    )
  }

  return (
    <Modal title={t('New Remote Support Session')} onClose={onClose}>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Field label={t('Target machine or user')} help={t('Name or identifier of the computer needing support')}>
          <input
            autoFocus
            type="text"
            placeholder={t('e.g. Rodrigo - Laptop Dell')}
            value={targetName}
            onChange={(e) => setTargetName(e.target.value)}
            required
          />
        </Field>
        <Field label={t('Reason')} help={t('Describe the problem or task')}>
          <input
            type="text"
            placeholder={t('e.g. Configuration of VPN profile')}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </Field>
        <Field label={t('Ticket reference')} help={t('Optional ITSM ticket ID')}>
          <input
            type="text"
            placeholder={t('e.g. INC-4892')}
            value={ticket}
            onChange={(e) => setTicket(e.target.value)}
          />
        </Field>
        <Field label={t('Link expiration')} help={t('How long the invitation link remains valid')}>
          <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
            <option value={15}>15 {t('minutes')}</option>
            <option value={30}>30 {t('minutes')}</option>
            <option value={60}>1 {t('hour')}</option>
            <option value={120}>2 {t('hours')}</option>
          </select>
        </Field>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
          <button type="button" className="btn" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" className="btn btn-primary" disabled={saving || !targetName.trim()}>
            {saving ? <Spinner /> : <LifeBuoy size={14} />} {t('Generate Link')}
          </button>
        </div>
      </form>
    </Modal>
  )
}

export function VerifyTOTPDialog({ session, onClose, onVerified }: { session: SupportSession; onClose: () => void; onVerified: () => void }) {
  const [code, setCode] = useState('')
  const [verifying, setVerifying] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const cleanCode = code.replace(/\s+/g, '')
    if (cleanCode.length !== 6) return
    setVerifying(true)
    try {
      await api.post(`/support/sessions/${session.id}/verify-totp`, { code: cleanCode })
      invalidate('/support/sessions')
      toast.ok(t('Verification code verified. Remote control activated.'))
      onVerified()
      onClose()
    } catch (err: any) {
      toast.err(err.message || t('Invalid verification code. Please check with the user.'))
    } finally {
      setVerifying(false)
    }
  }

  return (
    <Modal title={t('Verify Remote Code')} onClose={onClose}>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <p className="muted" style={{ margin: 0 }}>
          {t('Enter the 6-digit verification code currently shown on {0}\'s screen:', session.target_name)}
        </p>
        <div style={{ display: 'flex', justifyContent: 'center', margin: '12px 0' }}>
          <input
            autoFocus
            type="text"
            inputMode="numeric"
            maxLength={6}
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            style={{
              fontSize: 32,
              letterSpacing: 8,
              textAlign: 'center',
              width: 240,
              padding: '8px 16px',
              fontWeight: 700,
              fontFamily: 'monospace',
            }}
          />
        </div>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0, textAlign: 'center' }}>
          {t('This dynamic code prevents unauthorized access. The user must dictate this code to you.')}
        </p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
          <button type="button" className="btn" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" className="btn btn-primary" disabled={verifying || code.length !== 6}>
            {verifying ? <Spinner /> : <Shield size={14} />} {t('Verify & Take Control')}
          </button>
        </div>
      </form>
    </Modal>
  )
}

export function SupportViewerModal({ session, onClose }: { session: SupportSession; onClose: () => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [stats, setStats] = useState<{ fps: number; frame: number } | null>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const painter = new Painter(canvas)
    painter.onCursor = (css) => (canvas.style.cursor = css)

    let frameCount = 0
    let lastTime = performance.now()

    const ws = new WebSocket(wsURL(`/support/sessions/${session.id}/ws`))
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      setError(null)
    }

    ws.onmessage = async (e) => {
      if (typeof e.data === 'string') return
      const buf = new Uint8Array(e.data)
      const op = parseDisplay(buf)
      if (op) {
        if (op.op === 'size') {
          canvas.width = op.w
          canvas.height = op.h
        }
        painter.push(op, op.op === 'sync' ? () => {
          if (ws.readyState === 1) ws.send(ackEvent(op.frame))
          frameCount++
          const now = performance.now()
          if (now - lastTime >= 1000) {
            const fps = Math.round((frameCount * 1000) / (now - lastTime))
            setStats({ fps, frame: op.frame })
            frameCount = 0
            lastTime = now
          }
        } : undefined)
      }
    }

    ws.onerror = () => {
      setError(t('WebSocket connection error'))
    }

    ws.onclose = () => {
      setConnected(false)
    }

    return () => {
      ws.close()
    }
  }, [session.id])

  const containerRef = useRef<HTMLDivElement>(null)
  const buttonsRef = useRef(0)
  const pressedRef = useRef<Map<string, { ks: number; sc: number }>>(new Map())

  const send = (b: Uint8Array) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(b)
    }
  }

  const toDesktop = (e: React.MouseEvent) => {
    const canvas = canvasRef.current
    if (!canvas) return null
    const r = canvas.getBoundingClientRect()
    if (!r.width || !r.height) return null
    const scaleX = canvas.width / r.width
    const scaleY = canvas.height / r.height
    return {
      x: Math.round((e.clientX - r.left) * scaleX),
      y: Math.round((e.clientY - r.top) * scaleY)
    }
  }

  const handlePointerMove = (e: React.MouseEvent) => {
    const p = toDesktop(e)
    if (p) send(pointerEvent(p.x, p.y, buttonsRef.current))
  }

  const handlePointerDown = (e: React.MouseEvent) => {
    e.preventDefault()
    containerRef.current?.focus()
    buttonsRef.current = buttonMask(e.buttons)
    const p = toDesktop(e)
    if (p) send(pointerEvent(p.x, p.y, buttonsRef.current))
  }

  const handlePointerUp = (e: React.MouseEvent) => {
    e.preventDefault()
    buttonsRef.current = buttonMask(e.buttons)
    const p = toDesktop(e)
    if (p) send(pointerEvent(p.x, p.y, buttonsRef.current))
  }

  const handleWheel = (e: React.WheelEvent) => {
    const p = toDesktop(e)
    if (!p) return
    const bit = e.deltaY < 0 ? 8 : e.deltaY > 0 ? 16 : e.deltaX < 0 ? 32 : 64
    send(pointerEvent(p.x, p.y, buttonsRef.current | bit))
    send(pointerEvent(p.x, p.y, buttonsRef.current))
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    e.preventDefault()
    const n = e.nativeEvent
    const ks = keysymFor(n)
    if (!ks) return
    const altGr = n.getModifierState('AltGraph')
    const printable = [...n.key].length === 1 && (altGr || (!n.ctrlKey && !n.altKey && !n.metaKey))
    const sc = printable ? 0 : scancodeFor(n)
    pressedRef.current.set(e.code, { ks, sc })
    send(keyEvent(ks, true, sc))
  }

  const handleKeyUp = (e: React.KeyboardEvent) => {
    e.preventDefault()
    const k = pressedRef.current.get(e.code)
    pressedRef.current.delete(e.code)
    if (k) send(keyEvent(k.ks, false, k.sc))
  }

  const endSession = async () => {
    if (await confirm({ title: t('End Support Session'), body: t('Are you sure you want to end this remote assistance session?') })) {
      try {
        await api.post(`/support/sessions/${session.id}/end`)
        invalidate('/support/sessions')
        toast.ok(t('Session ended'))
        onClose()
      } catch (err: any) {
        toast.err(err.message)
      }
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 800, background: '#111',
      display: 'flex', flexDirection: 'column'
    }}>
      <header style={{
        padding: '8px 16px', background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <LifeBuoy size={18} style={{ color: 'var(--primary)' }} />
          <strong>{session.target_name}</strong>
          <span className="muted" style={{ fontSize: 13 }}>{session.reason}</span>
          {connected ? (
            <Tag tone="ok"><CheckCircle2 size={11} /> {t('Live')}</Tag>
          ) : (
            <Tag tone="warn"><Clock size={11} /> {t('Connecting...')}</Tag>
          )}
          {stats && (
            <Tag tone="accent">
              <Monitor size={11} /> {stats.fps} FPS · #{stats.frame}
            </Tag>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <button className="btn btn-danger" onClick={endSession} style={{ fontSize: 13, padding: '4px 10px' }}>
            <X size={14} /> {t('End Session')}
          </button>
          <button className="icon-btn" onClick={onClose} title={t('Close Viewer')}>
            <X size={16} />
          </button>
        </div>
      </header>

      <div
        ref={containerRef}
        tabIndex={0}
        onMouseMove={handlePointerMove}
        onMouseDown={handlePointerDown}
        onMouseUp={handlePointerUp}
        onWheel={handleWheel}
        onContextMenu={(e) => e.preventDefault()}
        onKeyDown={handleKeyDown}
        onKeyUp={handleKeyUp}
        onClick={() => containerRef.current?.focus()}
        style={{
          flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          overflow: 'auto', background: '#0a0a0a', outline: 'none', cursor: 'default'
        }}
      >
        {error && <div style={{ color: 'var(--danger)', padding: 24 }}>{error}</div>}
        <canvas
          ref={canvasRef}
          width={1280}
          height={800}
          style={{
            maxWidth: '100%',
            maxHeight: '100%',
            objectFit: 'contain',
            imageRendering: 'auto',
            boxShadow: '0 4px 24px rgba(0,0,0,0.8)'
          }}
        />
      </div>
    </div>
  )
}

export function Support({ id: _id }: { id?: string }) {
  const { data: sessions, loading } = useResource<SupportSession[]>('/support/sessions')
  const [filter, setFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [showCreate, setShowCreate] = useState(false)
  const [verifyingSession, setVerifyingSession] = useState<SupportSession | null>(null)
  const [activeViewerSession, setActiveViewerSession] = useState<SupportSession | null>(null)

  const filtered = useMemo(() => {
    if (!sessions) return []
    return sessions.filter((s) => {
      if (statusFilter !== 'all' && s.status !== statusFilter) return false
      if (!filter) return true
      const q = filter.toLowerCase()
      return s.target_name.toLowerCase().includes(q) || s.reason.toLowerCase().includes(q) || s.ticket.toLowerCase().includes(q)
    })
  }, [sessions, filter, statusFilter])

  const copyLink = (s: SupportSession) => {
    copy(formatJoinUrl(s.join_url))
    toast.ok(t('Link copied to clipboard'))
  }

  const endSession = async (s: SupportSession) => {
    if (await confirm({ title: t('End Support Session'), body: t('End remote support for {0}?', s.target_name) })) {
      try {
        await api.post(`/support/sessions/${s.id}/end`)
        invalidate('/support/sessions')
        toast.ok(t('Support session ended'))
      } catch (err: any) {
        toast.err(err.message)
      }
    }
  }

  const columns: Column<SupportSession>[] = [
    {
      key: 'target',
      label: t('Target'),
      render: (s: SupportSession) => (
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <strong>{s.target_name}</strong>
          {s.reason && <span className="muted" style={{ fontSize: 12 }}>{s.reason}</span>}
        </div>
      ),
    },
    {
      key: 'ticket',
      label: t('Ticket'),
      render: (s: SupportSession) => s.ticket ? <code>{s.ticket}</code> : <span className="muted">—</span>,
    },
    {
      key: 'status',
      label: t('Status'),
      render: (s: SupportSession) => <StatusBadge status={s.status} />,
    },
    {
      key: 'expires',
      label: t('Expires'),
      render: (s: SupportSession) => (
        <span className="muted" style={{ fontSize: 12 }} title={dateTime(s.expires_at)}>
          {ago(s.expires_at)}
        </span>
      ),
    },
    {
      key: 'actions',
      label: '',
      render: (s: SupportSession) => (
        <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
          {s.status === 'active' && (
            <button
              className="btn btn-primary"
              style={{ fontSize: 12, padding: '3px 8px' }}
              onClick={() => setActiveViewerSession(s)}
            >
              <Monitor size={12} /> {t('Open Screen')}
            </button>
          )}
          {(s.status === 'pending' || s.status === 'connected') && (
            <button
              className="btn btn-primary"
              style={{ fontSize: 12, padding: '3px 8px' }}
              onClick={() => setVerifyingSession(s)}
            >
              <KeyRound size={12} /> {t('Verify Code')}
            </button>
          )}
          {s.status !== 'ended' && s.status !== 'expired' && (
            <>
              <button
                className="icon-btn"
                title={t('Copy support link')}
                onClick={() => copyLink(s)}
              >
                <Copy size={14} />
              </button>
              <button
                className="icon-btn danger"
                title={t('End session')}
                onClick={() => endSession(s)}
              >
                <X size={14} />
              </button>
            </>
          )}
        </div>
      ),
    },
  ]

  return (
    <div className="page" style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22 }}>{t('Remote Support')}</h1>
          <p className="muted" style={{ margin: '4px 0 0', fontSize: 13 }}>
            {t('Generate on-demand assistance sessions with screen sharing, TOTP verification and local user priority.')}
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Plus size={16} /> {t('New Support Session')}
        </button>
      </div>

      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        <div style={{ position: 'relative', flex: 1 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder={t('Search by machine, reason or ticket...')}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{ width: '100%', paddingLeft: 32 }}
          />
        </div>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="all">{t('All statuses')}</option>
          <option value="pending">{t('Pending')}</option>
          <option value="connected">{t('Agent connected')}</option>
          <option value="active">{t('Active')}</option>
          <option value="ended">{t('Ended')}</option>
        </select>
        <button className="icon-btn" onClick={() => invalidate('/support/sessions')} title={t('Refresh')}>
          <RefreshCw size={14} />
        </button>
      </div>

      {loading ? (
        <div className="center" style={{ padding: 48 }}><Spinner /></div>
      ) : filtered.length === 0 ? (
        <Empty
          icon={<LifeBuoy size={32} />}
          title={t('No support sessions found')}
          action={
            <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
              <Plus size={14} /> {t('New Support Session')}
            </button>
          }
        >
          {t('Create a session to invite a remote user to share their screen.')}
        </Empty>
      ) : (
        <DataTable rows={filtered} columns={columns} rowKey={(s) => s.id} />
      )}

      {showCreate && (
        <CreateSupportDialog
          onClose={() => setShowCreate(false)}
          onCreated={(s) => {
            if (s.status === 'connected') setVerifyingSession(s)
          }}
        />
      )}

      {verifyingSession && (
        <VerifyTOTPDialog
          session={verifyingSession}
          onClose={() => setVerifyingSession(null)}
          onVerified={() => setActiveViewerSession(verifyingSession)}
        />
      )}

      {activeViewerSession && (
        <SupportViewerModal
          session={activeViewerSession}
          onClose={() => setActiveViewerSession(null)}
        />
      )}
    </div>
  )
}
