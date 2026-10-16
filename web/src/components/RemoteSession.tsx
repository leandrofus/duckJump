import { t } from '../i18n'
import { useEffect, useRef, useState } from 'react'
import { RotateCw, Maximize2, Minimize2, Circle, ClipboardList, Keyboard, Scaling, Send, Copy, X, Users, CheckCircle2, Eye, Shield, Hand } from 'lucide-react'
import { enc, wsURL } from '../lib/api'
import { KIND_DISPLAY, KEYSYM, SCANCODE, Painter, ackEvent, buttonMask, keyEvent, keysymFor, parseDisplay, pointerEvent, scancodeFor } from '../lib/gfx'
import { toast } from '../ui/overlays'
import type { SessionState } from './Terminal'
import type { PromptedCredentials } from './CredentialsDialog'
import { sessionErrorText } from '../lib/session'
import { ShareSessionDialog } from './ShareSessionDialog'
import type { Participant } from './ShareSessionDialog'

/** A graphical session (VNC or RDP) drawn on a canvas. */
export function RemoteSession({ connectionId, joinSessionId, shareToken, title, recorded, protocol, credentials, onNeedCredentials, onUnverifiedKey }: {
  connectionId: string
  joinSessionId?: string
  shareToken?: string
  title: string
  recorded?: boolean
  protocol: string
  credentials?: PromptedCredentials
  /** The server wants (other) credentials: the parent asks the user. */
  onNeedCredentials?: (code: string, reason: string) => void
  /** The server shows a key nobody approved yet (its fingerprint). */
  onUnverifiedKey?: (fingerprint: string) => void
}) {
  const host = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<SessionState>('connecting')
  const [message, setMessage] = useState('')
  const [full, setFull] = useState(false)
  const [fit, setFit] = useState(true)
  const [size, setSize] = useState({ w: 0, h: 0 })
  const [scale, setScale] = useState(1)
  const [clipOpen, setClipOpen] = useState(false)
  const [clipText, setClipText] = useState('')

  const [sessionId, setSessionId] = useState<string>(joinSessionId || '')
  const [myId, setMyId] = useState<string>('')
  const [isOwner, setIsOwner] = useState<boolean>(!joinSessionId)
  const [hasControl, setHasControl] = useState<boolean>(!joinSessionId)
  const hasControlRef = useRef<boolean>(!joinSessionId)
  const [controllerName, setControllerName] = useState<string>('')
  const [participants, setParticipants] = useState<Participant[]>([])
  const [shareOpen, setShareOpen] = useState(false)

  const updateControl = (has: boolean) => {
    if (!has && hasControlRef.current) {
      releaseAll()
    }
    hasControlRef.current = has
    setHasControl(has)
  }

  const send = (b: Uint8Array) => wsRef.current?.readyState === 1 && wsRef.current.send(b)

  useEffect(() => {
    const canvas = canvasRef.current!
    const painter = new Painter(canvas)
    painter.onCursor = (css) => (canvas.style.cursor = css)
    setState('connecting')
    setMessage('')
    // RDP lets the client pick the desktop size: ask for the space we have.
    const el = host.current
    const q = new URLSearchParams()
    if (protocol === 'rdp' && el) {
      q.set('width', String(Math.max(640, el.clientWidth & ~1)))
      q.set('height', String(Math.max(480, el.clientHeight & ~1)))
    }
    if (credentials) q.set('credentials', '1')
    const wsEndpoint = joinSessionId
      ? `/sessions/${enc(joinSessionId)}/join${shareToken ? `?token=${enc(shareToken)}` : ''}`
      : `/connections/${enc(connectionId)}/session${q.size ? '?' + q : ''}`
    const ws = new WebSocket(wsURL(wsEndpoint))
    // Prompted credentials travel as the first message, never in the URL.
    if (credentials && !joinSessionId) ws.onopen = () => ws.send(JSON.stringify({ type: 'credentials', ...credentials }))
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws
    let ended = false
    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') {
        const b = new Uint8Array(ev.data)
        if (b[0] !== KIND_DISPLAY) return
        const op = parseDisplay(b.subarray(1))
        if (!op) return
        if (op.op === 'size') setSize({ w: op.w, h: op.h })
        // Ack a frame only once it is drawn: that is the flow control.
        painter.push(op, op.op === 'sync' ? () => ws.readyState === 1 && ws.send(ackEvent(op.frame)) : undefined)
        return
      }
      let m: any
      try {
        m = JSON.parse(ev.data)
      } catch {
        return
      }
      if (m.type === 'ready') {
        setState('open')
        canvas.focus()
        if (m.session_id) setSessionId(m.session_id)
        if (m.my_id) setMyId(m.my_id)
        if (m.is_owner != null) setIsOwner(Boolean(m.is_owner))
        if (m.has_control != null) updateControl(Boolean(m.has_control))
        if (m.controller_name) setControllerName(m.controller_name)
      } else if (m.type === 'presence') {
        if (m.participants) setParticipants(m.participants)
        if (m.has_control != null) updateControl(Boolean(m.has_control))
        if (m.controller_name) setControllerName(m.controller_name)
      } else if (m.type === 'control_granted') {
        if (m.controller_name) setControllerName(m.controller_name)
        const granted = m.controller === myId
        updateControl(granted)
        if (granted) {
          toast.ok(t('You now have control of the session'))
        } else {
          toast.info(t('Control transferred to {0}', m.controller_name))
        }
      } else if (m.type === 'control_requested') {
        toast.info(t('{0} has requested session control', m.from_name || t('A participant')))
      } else if (m.type === 'clipboard') {
        setClipText(m.text)
        toast.info(t('The remote clipboard changed; open the clipboard panel to copy it.'))
      } else if (m.type === 'exit') {
        ended = true
        setState('closed')
        if (m.reason) setMessage(t('The server ended the session: {0}', m.reason))
      } else if (m.type === 'error') {
        ended = true
        setState('error')
        setMessage(sessionErrorText(m))
        if (onNeedCredentials && (m.code === 'credentials_required' || (credentials && m.code === 'auth_failed'))) onNeedCredentials(m.code, m.message)
        if (onUnverifiedKey && m.code === 'host_key_unverified' && m.fingerprint) onUnverifiedKey(m.fingerprint)
      }
    }
    ws.onclose = (ev) => {
      if (ended) return
      setState((s) => (s === 'connecting' ? 'error' : 'closed'))
      if (ev.code === 1006) setMessage((m) => m || t('Could not open the session (no access, or the gateway is unreachable).'))
    }
    return () => {
      ws.close()
      painter.dispose()
      wsRef.current = null
    }
  }, [connectionId, joinSessionId, shareToken, attempt, credentials])

  // Scale the desktop to the space available (or 1:1).
  useEffect(() => {
    const el = host.current
    if (!el || !size.w) return
    const update = () => setScale(fit ? Math.min(el.clientWidth / size.w, el.clientHeight / size.h, 1) || 1 : 1)
    update()
    const ro = new ResizeObserver(update)
    ro.observe(el)
    return () => ro.disconnect()
  }, [fit, size.w, size.h, full])

  // ---- input ----
  // Per physical key: what was sent on press, so the release matches it.
  const pressed = useRef(new Map<string, { ks: number; sc: number }>())
  const buttons = useRef(0)
  const lastMove = useRef<{ x: number; y: number } | null>(null)
  const raf = useRef(0)

  const toDesktop = (e: { clientX: number; clientY: number }) => {
    const c = canvasRef.current!
    const r = c.getBoundingClientRect()
    return { x: ((e.clientX - r.left) * c.width) / r.width, y: ((e.clientY - r.top) * c.height) / r.height }
  }
  const onMove = (e: React.MouseEvent) => {
    if (!hasControlRef.current) return
    lastMove.current = toDesktop(e)
    if (!raf.current) {
      // Coalesce moves to one event per animation frame.
      raf.current = requestAnimationFrame(() => {
        raf.current = 0
        const p = lastMove.current
        if (p) send(pointerEvent(p.x, p.y, buttons.current))
      })
    }
  }
  const onButton = (e: React.MouseEvent) => {
    e.preventDefault()
    canvasRef.current?.focus()
    if (!hasControlRef.current) return
    buttons.current = buttonMask(e.buttons)
    const p = toDesktop(e)
    send(pointerEvent(p.x, p.y, buttons.current))
  }
  const onWheel = (e: React.WheelEvent) => {
    if (!hasControlRef.current) return
    const p = toDesktop(e)
    const bit = e.deltaY < 0 ? 8 : e.deltaY > 0 ? 16 : e.deltaX < 0 ? 32 : 64
    send(pointerEvent(p.x, p.y, buttons.current | bit))
    send(pointerEvent(p.x, p.y, buttons.current))
  }
  const onKey = (down: boolean) => (e: React.KeyboardEvent) => {
    if (!hasControlRef.current) return
    e.preventDefault()
    const n = e.nativeEvent
    if (down) {
      const ks = keysymFor(n)
      if (!ks) return
      // Text goes as the character itself (no scancode), so it arrives
      // exactly whatever keyboard layouts the client and server use.
      // Special keys and shortcuts (Ctrl/Alt/Meta combos) go as physical
      // scancodes. AltGr reports Ctrl+Alt but produces text.
      const altGr = n.getModifierState('AltGraph')
      const printable = [...n.key].length === 1 && (altGr || (!n.ctrlKey && !n.altKey && !n.metaKey))
      const sc = printable ? 0 : scancodeFor(n)
      pressed.current.set(e.code, { ks, sc })
      send(keyEvent(ks, true, sc))
    } else {
      // Release what was pressed for this physical key, even if the
      // modifiers changed meanwhile.
      const k = pressed.current.get(e.code)
      pressed.current.delete(e.code)
      if (k) send(keyEvent(k.ks, false, k.sc))
    }
  }
  const releaseAll = () => {
    if (!hasControlRef.current) return
    for (const k of pressed.current.values()) send(keyEvent(k.ks, false, k.sc))
    pressed.current.clear()
  }
  const ctrlAltDel = () => {
    if (!hasControlRef.current) return
    const keys: [number, number][] = [[KEYSYM.Control_L, SCANCODE.Control_L], [KEYSYM.Alt_L, SCANCODE.Alt_L], [KEYSYM.Delete, SCANCODE.Delete]]
    for (const [k, sc] of keys) send(keyEvent(k, true, sc))
    for (const [k, sc] of [...keys].reverse()) send(keyEvent(k, false, sc))
    canvasRef.current?.focus()
  }
  const sendClipboard = () => {
    if (!hasControlRef.current) {
      toast.err(t('You must have session control to send clipboard'))
      return
    }
    wsRef.current?.readyState === 1 && wsRef.current.send(JSON.stringify({ type: 'clipboard', text: clipText }))
    toast.ok(t('Sent to the remote clipboard'))
  }

  const yieldControl = (targetParticipantId: string) => {
    wsRef.current?.readyState === 1 && wsRef.current.send(JSON.stringify({ type: 'yield_control', to: targetParticipantId }))
  }

  const takeControl = () => {
    wsRef.current?.readyState === 1 && wsRef.current.send(JSON.stringify({ type: 'take_control' }))
  }

  const requestControl = () => {
    wsRef.current?.readyState === 1 && wsRef.current.send(JSON.stringify({ type: 'request_control' }))
    toast.ok(t('Control requested'))
  }

  const stateLabel = { connecting: t('Connecting'), open: t('Connected'), closed: t('Disconnected'), error: t('Error') }[state]
  return (
    <div className={`terminal session-terminal remote${full ? ' full' : ''}`}>
      <div className="terminal-bar">
        <span className={`dot dot-${state === 'open' ? 'open' : state === 'connecting' ? 'connecting' : 'closed'}`} />
        <strong className="ellipsis">{title}</strong>
        <span className="muted small">{stateLabel}{size.w ? ` · ${size.w}×${size.h}${scale < 1 ? ` · ${Math.round(scale * 100)}%` : ''}` : ''}</span>
        {recorded && state === 'open' && <span className="rec-badge" title={t('This session is recorded and audited.')}><Circle size={8} fill="currentColor" /> {t('Recording')}</span>}
        {state === 'open' && (
          <>
            {hasControl ? (
              <span className="rec-badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8' }} title={t('You have control')}>
                <CheckCircle2 size={11} /> {t('Control')}
              </span>
            ) : (
              <span className="rec-badge" style={{ background: 'rgba(234, 179, 8, 0.15)', color: '#eab308' }} title={t('View-only mode')}>
                <Eye size={11} /> {t('View-only (Control: {0})', controllerName || t('Owner'))}
              </span>
            )}
            {!hasControl && isOwner && (
              <button className="btn btn-xs btn-outline" onClick={takeControl} title={t('Reclaim control')}>
                <Shield size={12} /> {t('Reclaim control')}
              </button>
            )}
            {!hasControl && !isOwner && (
              <button className="btn btn-xs btn-outline" onClick={requestControl} title={t('Request control')}>
                <Hand size={12} /> {t('Request control')}
              </button>
            )}
            <button
              className={`btn btn-xs${participants.length > 1 ? ' btn-primary' : ' btn-outline'}`}
              onClick={() => setShareOpen(true)}
              title={t('Share session')}
            >
              <Users size={12} /> {participants.length > 1 ? participants.length : t('Share')}
            </button>
          </>
        )}
        <span className="grow" />
        <button className="icon-btn" title="Ctrl+Alt+Del" onClick={ctrlAltDel} disabled={state !== 'open' || !hasControl}><Keyboard size={15} /></button>
        <button className={`icon-btn${clipOpen ? ' on' : ''}`} title={t('Clipboard')} onClick={() => setClipOpen(!clipOpen)}><ClipboardList size={15} /></button>
        <button className={`icon-btn${fit ? ' on' : ''}`} title={fit ? t('Actual size (1:1)') : t('Fit to window')} onClick={() => setFit(!fit)}><Scaling size={15} /></button>
        <button className="icon-btn" title={t('Reconnect')} onClick={() => setAttempt((n) => n + 1)}><RotateCw size={15} /></button>
        <button className="icon-btn" title={t('Full screen')} onClick={() => setFull(!full)}>{full ? <Minimize2 size={15} /> : <Maximize2 size={15} />}</button>
      </div>
      {clipOpen && (
        <div className="clip-panel">
          <textarea className="mono" rows={3} placeholder={t('Paste here to send it to the remote clipboard; text copied on the remote shows up here.')} value={clipText} onChange={(e) => setClipText(e.target.value)} />
          <div className="row gap">
            <button className="btn btn-sm" disabled={!clipText || !hasControl} onClick={sendClipboard}><Send size={13} /> {t('Send to remote')}</button>
            <button className="btn btn-sm" disabled={!clipText} onClick={() => navigator.clipboard.writeText(clipText).then(() => toast.ok(t('Copied')))}><Copy size={13} /> {t('Copy here')}</button>
            <span className="grow" />
            <button className="icon-btn" onClick={() => setClipOpen(false)}><X size={14} /></button>
          </div>
        </div>
      )}
      <div className={`remote-host${fit ? ' fit' : ''}`} ref={host}>
        <canvas
          ref={canvasRef}
          tabIndex={0}
          // No width/height props: assigning them clears the canvas. The
          // Painter sets the size on SIZE operations.
          style={{ width: size.w ? size.w * scale : undefined, height: size.h ? size.h * scale : undefined }}
          onMouseMove={onMove}
          onMouseDown={onButton}
          onMouseUp={onButton}
          onWheel={onWheel}
          onContextMenu={(e) => e.preventDefault()}
          onKeyDown={onKey(true)}
          onKeyUp={onKey(false)}
          onBlur={releaseAll}
        />
      </div>
      {(state === 'closed' || state === 'error') && (
        <div className="terminal-closed">
          {message ? <span className="tone-bad">{message}</span> : t('Session closed')} · <button className="link" onClick={() => setAttempt((n) => n + 1)}>{t('reconnect')}</button>
        </div>
      )}
      {shareOpen && (sessionId || joinSessionId) && (
        <ShareSessionDialog
          sessionId={sessionId || joinSessionId!}
          connectionId={connectionId}
          participants={participants.length > 0 ? participants : [{
            id: myId || 'owner',
            user_id: '',
            username: controllerName || 'Me',
            is_owner: isOwner,
            has_control: hasControl,
          }]}
          myId={myId}
          isOwner={isOwner}
          hasControl={hasControl}
          controllerName={controllerName}
          onYieldControl={yieldControl}
          onTakeControl={takeControl}
          onClose={() => setShareOpen(false)}
        />
      )}
    </div>
  )
}
