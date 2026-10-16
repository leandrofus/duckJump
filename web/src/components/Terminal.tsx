import { t } from '../i18n'
import { useEffect, useRef, useState } from 'react'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { RotateCw, Maximize2, Minimize2, Circle } from 'lucide-react'
import { enc, wsURL } from '../lib/api'
import { useMenu } from '../ui/ContextMenu'
import type { PromptedCredentials } from './CredentialsDialog'

const theme = {
  background: '#0e1726',
  foreground: '#e5ebf5',
  cursor: '#ffd84a',
  selectionBackground: '#28456e',
  black: '#16213a',
  brightBlack: '#5b6a84',
}

export type SessionState = 'connecting' | 'open' | 'closed' | 'error'

/** A terminal session to a connection over the gateway's WebSocket tunnel:
 *  binary frames carry terminal bytes, text frames JSON control messages. */
export function TerminalSession({ connectionId, title, recorded, credentials, onNeedCredentials }: {
  connectionId: string
  title: string
  recorded?: boolean
  credentials?: PromptedCredentials
  onNeedCredentials?: (code: string, reason: string) => void
}) {
  const host = useRef<HTMLDivElement>(null)
  const term = useRef<XTerm | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<SessionState>('connecting')
  const [message, setMessage] = useState('')
  const [full, setFull] = useState(false)
  const menu = useMenu()

  useEffect(() => {
    if (!host.current) return
    const x = new XTerm({
      fontFamily: '"JetBrains Mono", "Fira Code", ui-monospace, Menlo, monospace',
      fontSize: 14,
      cursorBlink: true,
      theme,
      scrollback: 10000,
    })
    const fit = new FitAddon()
    x.loadAddon(fit)
    x.open(host.current)
    fit.fit()
    term.current = x
    setState('connecting')
    setMessage('')
    x.write(`\x1b[2m${t('Connecting to {0}…', title)}\x1b[0m\r\n`)
    const ws = new WebSocket(wsURL(`/connections/${enc(connectionId)}/session?cols=${x.cols}&rows=${x.rows}${credentials ? '&credentials=1' : ''}`))
    if (credentials) ws.onopen = () => ws.send(JSON.stringify({ type: 'credentials', ...credentials }))
    ws.binaryType = 'arraybuffer'
    const encoder = new TextEncoder()
    let ended = false
    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') return x.write(new Uint8Array(ev.data))
      let m: any
      try {
        m = JSON.parse(ev.data)
      } catch {
        return
      }
      if (m.type === 'ready') {
        setState('open')
        x.focus()
      } else if (m.type === 'exit') {
        ended = true
        x.write(`\r\n\x1b[2m[${m.status != null ? t('session ended, exit status {0}', m.status) : t('session ended')}]\x1b[0m\r\n`)
        if (m.reason) setMessage(t('The server ended the session: {0}', m.reason))
      } else if (m.type === 'error') {
        ended = true
        setState('error')
        setMessage(m.message)
        x.write(`\r\n\x1b[31m${m.message}\x1b[0m\r\n`)
        if (onNeedCredentials && (m.code === 'credentials_required' || (credentials && m.code === 'auth_failed'))) onNeedCredentials(m.code, m.message)
      }
    }
    ws.onclose = (ev) => {
      if (ended) return setState((s) => (s === 'error' ? s : 'closed'))
      // Closed before any frame: the upgrade was refused (no grant, not found…).
      setState((s) => (s === 'connecting' ? 'error' : 'closed'))
      if (ev.code === 1006) setMessage((m) => m || t('Could not open the session (no access, or the gateway is unreachable).'))
    }
    const d1 = x.onData((d) => ws.readyState === 1 && ws.send(encoder.encode(d)))
    const d2 = x.onBinary((d) => ws.readyState === 1 && ws.send(Uint8Array.from(d, (c) => c.charCodeAt(0))))
    const d3 = x.onResize(({ cols, rows }) => ws.readyState === 1 && ws.send(JSON.stringify({ type: 'resize', cols, rows })))
    const ro = new ResizeObserver(() => {
      try {
        fit.fit()
      } catch {}
    })
    ro.observe(host.current)
    return () => {
      d1.dispose()
      d2.dispose()
      d3.dispose()
      ro.disconnect()
      ws.close()
      x.dispose()
      term.current = null
    }
  }, [connectionId, attempt, credentials])

  const ctx = menu(() => [
    { label: t('Copy selection'), disabled: !term.current?.hasSelection(), hint: 'Ctrl+Shift+C', onClick: () => navigator.clipboard.writeText(term.current?.getSelection() || '') },
    { label: t('Paste'), hint: 'Ctrl+Shift+V', onClick: async () => term.current?.paste(await navigator.clipboard.readText()) },
    { label: t('Select all'), onClick: () => term.current?.selectAll() },
    { label: t('Clear screen'), onClick: () => term.current?.clear() },
    'sep',
    { label: t('Reconnect'), onClick: () => setAttempt((n) => n + 1) },
    { label: full ? t('Exit full screen') : t('Full screen'), onClick: () => setFull(!full) },
  ])

  const stateLabel = { connecting: t('Connecting'), open: t('Connected'), closed: t('Disconnected'), error: t('Error') }[state]
  return (
    <div className={`terminal session-terminal${full ? ' full' : ''}`}>
      <div className="terminal-bar">
        <span className={`dot dot-${state === 'open' ? 'open' : state === 'connecting' ? 'connecting' : 'closed'}`} />
        <strong className="ellipsis">{title}</strong>
        <span className="muted small">{stateLabel}</span>
        {recorded && state === 'open' && (
          <span className="rec-badge" title={t('This session is recorded and audited.')}><Circle size={8} fill="currentColor" /> {t('Recording')}</span>
        )}
        <span className="grow" />
        <button className="icon-btn" title={t('Reconnect')} onClick={() => setAttempt((n) => n + 1)}><RotateCw size={15} /></button>
        <button className="icon-btn" title={t('Full screen')} onClick={() => setFull(!full)}>{full ? <Minimize2 size={15} /> : <Maximize2 size={15} />}</button>
      </div>
      <div className="terminal-host" ref={host} onContextMenu={ctx} />
      {(state === 'closed' || state === 'error') && (
        <div className="terminal-closed">
          {message ? <span className="tone-bad">{message}</span> : t('Session closed')} ·{' '}
          <button className="link" onClick={() => setAttempt((n) => n + 1)}>{t('reconnect')}</button>
        </div>
      )}
    </div>
  )
}
