import { t as tr } from '../i18n'
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { CheckCircle2, X, XCircle, AlertTriangle, Info } from 'lucide-react'

// ---------- tiny global bus ----------
type Listener = () => void
function bus<T>(initial: T) {
  let value = initial
  const ls = new Set<Listener>()
  return {
    get: () => value,
    set: (v: T) => {
      value = v
      ls.forEach((l) => l())
    },
    use(): T {
      const [, f] = useState(0)
      useEffect(() => {
        const l = () => f((n) => n + 1)
        ls.add(l)
        return () => {
          ls.delete(l)
        }
      }, [])
      return value
    },
  }
}

// ---------- toasts ----------
interface ToastT {
  id: number
  kind: 'ok' | 'err' | 'info'
  text: string
}
const toasts = bus<ToastT[]>([])
let tid = 0
function push(kind: ToastT['kind'], text: string, ms = 4500) {
  const id = ++tid
  toasts.set([...toasts.get(), { id, kind, text }])
  setTimeout(() => toasts.set(toasts.get().filter((t) => t.id !== id)), ms)
}
export const toast = {
  ok: (t: string) => push('ok', t),
  err: (t: unknown) => push('err', t instanceof Error ? t.message : String(t), 8000),
  info: (t: string) => push('info', t),
}

function Toaster() {
  const list = toasts.use()
  return (
    <div className="toasts">
      {list.map((t) => (
        <div key={t.id} className={`toast toast-${t.kind}`}>
          {t.kind === 'ok' ? <CheckCircle2 size={16} /> : t.kind === 'err' ? <XCircle size={16} /> : <Info size={16} />}
          <span>{t.text}</span>
          <button className="icon-btn" onClick={() => toasts.set(toasts.get().filter((x) => x.id !== t.id))}>
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  )
}

// ---------- modal / dialogs ----------
export function Modal({
  title,
  children,
  onClose,
  footer,
  wide,
  icon,
}: {
  title: ReactNode
  children: ReactNode
  onClose: () => void
  footer?: ReactNode
  wide?: boolean | 'xl'
  icon?: ReactNode
}) {
  useEffect(() => {
    const on = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', on)
    return () => window.removeEventListener('keydown', on)
  }, [onClose])
  return createPortal(
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal${wide === 'xl' ? ' modal-xl' : wide ? ' modal-wide' : ''}`} role="dialog">
        <div className="modal-head">
          {icon}
          <h3>{title}</h3>
          <button className="icon-btn" onClick={onClose} aria-label={tr('Close')}>
            <X size={16} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>,
    document.body,
  )
}

type DialogFn = (close: () => void) => ReactNode
const dialogs = bus<{ id: number; render: DialogFn }[]>([])
let did = 0

/** Mount an arbitrary modal imperatively. */
export function openDialog(render: DialogFn) {
  const id = ++did
  const close = () => dialogs.set(dialogs.get().filter((d) => d.id !== id))
  dialogs.set([...dialogs.get(), { id, render: () => render(close) }])
  return close
}

export function confirm(opts: { title: string; body?: ReactNode; confirm?: string; danger?: boolean; check?: string }): Promise<false | { checked: boolean }> {
  return new Promise((resolve) => {
    openDialog((close) => <ConfirmDialog {...opts} onDone={(v) => (close(), resolve(v))} />)
  })
}

function ConfirmDialog(props: { title: string; body?: ReactNode; confirm?: string; danger?: boolean; check?: string; onDone: (v: false | { checked: boolean }) => void }) {
  const [checked, setChecked] = useState(false)
  return (
    <Modal
      title={props.title}
      icon={props.danger ? <AlertTriangle size={18} className="tone-bad" /> : undefined}
      onClose={() => props.onDone(false)}
      footer={
        <>
          <button className="btn" onClick={() => props.onDone(false)}>
            {tr('Cancel')}
          </button>
          <button autoFocus className={`btn ${props.danger ? 'btn-danger' : 'btn-primary'}`} onClick={() => props.onDone({ checked })}>
            {props.confirm || tr('Confirm')}
          </button>
        </>
      }
    >
      {props.body && <div className="muted">{props.body}</div>}
      {props.check && (
        <label className="check" style={{ marginTop: 12 }}>
          <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} /> {props.check}
        </label>
      )}
    </Modal>
  )
}

export function prompt(opts: { title: string; label?: string; value?: string; placeholder?: string; confirm?: string; help?: ReactNode }): Promise<string | null> {
  return new Promise((resolve) => {
    openDialog((close) => <PromptDialog {...opts} onDone={(v) => (close(), resolve(v))} />)
  })
}

function PromptDialog(props: { title: string; label?: string; value?: string; placeholder?: string; confirm?: string; help?: ReactNode; onDone: (v: string | null) => void }) {
  const [v, setV] = useState(props.value ?? '')
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    ref.current?.focus()
    ref.current?.select()
  }, [])
  return (
    <Modal
      title={props.title}
      onClose={() => props.onDone(null)}
      footer={
        <>
          <button className="btn" onClick={() => props.onDone(null)}>
            {tr('Cancel')}
          </button>
          <button className="btn btn-primary" disabled={!v.trim()} onClick={() => props.onDone(v.trim())}>
            {props.confirm || tr('OK')}
          </button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (v.trim()) props.onDone(v.trim())
        }}
      >
        <label className="field">
          {props.label && <span>{props.label}</span>}
          <input ref={ref} value={v} placeholder={props.placeholder} onChange={(e) => setV(e.target.value)} />
        </label>
        {props.help && <p className="help">{props.help}</p>}
      </form>
    </Modal>
  )
}

function DialogHost() {
  const list = dialogs.use()
  return (
    <>
      {list.map((d) => (
        <div key={d.id}>{d.render(() => {})}</div>
      ))}
    </>
  )
}

// ---------- drawer (record preview) ----------
export function Drawer({ children, onClose, width = 560 }: { children: ReactNode; onClose: () => void; width?: number }) {
  useEffect(() => {
    const on = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', on)
    return () => window.removeEventListener('keydown', on)
  }, [onClose])
  return createPortal(
    <div className="drawer-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside className="drawer" style={{ width }}>
        {children}
      </aside>
    </div>,
    document.body,
  )
}

export function OverlayHost() {
  return (
    <>
      <DialogHost />
      <Toaster />
    </>
  )
}
