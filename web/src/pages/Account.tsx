import { t } from '../i18n'
import { useState } from 'react'
import { UserCog, KeyRound, ShieldCheck, ShieldOff } from 'lucide-react'
import { renderSVG } from 'uqr'
import { api } from '../lib/api'
import type { Me } from '../lib/api'
import { getMe, setMe } from '../lib/session'
import { Section, Tag } from '../ui/common'
import { Modal, openDialog, toast } from '../ui/overlays'
import { Field } from '../components/FormBits'
import { RoleTag } from './Users'

const refreshMe = () => api.get<Me>('/auth/me').then(setMe)

export function Account() {
  const [, force] = useState(0)
  const me = getMe()!
  const u = me.user
  if (me.dev) return <div className="page"><div className="alert alert-warn">{t('There are no accounts in dev mode.')}</div></div>
  return (
    <div className="page">
      <div className="page-head"><div className="page-title"><UserCog size={20} /><h1>{t('My account')}</h1></div></div>
      <div className="page-body narrow">
        <Section title={t('Profile')}>
          <p><strong>{u.display_name || u.username}</strong> <span className="muted mono">{u.username}</span> <RoleTag role={u.role} /></p>
          {me.groups && me.groups.length > 0 && <p className="tags">{me.groups.map((g) => <Tag key={g.id}>{g.name}</Tag>)}</p>}
        </Section>
        <Section title={t('Password')}>
          <PasswordForm />
        </Section>
        <Section title={t('Two-step verification (TOTP)')}>
          {u.totp_enabled ? (
            <div className="row gap wrap">
              <span className="tag tag-ok"><ShieldCheck size={13} /> {t('Enabled')}</span>
              <button className="btn btn-sm" onClick={() => openDialog((c) => <DisableTOTP onClose={c} onDone={() => refreshMe().then(() => force((n) => n + 1))} />)}><ShieldOff size={13} /> {t('Disable')}</button>
            </div>
          ) : (
            <div className="row gap wrap">
              <span className="muted">{t('Protect your account with a code from an authenticator app (Google Authenticator, Aegis, 1Password…).')}</span>
              <button className="btn btn-primary btn-sm" onClick={() => openDialog((c) => <EnrollTOTP onClose={c} onDone={() => refreshMe().then(() => force((n) => n + 1))} />)}><ShieldCheck size={13} /> {t('Enable')}</button>
            </div>
          )}
        </Section>
      </div>
    </div>
  )
}

function PasswordForm() {
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const save = (e: React.FormEvent) => {
    e.preventDefault()
    api.put('/auth/me/password', { current: cur, new: next }).then(() => {
      toast.ok(t('Password changed. Your other sessions were closed.'))
      setCur(''), setNext(''), setAgain('')
    }, toast.err)
  }
  return (
    <form className="grid-2" onSubmit={save}>
      <Field label={t('Current password')} span><input type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} /></Field>
      <Field label={t('New password')} help={t('At least 10 characters.')}><input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></Field>
      <Field label={t('Repeat it')} help={again && again !== next ? <span className="tone-bad">{t('They do not match.')}</span> : undefined}><input type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} /></Field>
      <div><button className="btn btn-primary" disabled={!cur || next.length < 10 || next !== again}><KeyRound size={14} /> {t('Change password')}</button></div>
    </form>
  )
}

function EnrollTOTP({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [enr, setEnr] = useState<{ secret: string; otpauth_url: string } | null>(null)
  const [code, setCode] = useState('')
  const [err, setErr] = useState('')
  if (!enr) api.post('/auth/me/totp/enroll').then(setEnr, (e) => (toast.err(e), onClose()))
  const confirm = () =>
    api.post('/auth/me/totp/confirm', { code }).then(
      () => (toast.ok(t('Two-step verification enabled')), onDone(), onClose()),
      (e) => (setErr(e.message), setCode('')),
    )
  return (
    <Modal title={t('Enable two-step verification')} icon={<ShieldCheck size={18} />} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" disabled={code.length !== 6} onClick={confirm}>{t('Enable')}</button></>}>
      {enr && (
        <>
          <p>{t('1. Scan the code with your authenticator app:')}</p>
          <div className="qr" dangerouslySetInnerHTML={{ __html: renderSVG(enr.otpauth_url, { border: 2 }) }} />
          <p className="help">{t('Or enter this key by hand:')} <code className="mono">{enr.secret.replace(/(.{4})/g, '$1 ').trim()}</code></p>
          <p>{t('2. Enter the 6-digit code it shows:')}</p>
          <input autoFocus className="mono otp" inputMode="numeric" maxLength={6} placeholder="000000" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} onKeyDown={(e) => e.key === 'Enter' && code.length === 6 && confirm()} />
          {err && <div className="alert alert-bad">{err}</div>}
        </>
      )}
    </Modal>
  )
}

function DisableTOTP({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [pw, setPw] = useState('')
  return (
    <Modal title={t('Disable two-step verification')} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-danger" disabled={!pw} onClick={() => api.del('/auth/me/totp', { password: pw }).then(() => (onDone(), onClose()), toast.err)}>{t('Disable')}</button></>}>
      <Field label={t('Confirm with your password')}><input autoFocus type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
    </Modal>
  )
}
