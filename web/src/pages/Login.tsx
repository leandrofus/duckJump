import { t, LANGUAGES, getLang, setLang } from '../i18n'
import { useState } from 'react'
import { ShieldCheck } from 'lucide-react'
import { api } from '../lib/api'
import { Spinner } from '../ui/common'

/** Password step, then the TOTP step when the user has it enabled. A
 *  half-open session (mfa=true) resumes directly at the TOTP step. */
export function Login({ mfa, onDone }: { mfa: boolean; onDone: () => void }) {
  const [step, setStep] = useState<'password' | 'totp'>(mfa ? 'totp' : 'password')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      if (step === 'password') {
        const r = await api.post<{ mfa_required: boolean }>('/auth/login', { username, password })
        if (r.mfa_required) {
          setStep('totp')
          setPassword('')
          return
        }
      } else {
        await api.post('/auth/totp', { code })
      }
      onDone()
    } catch (e: any) {
      setErr(e.message)
      if (step === 'password') setPassword('')
      else setCode('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login">
      <form className="login-card" onSubmit={submit}>
        <img className="login-logo" src="/duckjump-logo.svg" alt="DuckJump" />
        {step === 'password' ? (
          <>
            <p className="muted">{t('Sign in to the access bastion.')}</p>
            <input autoFocus autoComplete="username" placeholder={t('user')} value={username} onChange={(e) => setUsername(e.target.value)} />
            <input type="password" autoComplete="current-password" placeholder={t('password')} value={password} onChange={(e) => setPassword(e.target.value)} />
          </>
        ) : (
          <>
            <p className="muted row gap"><ShieldCheck size={16} /> {t('Enter the 6-digit code from your authenticator app.')}</p>
            <input
              autoFocus
              className="mono otp"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="000000"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            />
          </>
        )}
        {err && <div className="alert alert-bad">{err}</div>}
        <button className="btn btn-primary" disabled={busy || (step === 'password' ? !username || !password : code.length !== 6)}>
          {busy ? <Spinner /> : step === 'password' ? t('Sign in') : t('Verify')}
        </button>
        {step === 'totp' && (
          <button type="button" className="link small center-link" onClick={() => api.post('/auth/logout').finally(() => location.reload())}>
            {t('Use another account')}
          </button>
        )}
        <select className="lang-select" value={getLang()} onChange={(e) => setLang(e.target.value)} aria-label="Language">
          {LANGUAGES.map((l) => <option key={l.id} value={l.id}>{l.label}</option>)}
        </select>
      </form>
    </div>
  )
}
