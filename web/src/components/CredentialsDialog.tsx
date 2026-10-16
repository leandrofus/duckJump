import { t } from '../i18n'
import { useState } from 'react'
import { KeyRound, Lock } from 'lucide-react'
import { Modal } from '../ui/overlays'
import { Field } from './FormBits'

export interface PromptedCredentials {
  username: string
  password: string
  domain: string
}

/** Asks for the target's credentials before connecting, like mstsc does.
 *  They go to the gateway once, for this session, and are never stored. */
export function CredentialsDialog({ title, protocol, reason, initial, onSubmit, onCancel }: {
  title: string
  protocol: string
  reason?: string
  initial?: PromptedCredentials
  onSubmit: (c: PromptedCredentials) => void
  onCancel: () => void
}) {
  const [v, setV] = useState<PromptedCredentials>(initial ?? { username: '', password: '', domain: '' })
  const needsUser = protocol !== 'vnc'
  const ok = (!needsUser || v.username.trim()) && v.password
  const submit = (e?: React.FormEvent) => {
    e?.preventDefault()
    if (ok) onSubmit({ ...v, username: v.username.trim(), domain: v.domain.trim() })
  }
  return (
    <Modal title={t('Sign in to {0}', title)} icon={<KeyRound size={18} />} onClose={onCancel}
      footer={<><button className="btn" onClick={onCancel}>{t('Cancel')}</button><button className="btn btn-primary" disabled={!ok} onClick={() => submit()}>{t('Connect')}</button></>}>
      <form onSubmit={submit} className="creds-form">
        {reason && <div className="alert alert-warn">{reason}</div>}
        {needsUser && (
          <Field label={t('User')}>
            <input autoFocus autoComplete="off" value={v.username} placeholder={protocol === 'rdp' ? 'administrator' : 'root'} onChange={(e) => setV({ ...v, username: e.target.value })} />
          </Field>
        )}
        <Field label={t('Password')}>
          <input autoFocus={!needsUser} type="password" autoComplete="off" value={v.password} onChange={(e) => setV({ ...v, password: e.target.value })} />
        </Field>
        {protocol === 'rdp' && (
          <Field label={t('Windows domain')} help={t('Optional; for domain accounts.')}>
            <input autoComplete="off" value={v.domain} placeholder="CORP" onChange={(e) => setV({ ...v, domain: e.target.value })} />
          </Field>
        )}
        <p className="help row gap"><Lock size={12} /> {t('Used only for this session and never stored. The audit log records the account name.')}</p>
        <button type="submit" hidden />
      </form>
    </Modal>
  )
}
