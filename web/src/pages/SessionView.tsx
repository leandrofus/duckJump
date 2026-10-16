import { t } from '../i18n'
import { useEffect, useState } from 'react'
import { ChevronRight } from 'lucide-react'
import type { PortalConnection } from '../lib/api'
import { useResource } from '../lib/store'
import { usePref } from '../lib/prefs'
import { href } from '../lib/router'
import { getMe } from '../lib/session'
import { Spinner } from '../ui/common'
import { TerminalSession } from '../components/Terminal'
import { RemoteSession } from '../components/RemoteSession'
import { CredentialsDialog } from '../components/CredentialsDialog'
import type { PromptedCredentials } from '../components/CredentialsDialog'
import { go } from '../lib/router'
import type { Recent } from '../App'

export function SessionView({ id }: { id: string }) {
  const { data } = useResource<PortalConnection[]>('/portal/connections')
  const [, setRecent] = usePref<Recent[]>('recent', [])
  const c = data?.find((x) => x.id === id)
  // Prompted credentials (connections without a vaulted one): asked before
  // connecting for "prompt", or when the server answers it needs them.
  const [creds, setCreds] = useState<PromptedCredentials | undefined>()
  const [ask, setAsk] = useState<{ reason?: string } | null>(null)
  useEffect(() => {
    if (c?.credentials === 'prompt' && !creds) setAsk({})
  }, [c?.id])
  // The server's reason, in the user's language when we know the code.
  const needCredentials = (code: string, reason: string) =>
    setAsk({
      reason: code === 'credentials_required'
        ? t('The server needs your credentials before the session starts (it requires NLA).')
        : code === 'auth_failed' ? t('Wrong username or password, or the account may not sign in remotely.') : reason,
    })
  useEffect(() => {
    if (!c) return
    document.title = `${c.name} · DuckJump`
    setRecent((list) => [{ id: c.id, name: c.name, protocol: c.protocol }, ...list.filter((r) => r.id !== c.id)].slice(0, 20))
    return () => {
      document.title = 'DuckJump'
    }
  }, [c?.id])
  if (!data) return <div className="center page"><Spinner /></div>
  if (!c && !getMe()?.dev) {
    return (
      <div className="page">
        <div className="alert alert-bad">{t('This connection does not exist or you have no access to it.')}</div>
        <a href={href('portal')}>{t('Back to my connections')}</a>
      </div>
    )
  }
  return (
    <div className="session-page">
      <div className="breadcrumbs">
        <a href={href('portal')}>{t('My connections')}</a>
        <ChevronRight size={13} />
        {c?.folder_path && (<><span className="muted">{c.folder_path}</span><ChevronRight size={13} /></>)}
        <span>{c?.name ?? id}</span>
      </div>
      {ask && c && (
        <CredentialsDialog title={c.name} protocol={c.protocol} reason={ask.reason} initial={creds && { ...creds, password: '' }}
          onCancel={() => (setAsk(null), !creds && c.credentials === 'prompt' && go('portal'))}
          onSubmit={(v) => (setAsk(null), setCreds(v))} />
      )}
      {c?.credentials === 'prompt' && !creds ? (
        <div className="terminal session-terminal waiting">{!ask && <button className="btn btn-primary" onClick={() => setAsk({})}>{t('Enter credentials')}</button>}</div>
      ) : c?.protocol === 'vnc' || c?.protocol === 'rdp' ? (
        <RemoteSession connectionId={id} title={c.name} recorded={c.record} protocol={c.protocol} credentials={creds} onNeedCredentials={needCredentials} />
      ) : (
        <TerminalSession connectionId={id} title={c?.name ?? id} recorded={c?.record ?? true} credentials={creds} onNeedCredentials={needCredentials} />
      )}
    </div>
  )
}
