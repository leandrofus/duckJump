import { t } from '../i18n'
import { useEffect, useState } from 'react'
import { ChevronRight, FolderInput, Users, Globe, ArrowLeftRight, RotateCw, ExternalLink, Copy } from 'lucide-react'
import { FilesPanel } from '../components/FilesPanel'
import type { PortalConnection } from '../lib/api'
import { useResource } from '../lib/store'
import { usePref } from '../lib/prefs'
import { href, useRoute } from '../lib/router'
import { copy } from '../lib/format'
import { getMe, isAdmin } from '../lib/session'
import { api, enc } from '../lib/api'
import { confirm, toast } from '../ui/overlays'
import { Spinner } from '../ui/common'
import { TerminalSession } from '../components/Terminal'
import { RemoteSession } from '../components/RemoteSession'
import { CredentialsDialog } from '../components/CredentialsDialog'
import type { PromptedCredentials } from '../components/CredentialsDialog'
import { go } from '../lib/router'
import type { Recent } from '../App'

export function SessionView({ id }: { id: string }) {
  const route = useRoute()
  const joinSessionId = route.query.get('join') || undefined
  const shareToken = route.query.get('token') || undefined

  const { data } = useResource<PortalConnection[]>('/portal/connections')
  const [, setRecent] = usePref<Recent[]>('recent', [])
  const [sessionInfo, setSessionInfo] = useState<{ connection_id: string; connection_name: string; protocol: string } | null>(null)

  useEffect(() => {
    if (joinSessionId) {
      api.get<{ connection_id: string; connection_name: string; protocol: string }>(
        `/sessions/${enc(joinSessionId)}/info${shareToken ? `?token=${enc(shareToken)}` : ''}`
      ).then(setSessionInfo).catch(() => {})
    }
  }, [joinSessionId, shareToken])

  let c = data?.find((x) => x.id === id)
  if (!c && sessionInfo) {
    c = {
      id: sessionInfo.connection_id,
      name: sessionInfo.connection_name,
      protocol: sessionInfo.protocol,
      credentials: 'vault',
      record: false,
      folder_path: '',
    } as PortalConnection
  }

  // Prompted credentials (connections without a vaulted one): asked before
  // connecting for "prompt", or when the server answers it needs them.
  const [creds, setCreds] = useState<PromptedCredentials | undefined>()
  const [ask, setAsk] = useState<{ reason?: string } | null>(null)
  useEffect(() => {
    if (c?.credentials === 'prompt' && !creds && !joinSessionId) setAsk({})
  }, [c?.id, joinSessionId])
  // The server's reason, in the user's language when we know the code.
  const needCredentials = (code: string, reason: string) =>
    setAsk({
      reason: code === 'credentials_required'
        ? t('The server needs your credentials before the session starts (it requires NLA).')
        : code === 'auth_failed' ? t('Wrong username or password, or the account may not sign in remotely.') : reason,
    })
  // A server key nobody approved: admins can check it and approve it here.
  const [attempt, setAttempt] = useState(0)
  const [files, setFiles] = useState(false)
  const unverifiedKey = async (fp: string) => {
    if (!isAdmin()) return
    const ok = await confirm({
      title: t('Approve the key of {0}?', c?.name ?? id),
      body: (<>
        <p>{t('The server presented this key. Compare it with the key on the server itself before approving it: a different key means someone may be intercepting the connection.')}</p>
        <p className="mono small">{fp}</p>
        <p className="help">{t('SSH: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub on the server. RDP and VNC: the fingerprint of its TLS certificate.')}</p>
      </>),
      confirm: t('Approve and connect'),
    })
    if (!ok) return
    try {
      await api.put(`/connections/${enc(id)}/host-key`, { fingerprint: fp })
      toast.ok(t('Key approved'))
      setAttempt((n) => n + 1)
    } catch (e) {
      toast.err(e)
    }
  }
  useEffect(() => {
    if (!c) return
    document.title = `${c.name} · DuckJump`
    setRecent((list) => [{ id: c.id, name: c.name, protocol: c.protocol }, ...list.filter((r) => r.id !== c.id)].slice(0, 20))
    return () => {
      document.title = 'DuckJump'
    }
  }, [c?.id])
  if (!data && !sessionInfo) return <div className="center page"><Spinner /></div>
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
        {joinSessionId && (
          <span className="pill pill-muted" style={{ display: 'inline-flex', alignItems: 'center', gap: 4, marginLeft: 8 }}>
            <Users size={12} /> {t('Shared session')}
          </span>
        )}
        {c && (c.can_upload || c.can_download) && !joinSessionId && (
          <>
            <span className="grow" />
            <button className={`btn btn-sm${files ? ' on' : ''}`} onClick={() => setFiles(!files)}><FolderInput size={14} /> {t('Files')}</button>
          </>
        )}
      </div>
      {ask && c && (
        <CredentialsDialog title={c.name} protocol={c.protocol} reason={ask.reason} initial={creds && { ...creds, password: '' }}
          onCancel={() => (setAsk(null), !creds && c.credentials === 'prompt' && go('portal'))}
          onSubmit={(v) => (setAsk(null), setCreds(v))} />
      )}
      {c?.credentials === 'prompt' && !creds && !joinSessionId ? (
        <div className="terminal session-terminal waiting">{!ask && <button className="btn btn-primary" onClick={() => setAsk({})}>{t('Enter credentials')}</button>}</div>
      ) : c?.protocol === 'http' || c?.protocol === 'https' ? (
        <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 48px)', width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 16px', background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)' }}>
            <span className="pill pill-muted" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <Globe size={13} /> {c.protocol.toUpperCase()}
            </span>
            {c.virtual_host && (
              <span className="pill pill-muted" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                Host: <code>{c.virtual_host}</code>
              </span>
            )}
            <span className="muted small ellipsis" style={{ flex: 1 }}>
              {location.origin}/api/v1/connections/{c.id}/http/
            </span>
            <button className="btn btn-sm" onClick={() => {
              const ifr = document.getElementById('web-session-frame') as HTMLIFrameElement
              if (ifr) ifr.src = ifr.src
            }}>
              <RotateCw size={13} /> {t('Reload')}
            </button>
            <button className="btn btn-sm btn-primary" onClick={() => window.open(`/api/v1/connections/${c.id}/http/`, '_blank')}>
              <ExternalLink size={13} /> {t('Open in new window')}
            </button>
          </div>
          <iframe
            id="web-session-frame"
            src={`/api/v1/connections/${c.id}/http/`}
            style={{ width: '100%', height: '100%', border: 'none', flex: 1, background: '#fff' }}
            title={c.name}
          />
        </div>
      ) : c?.protocol === 'tcp' ? (
        <div style={{ padding: '2rem', maxWidth: 640, margin: '3rem auto', background: 'var(--bg-panel)', borderRadius: 8, border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 16 }}>
            <div className="conn-icon proto-tcp" style={{ width: 44, height: 44, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ArrowLeftRight size={24} />
            </div>
            <div>
              <h2 style={{ margin: 0, fontSize: '1.25rem' }}>{c.name}</h2>
              <span className="muted small">Túnel TCP / Port Forwarding</span>
            </div>
          </div>
          <p className="muted" style={{ marginBottom: 16, lineHeight: 1.5 }}>
            {t('Esta conexión es un servicio TCP nativo (base de datos, broker o API interna). Inicia el reenvío de puertos local ejecutando en tu terminal:')}
          </p>
          <div style={{ background: 'var(--bg-subtle, #1a1a1a)', padding: '12px 16px', borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontFamily: 'monospace', marginBottom: 16 }}>
            <code>duckjump forward {c.name} 5432</code>
            <button className="btn btn-sm" onClick={() => {
              copy(`duckjump forward ${c.name} 5432`)
              toast.ok(t('Comando copiado al portapapeles'))
            }}>
              <Copy size={13} /> {t('Copiar')}
            </button>
          </div>
          <p className="help">
            💡 {t('O inicia este túnel gráficamente desde la aplicación de escritorio DuckJump en la pestaña «Túneles TCP / HTTP».')}
          </p>
        </div>
      ) : c?.protocol === 'vnc' || c?.protocol === 'rdp' ? (
        <RemoteSession
          key={attempt}
          connectionId={id}
          joinSessionId={joinSessionId}
          shareToken={shareToken}
          title={c.name}
          recorded={c.record}
          protocol={c.protocol}
          credentials={creds}
          onNeedCredentials={needCredentials}
          onUnverifiedKey={unverifiedKey}
        />
      ) : (
        <div className="session-with-files">
          <TerminalSession
            key={attempt}
            connectionId={id}
            joinSessionId={joinSessionId}
            shareToken={shareToken}
            title={c?.name ?? id}
            recorded={c?.record ?? true}
            credentials={creds}
            onNeedCredentials={needCredentials}
            onUnverifiedKey={unverifiedKey}
          />
          {files && c && !joinSessionId && <FilesPanel conn={c} credentials={creds && { username: creds.username, password: creds.password }} onClose={() => setFiles(false)} />}
        </div>
      )}
    </div>
  )
}
