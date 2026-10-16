import { t } from '../i18n'
import { useEffect, useState } from 'react'
import { Folder, File, ArrowUp, RefreshCw, Download, Upload, FolderInput, X } from 'lucide-react'
import { api, enc, uploadToTray } from '../lib/api'
import type { HostListing, PortalConnection, TrayFile } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { bytes } from '../lib/format'
import { Spinner } from '../ui/common'
import { openDialog, toast } from '../ui/overlays'
import { SendDialog } from '../pages/Files'

type Creds = { username: string; password: string }

/** The host's files beside a session: take them into the tray, or send
 *  tray files (or files from this computer) here. */
export function FilesPanel({ conn, credentials, onClose }: { conn: PortalConnection; credentials?: Creds; onClose: () => void }) {
  const [path, setPath] = useState('')
  const [listing, setListing] = useState<HostListing | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [creds, setCreds] = useState<Creds | undefined>(credentials)
  const [ask, setAsk] = useState(false)
  const { data: tray } = useResource<TrayFile[]>('/files')
  const { data: conns } = useResource<PortalConnection[]>('/portal/connections')
  const withCreds = (body: object) => ({ ...body, ...(creds ? { credentials: creds } : {}) })

  const load = async (p: string) => {
    setBusy(true)
    setErr('')
    try {
      const l = await api.post<HostListing>(`/connections/${enc(conn.id)}/files/list`, withCreds({ path: p }))
      setListing(l)
      setPath(l.path)
    } catch (e: any) {
      if (e.code === 'credentials_required') setAsk(true)
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }
  useEffect(() => void load(''), [conn.id, creds])

  const join = (name: string) => (path.endsWith('/') ? path : path + '/') + name
  const up = () => load(path.replace(/\/[^/]+\/?$/, '') || '/')
  const pull = async (name: string) => {
    try {
      const f = await api.post<TrayFile>(`/connections/${enc(conn.id)}/files/pull`, withCreds({ path: join(name) }))
      invalidate('/files')
      toast.ok(t('{0} is in your tray', f.name))
    } catch (e) {
      toast.err(e)
    }
  }
  const sendHere = (f: TrayFile) =>
    openDialog((close) => <SendDialog file={f} conns={conns ?? [conn]} connectionId={conn.id} dir={path} credentials={creds}
      onClose={() => (close(), load(path))} />)
  const fromComputer = async (files: FileList | null) => {
    if (!files?.length) return
    for (const file of Array.from(files)) {
      try {
        const f = await uploadToTray(file)
        invalidate('/files')
        sendHere(f)
      } catch (e) {
        toast.err(e)
      }
    }
  }

  return (
    <aside className="files-panel">
      <header className="row gap">
        <FolderInput size={16} /> <strong>{t('Files on {0}', conn.name)}</strong>
        <span className="grow" />
        <button className="icon-btn" title={t('Reload')} onClick={() => load(path)}><RefreshCw size={14} /></button>
        <button className="icon-btn" title={t('Close')} onClick={onClose}><X size={14} /></button>
      </header>
      {ask && (
        <form className="files-creds" onSubmit={(e) => {
          e.preventDefault()
          const d = new FormData(e.currentTarget)
          setAsk(false)
          setCreds({ username: String(d.get('u')), password: String(d.get('p')) })
        }}>
          <span className="small muted">{t('Credentials for {0}', conn.name)}</span>
          <input name="u" placeholder={t('user')} autoComplete="off" />
          <input name="p" type="password" placeholder={t('password')} autoComplete="off" />
          <button className="btn btn-sm btn-primary">{t('Connect')}</button>
        </form>
      )}
      <div className="row gap files-path">
        <button className="icon-btn" title={t('Up')} disabled={!path || path === '/'} onClick={up}><ArrowUp size={14} /></button>
        <input className="mono grow" value={path} onChange={(e) => setPath(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && load(path)} />
        {busy && <Spinner />}
      </div>
      {err && !ask && <div className="alert alert-bad small">{err}</div>}
      <div className="files-list">
        {listing?.entries.map((e) => (
          <div key={e.name} className="files-row">
            {e.dir ? <Folder size={14} /> : <File size={14} />}
            {e.dir
              ? <button className="link grow" onClick={() => load(join(e.name))}>{e.name}</button>
              : <span className="grow">{e.name}</span>}
            {!e.dir && <span className="muted small">{bytes(e.size)}</span>}
            {!e.dir && conn.can_download && <button className="icon-btn" title={t('Take into my tray')} onClick={() => pull(e.name)}><Download size={14} /></button>}
          </div>
        ))}
      </div>
      {conn.can_upload && (
        <footer>
          <div className="small muted">{t('Send here')}</div>
          <label className="btn btn-sm"><Upload size={14} /> {t('From this computer')}
            <input type="file" multiple hidden onChange={(e) => fromComputer(e.target.files)} />
          </label>
          {tray?.map((f) => (
            <button key={f.id} className="files-row link" onClick={() => sendHere(f)} title={t('Send {0} here', f.name)}>
              <File size={13} /> <span className="grow">{f.name}</span> <span className="muted small">{bytes(f.size)}</span>
            </button>
          ))}
        </footer>
      )}
    </aside>
  )
}
