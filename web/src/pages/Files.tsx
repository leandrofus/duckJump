import { t } from '../i18n'
import { useRef, useState } from 'react'
import { FolderInput, Upload, Download, Trash2, Send, Laptop, Server, ShieldCheck } from 'lucide-react'
import { api, enc, uploadToTray } from '../lib/api'
import type { PortalConnection, TrayFile } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { ago, bytes, dateTime } from '../lib/format'
import { isAuditor } from '../lib/session'
import { DataTable, Empty, Spinner, Tabs, Tag } from '../ui/common'
import { Modal, confirm, openDialog, toast } from '../ui/overlays'
import { Field } from '../components/FormBits'

/** My file tray: files on their way between my computer and hosts, or
 *  between two hosts. Everything that passes is kept with its hash and
 *  audited. */
export function Files() {
  const [tab, setTab] = useState('tray')
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title"><FolderInput size={20} /><h1>{t('My files')}</h1></div>
        {isAuditor() && (
          <Tabs active={tab} onChange={setTab} tabs={[{ id: 'tray', label: t('My tray') }, { id: 'all', label: t('All transfers') }]} />
        )}
      </div>
      <div className="page-body">{tab === 'all' ? <AllTransfers /> : <Tray />}</div>
    </div>
  )
}

export function UploadButton({ onUploaded, label }: { onUploaded?: (f: TrayFile) => void; label?: string }) {
  const input = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState(false)
  const pick = async (files: FileList | null) => {
    if (!files?.length) return
    setBusy(true)
    try {
      for (const f of Array.from(files)) {
        const up = await uploadToTray(f)
        onUploaded?.(up)
      }
      invalidate('/files')
      toast.ok(t('Uploaded to your tray'))
    } catch (e) {
      toast.err(e)
    } finally {
      setBusy(false)
      if (input.current) input.current.value = ''
    }
  }
  return (
    <>
      <input ref={input} type="file" multiple hidden onChange={(e) => pick(e.target.files)} />
      <button className="btn btn-sm" disabled={busy} onClick={() => input.current?.click()}>
        {busy ? <Spinner /> : <Upload size={14} />} {label ?? t('Upload from this computer')}
      </button>
    </>
  )
}

function Origin({ f, conns }: { f: TrayFile; conns?: PortalConnection[] }) {
  if (f.origin === 'upload') return <span className="row gap small"><Laptop size={13} /> {t('my computer')}</span>
  const c = conns?.find((x) => x.id === f.connection_id)
  return <span className="row gap small" title={f.remote_path}><Server size={13} /> {c?.name ?? t('a host')} <span className="muted mono">{f.remote_path}</span></span>
}

function Tray() {
  const { data, error } = useResource<TrayFile[]>('/files')
  const { data: conns } = useResource<PortalConnection[]>('/portal/connections')
  if (error) return <div className="alert alert-bad">{error.message}</div>
  if (!data) return <Spinner />
  return (
    <>
      <div className="row gap wrap" style={{ marginBottom: 12 }}>
        <UploadButton />
        <span className="muted small">{t('Files stay here for a few days and every move is audited. Send them to a host from here or from a session.')}</span>
      </div>
      <DataTable
        rows={data}
        rowKey={(f) => f.id}
        empty={<Empty icon={<FolderInput size={28} />} title={t('Your tray is empty')}>{t('Upload a file, or take one out of a host from an SSH session.')}</Empty>}
        columns={[
          { key: 'name', label: t('Name'), sort: (f) => f.name, render: (f) => <strong>{f.name}</strong> },
          { key: 'size', label: t('Size'), sort: (f) => f.size, render: (f) => bytes(f.size) },
          { key: 'from', label: t('From'), render: (f) => <Origin f={f} conns={conns} /> },
          { key: 'when', label: t('Added'), sort: (f) => f.created_at, render: (f) => <span className="small" title={dateTime(f.created_at)}>{ago(f.created_at)}</span> },
          { key: 'exp', label: t('Kept until'), render: (f) => <span className="small muted">{dateTime(f.expires_at)}</span> },
          { key: 'hash', label: 'SHA-256', render: (f) => <span className="mono small muted" title={f.sha256}>{f.sha256.slice(0, 12)}…</span> },
          {
            key: 'act', label: '', render: (f) => (
              <span className="row gap">
                <a className="icon-btn" title={t('Download')} href={`/api/v1/files/${enc(f.id)}/content`}><Download size={14} /></a>
                <button className="icon-btn" title={t('Send to a host…')} onClick={() => openDialog((close) => <SendDialog file={f} conns={conns ?? []} onClose={close} />)}><Send size={14} /></button>
                <button className="icon-btn" title={t('Delete')} onClick={() => remove(f)}><Trash2 size={14} /></button>
              </span>
            ),
          },
        ]}
      />
    </>
  )
}

async function remove(f: TrayFile) {
  if (!(await confirm({ title: t('Delete {0}?', f.name), body: t('Its content is deleted; the record of its transfers stays in the audit log.'), danger: true, confirm: t('Delete') }))) return
  api.del(`/files/${enc(f.id)}`).then(() => invalidate('/files'), toast.err)
}

/** Sends a tray file into a host the user may upload to. */
export function SendDialog({ file, conns, onClose, connectionId, dir, credentials }: {
  file: TrayFile
  conns: PortalConnection[]
  onClose: () => void
  connectionId?: string
  dir?: string
  credentials?: { username: string; password: string }
}) {
  const targets = conns.filter((c) => c.can_upload)
  const [conn, setConn] = useState(connectionId ?? targets[0]?.id ?? '')
  const [path, setPath] = useState(dir ? dir.replace(/\/?$/, '/') : './')
  const [overwrite, setOverwrite] = useState(false)
  const [busy, setBusy] = useState(false)
  const send = async () => {
    setBusy(true)
    try {
      await api.post(`/connections/${enc(conn)}/files/push`, { file_id: file.id, path, overwrite, ...(credentials ? { credentials } : {}) })
      toast.ok(t('{0} sent', file.name))
      onClose()
    } catch (e) {
      toast.err(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal title={t('Send {0}', file.name)} icon={<Send size={18} />} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" disabled={busy || !conn || !path.trim()} onClick={send}>{busy ? <Spinner /> : t('Send')}</button></>}>
      {targets.length === 0 ? <div className="alert alert-warn">{t('You may not send files to any host.')}</div> : (
        <>
          <Field label={t('Host')}>
            <select value={conn} disabled={!!connectionId} onChange={(e) => setConn(e.target.value)}>
              {targets.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </Field>
          <Field label={t('Path')} help={t('Ending in / puts it in that directory with its own name; ./ is your home directory.')}>
            <input className="mono" value={path} onChange={(e) => setPath(e.target.value)} />
          </Field>
          <label className="check"><input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} /> {t('Replace the file if it exists')}</label>
        </>
      )}
    </Modal>
  )
}

function AllTransfers() {
  const { data, error } = useResource<TrayFile[]>('/audit/files?limit=500')
  if (error) return <div className="alert alert-bad">{error.message}</div>
  if (!data) return <Spinner />
  return (
    <>
      <p className="help row gap"><ShieldCheck size={14} /> {t('Every file that went through the gateway. Content is kept until it expires; the record and its hash stay. Each download is audited.')}</p>
      <DataTable
        rows={data}
        rowKey={(f) => f.id}
        columns={[
          { key: 'when', label: t('When'), render: (f) => <span className="small" title={dateTime(f.created_at)}>{ago(f.created_at)}</span> },
          { key: 'who', label: t('User'), render: (f) => <strong>{f.owner_name}</strong> },
          { key: 'name', label: t('Name'), render: (f) => f.name },
          { key: 'size', label: t('Size'), render: (f) => bytes(f.size) },
          { key: 'from', label: t('From'), render: (f) => (f.origin === 'upload' ? t('their computer') : <span className="mono small">{f.remote_path}</span>) },
          { key: 'hash', label: 'SHA-256', render: (f) => <span className="mono small muted" title={f.sha256}>{f.sha256.slice(0, 16)}…</span> },
          {
            key: 'state', label: '', render: (f) => (f.deleted_at ? <Tag>{t('content deleted')}</Tag> : (
              <a className="icon-btn" title={t('Download (audited)')} href={`/api/v1/audit/files/${enc(f.id)}/content`}><Download size={14} /></a>
            )),
          },
        ]}
      />
    </>
  )
}
