import { t } from '../i18n'
import { useMemo, useState } from 'react'
import { Server, Search, X, Plus, Folder as FolderIcon, FolderOpen, FolderPlus, Pencil, Trash2, ShieldCheck, KeyRound, Fingerprint, TerminalSquare, ChevronRight, Copy, History } from 'lucide-react'
import { api, enc } from '../lib/api'
import type { Connection, Policy, Session } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { go, href } from '../lib/router'
import { ago, copy, dateTime } from '../lib/format'
import { isAuditor } from '../lib/session'
import { folderTree, subtree, useConnections, useFolders, useSecrets, useSites } from '../lib/lookup'
import { useMenu } from '../ui/ContextMenu'
import type { MenuEntry } from '../ui/ContextMenu'
import { DataTable, Empty, MenuButton, Props, Section, Spinner, Tag } from '../ui/common'
import { Drawer, Modal, confirm, openDialog, prompt, toast } from '../ui/overlays'
import { Field, FolderSelect, TagsInput } from '../components/FormBits'
import { ProtoTag } from './Portal'
import { PolicyDialog, PolicyList } from './Policies'
import { SecretFormDialog } from './Secrets'

const ALL = '__all'
const NONE = '__none'

export function Connections({ id }: { id?: string }) {
  const conns = useConnections()
  const folders = useFolders()
  const sites = useSites()
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(ALL)
  const menu = useMenu()

  const inFolder = useMemo(() => {
    if (sel === ALL) return conns.rows
    if (sel === NONE) return conns.rows.filter((c) => !c.folder_id)
    const ids = subtree(folders.rows, sel)
    return conns.rows.filter((c) => c.folder_id && ids.has(c.folder_id))
  }, [conns.rows, folders.rows, sel])
  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return inFolder.filter((c) => words.every((w) => `${c.name} ${c.host} ${c.protocol} ${c.environment} ${c.tags.join(' ')} ${folders.path(c.folder_id)}`.toLowerCase().includes(w)))
  }, [inFolder, q, folders.rows])

  const selectedFolder = sel !== ALL && sel !== NONE ? sel : ''
  const newConn = () => openDialog((c) => <ConnectionFormDialog folderId={selectedFolder} onClose={c} />)
  const newFolder = async (parent: string) => {
    const name = await prompt({ title: t('New folder'), label: t('Name'), confirm: t('Create') })
    if (!name) return
    try {
      await api.post('/folders', { name, parent_id: parent || null })
      invalidate('/folders')
    } catch (e) {
      toast.err(e)
    }
  }
  const folderMenu = (fid: string): MenuEntry[] => {
    const f = folders.map.get(fid)!
    return [
      { header: f.name },
      { label: t('New connection here'), icon: <Plus size={14} />, onClick: () => openDialog((c) => <ConnectionFormDialog folderId={fid} onClose={c} />) },
      { label: t('New subfolder'), icon: <FolderPlus size={14} />, onClick: () => newFolder(fid) },
      { label: t('Grant access to this folder…'), icon: <ShieldCheck size={14} />, onClick: () => openDialog((c) => <PolicyDialog object={{ type: 'folder', ref: fid }} onClose={c} />) },
      'sep',
      {
        label: t('Rename…'), icon: <Pencil size={14} />, onClick: async () => {
          const name = await prompt({ title: t('Rename folder'), label: t('Name'), value: f.name })
          if (name) api.patch(`/folders/${fid}`, { name }).then(() => invalidate('/folders'), toast.err)
        },
      },
      { label: t('Move…'), icon: <FolderOpen size={14} />, onClick: () => openDialog((c) => <MoveFolderDialog folderId={fid} onClose={c} />) },
      {
        label: t('Delete'), icon: <Trash2 size={14} />, danger: true, onClick: async () => {
          if (!(await confirm({ title: t('Delete folder {0}?', f.name), body: t('Only empty folders can be deleted. Access grants on the folder are removed.'), danger: true, confirm: t('Delete') }))) return
          api.del(`/folders/${fid}`).then(() => (setSel(ALL), invalidate('/folders')), toast.err)
        },
      },
    ]
  }

  const count = (fid: string) => {
    const ids = subtree(folders.rows, fid)
    return conns.rows.filter((c) => c.folder_id && ids.has(c.folder_id)).length
  }

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <Server size={20} />
          <h1>{t('Connections')}</h1>
          <span className="count">{conns.rows.length}</span>
          {conns.loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Search by name, host, tag…')} value={q} onChange={(e) => setQ(e.target.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>
          <button className="btn btn-sm" onClick={() => newFolder(selectedFolder)}><FolderPlus size={14} /> {t('Folder')}</button>
          <button className="btn btn-primary btn-sm" onClick={newConn}><Plus size={14} /> {t('Connection')}</button>
        </div>
      </div>
      <div className="page-body split">
        <aside className="tree-panel">
          <button className={`tree-item${sel === ALL ? ' active' : ''}`} onClick={() => setSel(ALL)}>
            <Server size={14} /> <span className="grow">{t('All')}</span> <span className="muted small">{conns.rows.length}</span>
          </button>
          {folderTree(folders.rows).map(({ folder, depth }) => (
            <button key={folder.id} className={`tree-item${sel === folder.id ? ' active' : ''}`} style={{ paddingLeft: 10 + depth * 16 }}
              onClick={() => setSel(folder.id)} onContextMenu={menu(() => folderMenu(folder.id))}>
              {sel === folder.id ? <FolderOpen size={14} /> : <FolderIcon size={14} />}
              <span className="grow ellipsis">{folder.name}</span>
              <span className="muted small">{count(folder.id)}</span>
            </button>
          ))}
          <button className={`tree-item${sel === NONE ? ' active' : ''}`} onClick={() => setSel(NONE)}>
            <FolderIcon size={14} className="muted" /> <span className="grow muted">{t('No folder')}</span>
            <span className="muted small">{conns.rows.filter((c) => !c.folder_id).length}</span>
          </button>
          <p className="help">{t('Right-click a folder for more actions. Access granted on a folder covers everything inside it.')}</p>
        </aside>
        <div className="grow">
          {conns.error && <div className="alert alert-bad">{conns.error.message}</div>}
          <DataTable
            rows={rows}
            rowKey={(c) => c.id}
            onOpen={(c) => go('connections', c.id)}
            rowMenu={(c) => connectionActions(c)}
            defaultSort={{ key: 'name', dir: 1 }}
            empty={
              conns.data && (
                <Empty icon={<Server size={28} />} title={conns.rows.length ? t('Nothing here') : t('The catalog is empty')} action={<button className="btn btn-primary" onClick={newConn}><Plus size={14} /> {t('New connection')}</button>}>
                  {conns.rows.length ? t('No connection in this folder matches.') : t('Add the hosts users will connect to.')}
                </Empty>
              )
            }
            columns={[
              { key: 'name', label: t('Name'), sort: (c) => c.name, render: (c) => <strong>{c.name}</strong> },
              { key: 'proto', label: t('Protocol'), sort: (c) => c.protocol, render: (c) => <ProtoTag p={c.protocol} /> },
              { key: 'host', label: t('Host'), sort: (c) => c.host, render: (c) => <span className="mono small">{c.host}:{c.port}</span> },
              { key: 'folder', label: t('Folder'), sort: (c) => folders.path(c.folder_id), render: (c) => folders.path(c.folder_id) || <span className="muted">—</span> },
              { key: 'site', label: t('Site'), sort: (c) => sites.map.get(c.site_id || '')?.name ?? '', render: (c) => (c.site_id ? sites.map.get(c.site_id)?.name : <span className="muted">{t('direct')}</span>) },
              { key: 'env', label: t('Environment'), sort: (c) => c.environment, render: (c) => c.environment || <span className="muted">—</span> },
              { key: 'tags', label: t('Tags'), render: (c) => <span className="tags">{c.tags.map((x) => <Tag key={x}>{x}</Tag>)}</span> },
            ]}
          />
        </div>
      </div>
      {id && <ConnectionDrawer id={id} onClose={() => go('connections')} />}
    </div>
  )
}

export function connectionActions(c: Connection): MenuEntry[] {
  return [
    { header: c.name },
    { label: t('Open'), onClick: () => go('connections', c.id) },
    { label: t('Edit…'), icon: <Pencil size={14} />, onClick: () => openDialog((close) => <ConnectionFormDialog initial={c} onClose={close} />) },
    { label: t('Grant access…'), icon: <ShieldCheck size={14} />, onClick: () => openDialog((close) => <PolicyDialog object={{ type: 'connection', ref: c.id }} onClose={close} />) },
    { label: t('Connect'), icon: <TerminalSquare size={14} />, onClick: () => go('session', c.id) },
    'sep',
    { label: t('Copy host'), icon: <Copy size={14} />, onClick: () => copy(`${c.host}:${c.port}`) },
    c.host_key && { label: t('Forget host key…'), icon: <Fingerprint size={14} />, onClick: () => forgetHostKey(c) },
    {
      label: t('Delete'), icon: <Trash2 size={14} />, danger: true, onClick: async () => {
        if (!(await confirm({ title: t('Delete {0}?', c.name), body: t('Its access grants are removed too. Session history and recordings are kept.'), danger: true, confirm: t('Delete') }))) return
        api.del(`/connections/${c.id}`).then(() => (invalidate('/connections', '/portal'), go('connections')), toast.err)
      },
    },
  ]
}

async function forgetHostKey(c: Connection) {
  if (!(await confirm({ title: t('Forget the host key of {0}?', c.name), body: t('The next session trusts whatever key the host presents and pins it. Do it only if you know why the key changed.'), confirm: t('Forget') }))) return
  api.del(`/connections/${c.id}/host-key`).then(() => (invalidate('/connections'), toast.ok(t('Host key cleared'))), toast.err)
}

function ConnectionDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: c, error } = useResource<Connection>(`/connections/${enc(id)}`)
  const folders = useFolders()
  const sites = useSites()
  const secrets = useSecrets()
  const { data: policies } = useResource<Policy[]>(`/policies?object_ref=${enc(id)}`)
  const { data: sessions } = useResource<Session[]>(isAuditor() ? `/audit/sessions?connection_id=${enc(id)}&limit=10` : null)
  return (
    <Drawer onClose={onClose} width={620}>
      {error && <div className="alert alert-bad">{error.message}</div>}
      {!c ? <Spinner /> : (
        <div className="drawer-body">
          <div className="breadcrumbs">
            <a href={href('connections')}>{t('Connections')}</a>
            {c.folder_id && (<><ChevronRight size={13} /><span>{folders.path(c.folder_id)}</span></>)}
          </div>
          <header className="record-head">
            <div className="record-title">
              <h1>{c.name}</h1>
              <div className="row gap wrap">
                <ProtoTag p={c.protocol} />
                {c.environment && <Tag>{c.environment}</Tag>}
                {c.tags.map((x) => <Tag key={x}>{x}</Tag>)}
              </div>
            </div>
            <div className="record-actions">
              <button className="btn btn-sm" onClick={() => openDialog((close) => <ConnectionFormDialog initial={c} onClose={close} />)}><Pencil size={14} /> {t('Edit')}</button>
              <MenuButton items={() => connectionActions(c)} className="btn btn-sm" />
            </div>
          </header>
          {c.description && <p className="muted">{c.description}</p>}
          <Section title={t('Properties')}>
            <Props items={[
              [t('Host'), <span className="mono">{c.host}:{c.port}</span>, () => [{ label: t('Copy'), onClick: () => copy(`${c.host}:${c.port}`) }]],
              [t('Site'), c.site_id ? sites.map.get(c.site_id)?.name ?? c.site_id : t('direct (reachable from paltad)')],
              [t('Credential'), c.secret_id ? (<span className="row gap"><KeyRound size={13} /> {secrets.map.get(c.secret_id)?.name ?? '?'} <span className="muted small">({secrets.map.get(c.secret_id)?.username})</span></span>) : <span className="tone-warn">{t('none: sessions will fail')}</span>],
              [t('Credential mode'), c.credential_mode === 'vault' ? t('injected from the vault') : t('asked at connect time')],
              [t('Session recording'), c.record ? (c.record_input ? t('output and keystrokes') : t('output')) : t('off')],
              [t('Host key'), c.host_key ? <span className="mono small">{c.host_key}</span> : <span className="muted">{t('not pinned yet (trust on first use)')}</span>],
              [t('Backend'), c.backend],
              [t('Updated'), <span title={dateTime(c.updated_at)}>{ago(c.updated_at)}</span>],
            ]} />
          </Section>
          <Section title={t('Who has access')} actions={<button className="btn btn-sm" onClick={() => openDialog((close) => <PolicyDialog object={{ type: 'connection', ref: c.id }} onClose={close} />)}><Plus size={13} /> {t('Grant')}</button>}>
            <p className="help">{t('Grants made directly on this connection. Grants on its folders or tags also apply; see them in Access.')}</p>
            <PolicyList rows={policies || []} hideObject />
          </Section>
          {isAuditor() && (
            <Section title={t('Recent sessions')}>
              {sessions?.length ? (
                <div className="rel-list">
                  {sessions.map((s) => (
                    <a key={s.id} className="rel-item" href={href('sessions', s.id)}>
                      <History size={13} /> <strong>{s.username}</strong>
                      <span className="muted small">{ago(s.started_at)}</span>
                      <span className="grow" />
                      {s.ended_at ? <span className="muted small">{s.end_reason}</span> : <span className="tag tag-ok">{t('active')}</span>}
                    </a>
                  ))}
                </div>
              ) : <span className="muted">{t('No sessions yet.')}</span>}
            </Section>
          )}
        </div>
      )}
    </Drawer>
  )
}

const DEFAULT_PORT: Record<string, number> = { ssh: 22, rdp: 3389, vnc: 5900 }

export function ConnectionFormDialog({ initial, folderId, onClose }: { initial?: Connection; folderId?: string; onClose: () => void }) {
  const folders = useFolders()
  const sites = useSites()
  const secrets = useSecrets()
  const [v, setV] = useState({
    name: initial?.name ?? '',
    protocol: initial?.protocol ?? 'ssh',
    host: initial?.host ?? '',
    port: initial ? String(initial.port) : '',
    folder_id: initial?.folder_id ?? folderId ?? '',
    site_id: initial?.site_id ?? '',
    secret_id: initial?.secret_id ?? '',
    credential_mode: initial?.credential_mode ?? 'vault',
    environment: initial?.environment ?? '',
    description: initial?.description ?? '',
    tags: initial?.tags ?? [],
    record: initial?.record ?? true,
    record_input: initial?.record_input ?? false,
  })
  const initialParams = (initial?.params ?? {}) as { domain?: string; security?: string }
  const [rdp, setRdp] = useState({ domain: initialParams.domain ?? '', security: initialParams.security ?? 'any' })
  const [busy, setBusy] = useState(false)
  const set = (p: Partial<typeof v>) => setV({ ...v, ...p })
  const save = async () => {
    setBusy(true)
    const body = {
      name: v.name.trim(), protocol: v.protocol, host: v.host.trim(), port: v.port ? Number(v.port) : DEFAULT_PORT[v.protocol],
      folder_id: v.folder_id || null, site_id: v.site_id || null,
      credential_mode: v.credential_mode, secret_id: v.credential_mode === 'prompt' ? null : v.secret_id || null,
      environment: v.environment.trim(), description: v.description.trim(), tags: v.tags, record: v.record, record_input: v.record_input,
      params: v.protocol === 'rdp' ? { ...(initial?.params ?? {}), domain: rdp.domain.trim(), security: rdp.security } : (initial?.params ?? {}),
    }
    try {
      const saved = initial ? await api.patch<Connection>(`/connections/${initial.id}`, body) : await api.post<Connection>('/connections', body)
      invalidate('/connections', '/portal')
      toast.ok(initial ? t('Connection saved') : t('Connection {0} created', saved.name))
      onClose()
      if (!initial) go('connections', saved.id)
    } catch (e) {
      toast.err(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal wide title={initial ? t('Edit {0}', initial.name) : t('New connection')} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" disabled={busy || !v.name.trim() || !v.host.trim()} onClick={save}>{initial ? t('Save') : t('Create')}</button></>}>
      <div className="grid-2">
        <Field label={t('Name')}><input autoFocus value={v.name} placeholder="web-prod-1" onChange={(e) => set({ name: e.target.value })} /></Field>
        <Field label={t('Protocol')}>
          <select value={v.protocol} onChange={(e) => set({ protocol: e.target.value as Connection['protocol'] })}>
            <option value="ssh">SSH</option>
            <option value="rdp">RDP</option>
            <option value="vnc">VNC</option>
          </select>
        </Field>
        <Field label={t('Host')}><input className="mono" value={v.host} placeholder="10.0.0.5" onChange={(e) => set({ host: e.target.value })} /></Field>
        <Field label={t('Port')}><input className="mono" inputMode="numeric" value={v.port} placeholder={String(DEFAULT_PORT[v.protocol])} onChange={(e) => set({ port: e.target.value.replace(/\D/g, '') })} /></Field>
        <Field label={t('Folder')}><FolderSelect folders={folders.rows} value={v.folder_id} onChange={(x) => set({ folder_id: x })} /></Field>
        <Field label={t('Site')} help={t('Hosts behind an edge agent belong to an agent site.')}>
          <select value={v.site_id} onChange={(e) => set({ site_id: e.target.value })}>
            <option value="">{t('(direct: reachable from paltad)')}</option>
            {sites.rows.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.kind === 'agent' ? t('agent') : t('direct')})</option>)}
          </select>
        </Field>
        <Field label={t('Credentials')} help={v.credential_mode === 'prompt' ? t('Each user types them when connecting; they are not stored.') : t('Injected from the vault, or none: RDP then shows the Windows login screen if the server allows it, and asks for credentials if it requires NLA.')}>
          <select value={v.credential_mode} onChange={(e) => set({ credential_mode: e.target.value as Connection['credential_mode'] })}>
            <option value="vault">{t('From the vault')}</option>
            <option value="prompt">{t('Ask when connecting')}</option>
          </select>
        </Field>
        {v.credential_mode === 'vault' && <Field label={t('Credential')} help={<>{t('Injected at connect time; users never see it.')} <button type="button" className="link" onClick={() => openDialog((c) => <SecretFormDialog onClose={c} onCreated={(s) => set({ secret_id: s.id })} />)}>{t('New credential…')}</button></>}>
          <select value={v.secret_id} onChange={(e) => set({ secret_id: e.target.value })}>
            <option value="">{t('(none)')}</option>
            {secrets.rows.map((s) => <option key={s.id} value={s.id}>{s.name} — {s.username}</option>)}
          </select>
        </Field>}
        {v.protocol === 'rdp' && (
          <>
            <Field label={t('Windows domain')} help={t('Optional; for domain accounts.')}><input value={rdp.domain} placeholder="CORP" onChange={(e) => setRdp({ ...rdp, domain: e.target.value })} /></Field>
            <Field label={t('Security')} help={t('NLA authenticates before the session starts; xrdp only supports TLS.')}>
              <select value={rdp.security} onChange={(e) => setRdp({ ...rdp, security: e.target.value })}>
                <option value="any">{t('Automatic (NLA or TLS)')}</option>
                <option value="nla">{t('NLA (CredSSP) only')}</option>
                <option value="tls">{t('TLS only')}</option>
              </select>
            </Field>
          </>
        )}
        <Field label={t('Environment')}><input value={v.environment} placeholder="prod" onChange={(e) => set({ environment: e.target.value })} /></Field>
        <Field label={t('Tags')} span help={t('Access can be granted on a tag: it then covers every connection carrying it.')}><TagsInput value={v.tags} onChange={(tags) => set({ tags })} /></Field>
        <Field label={t('Description')} span><input value={v.description} onChange={(e) => set({ description: e.target.value })} /></Field>
        <label className="check span-2"><input type="checkbox" checked={v.record} onChange={(e) => set({ record: e.target.checked })} /> {t('Record sessions')}</label>
        {v.record && (
          <label className="check span-2">
            <input type="checkbox" checked={v.record_input} onChange={(e) => set({ record_input: e.target.checked })} /> {t('Also record keystrokes')}
            <span className="muted small"> — {t('captures anything typed, including passwords for sudo')}</span>
          </label>
        )}
      </div>
      {v.protocol === 'vnc' && <p className="help">{t('VNC: the credential is the VNC password (its account name is not used). Leave it empty for servers without a password.')}</p>}
    </Modal>
  )
}

function MoveFolderDialog({ folderId, onClose }: { folderId: string; onClose: () => void }) {
  const folders = useFolders()
  const f = folders.map.get(folderId)
  const [parent, setParent] = useState(f?.parent_id ?? '')
  const exclude = useMemo(() => subtree(folders.rows, folderId), [folders.rows, folderId])
  return (
    <Modal title={t('Move {0}', f?.name ?? '')} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" onClick={() => api.patch(`/folders/${folderId}`, { parent_id: parent || null }).then(() => (invalidate('/folders'), onClose()), toast.err)}>{t('Move')}</button></>}>
      <Field label={t('Into')}><FolderSelect folders={folders.rows} value={parent} onChange={setParent} exclude={exclude} rootLabel={t('(root)')} /></Field>
    </Modal>
  )
}
