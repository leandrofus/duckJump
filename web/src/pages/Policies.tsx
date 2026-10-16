import { t } from '../i18n'
import { useMemo, useState } from 'react'
import { ShieldCheck, Plus, Search, X, Trash2, Clock, User as UserIcon, UsersRound, Server, Folder as FolderIcon, Tag as TagIcon, Pencil } from 'lucide-react'
import { api } from '../lib/api'
import type { Policy } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { ago, dateTime } from '../lib/format'
import { href } from '../lib/router'
import { folderTree, useConnections, useFolders, useGroups, useUsers } from '../lib/lookup'
import { DataTable, Empty, Spinner, Tag } from '../ui/common'
import { Modal, confirm, openDialog, toast } from '../ui/overlays'
import { Field } from '../components/FormBits'

type Subject = { type: 'user' | 'group'; id: string }
type ObjectRef = { type: 'connection' | 'folder' | 'tag'; ref: string }

const TTLS = [
  { label: t('Permanent'), s: 0 },
  { label: t('1 hour'), s: 3600 },
  { label: t('8 hours'), s: 8 * 3600 },
  { label: t('1 day'), s: 86400 },
  { label: t('7 days'), s: 7 * 86400 },
  { label: t('30 days'), s: 30 * 86400 },
]

/** Names for the subject and object of a policy. */
function usePolicyNames() {
  const users = useUsers()
  const groups = useGroups()
  const conns = useConnections()
  const folders = useFolders()
  return {
    subject: (p: Policy) => {
      if (p.subject_type === 'user') {
        const u = users.map.get(p.subject_id)
        return { icon: <UserIcon size={13} />, name: u ? u.display_name || u.username : '?', link: href('users', p.subject_id) }
      }
      return { icon: <UsersRound size={13} />, name: groups.map.get(p.subject_id)?.name ?? '?', link: href('groups', p.subject_id) }
    },
    object: (p: Policy) => {
      if (p.object_type === 'connection') return { icon: <Server size={13} />, name: conns.map.get(p.object_ref)?.name ?? '?', link: href('connections', p.object_ref) }
      if (p.object_type === 'folder') return { icon: <FolderIcon size={13} />, name: folders.path(p.object_ref) || '?', link: href('connections') }
      return { icon: <TagIcon size={13} />, name: p.object_ref, link: undefined }
    },
  }
}

export function expiryState(p: Policy) {
  if (!p.expires_at) return 'permanent'
  const left = Date.parse(p.expires_at) - Date.now()
  return left <= 0 ? 'expired' : left < 86400e3 ? 'expiring' : 'active'
}

function Expiry({ p }: { p: Policy }) {
  const st = expiryState(p)
  if (st === 'permanent') return <span className="muted">{t('permanent')}</span>
  return (
    <span className={`row gap small ${st === 'expired' ? 'tone-bad' : st === 'expiring' ? 'tone-warn' : ''}`} title={dateTime(p.expires_at)}>
      <Clock size={12} /> {st === 'expired' ? t('expired {0}', ago(p.expires_at)) : t('expires {0}', ago(p.expires_at))}
    </span>
  )
}

function Perms({ p }: { p: Policy }) {
  return (
    <span className="tags">
      {p.can_connect && <Tag tone="ok">{t('connect')}</Tag>}
      {p.can_view_recordings && <Tag>{t('recordings')}</Tag>}
    </span>
  )
}

async function revoke(p: Policy) {
  if (!(await confirm({ title: t('Revoke this access?'), body: t('Sessions already open are not cut.'), danger: true, confirm: t('Revoke') }))) return
  api.del(`/policies/${p.id}`).then(() => (invalidate('/policies', '/access', '/portal'), toast.ok(t('Access revoked'))), toast.err)
}

/** Compact list used inside records (a connection's or user's access). */
export function PolicyList({ rows, hideObject, hideSubject }: { rows: Policy[]; hideObject?: boolean; hideSubject?: boolean }) {
  const names = usePolicyNames()
  if (!rows.length) return <span className="muted">{t('No grants.')}</span>
  return (
    <div className="rel-list">
      {rows.map((p) => {
        const s = names.subject(p)
        const o = names.object(p)
        return (
          <div key={p.id} className={`rel-item${expiryState(p) === 'expired' ? ' dim' : ''}`}>
            {!hideSubject && <a href={s.link} className="row gap">{s.icon} <strong>{s.name}</strong></a>}
            {!hideObject && <span className="row gap">{o.icon} {o.name}</span>}
            <Perms p={p} />
            <span className="grow" />
            <Expiry p={p} />
            <button className="icon-btn" title={t('Revoke')} onClick={() => revoke(p)}><Trash2 size={13} /></button>
          </div>
        )
      })}
    </div>
  )
}

export function Policies() {
  const { data, loading, error } = useResource<Policy[]>('/policies')
  const names = usePolicyNames()
  const [q, setQ] = useState('')
  const [showExpired, setShowExpired] = useState(false)
  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return (data || []).filter((p) => (showExpired || expiryState(p) !== 'expired') && words.every((w) => `${names.subject(p).name} ${names.object(p).name} ${p.description}`.toLowerCase().includes(w)))
  }, [data, q, showExpired, names])
  const expiredCount = (data || []).filter((p) => expiryState(p) === 'expired').length
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <ShieldCheck size={20} />
          <h1>{t('Access')}</h1>
          <span className="count">{rows.length}</span>
          {loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Search by user, group, connection…')} value={q} onChange={(e) => setQ(e.target.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>
          {expiredCount > 0 && (
            <label className="check small"><input type="checkbox" checked={showExpired} onChange={(e) => setShowExpired(e.target.checked)} /> {t('Show expired ({0})', expiredCount)}</label>
          )}
          <button className="btn btn-primary btn-sm" onClick={() => openDialog((c) => <PolicyDialog onClose={c} />)}><Plus size={14} /> {t('Grant access')}</button>
        </div>
      </div>
      <div className="page-body">
        <p className="help">{t('A grant gives a user or a group access to one connection, to everything inside a folder, or to every connection with a tag. Nobody bypasses grants, administrators included.')}</p>
        {error && <div className="alert alert-bad">{error.message}</div>}
        <DataTable
          rows={rows}
          rowKey={(p) => p.id}
          rowClass={(p) => (expiryState(p) === 'expired' ? 'dim' : '')}
          defaultSort={{ key: 'created', dir: -1 }}
          rowMenu={(p) => [
            { header: `${names.subject(p).name} → ${names.object(p).name}` },
            { label: t('Edit…'), icon: <Pencil size={14} />, onClick: () => openDialog((c) => <EditPolicyDialog policy={p} onClose={c} />) },
            { label: t('Revoke'), icon: <Trash2 size={14} />, danger: true, onClick: () => revoke(p) },
          ]}
          onOpen={(p) => openDialog((c) => <EditPolicyDialog policy={p} onClose={c} />)}
          empty={data && <Empty icon={<ShieldCheck size={28} />} title={t('No access granted yet')}>{t('Users see nothing in their portal until they are granted access.')}</Empty>}
          columns={[
            { key: 'subject', label: t('Who'), sort: (p) => names.subject(p).name, render: (p) => { const s = names.subject(p); return <a href={s.link} className="row gap">{s.icon} <strong>{s.name}</strong></a> } },
            { key: 'object', label: t('On'), sort: (p) => names.object(p).name, render: (p) => { const o = names.object(p); return <span className="row gap">{o.icon} {o.name}</span> } },
            { key: 'perms', label: t('Permissions'), render: (p) => <Perms p={p} /> },
            { key: 'exp', label: t('Expiry'), sort: (p) => (p.expires_at ? Date.parse(p.expires_at) : Infinity), render: (p) => <Expiry p={p} /> },
            { key: 'desc', label: t('Reason'), render: (p) => <span className="muted small">{p.description}</span> },
            { key: 'created', label: t('Granted'), sort: (p) => p.created_at, render: (p) => <span className="muted small" title={dateTime(p.created_at)}>{ago(p.created_at)}</span> },
          ]}
        />
      </div>
    </div>
  )
}

export function PolicyDialog({ subject, object, onClose }: { subject?: Subject; object?: ObjectRef; onClose: () => void }) {
  const users = useUsers()
  const groups = useGroups()
  const conns = useConnections()
  const folders = useFolders()
  const [subj, setSubj] = useState<Subject>(subject ?? { type: 'user', id: '' })
  const [obj, setObj] = useState<ObjectRef>(object ?? { type: 'connection', ref: '' })
  const [connect, setConnect] = useState(true)
  const [recordings, setRecordings] = useState(false)
  const [ttl, setTTL] = useState(0)
  const [desc, setDesc] = useState('')
  const [busy, setBusy] = useState(false)
  const tags = useMemo(() => [...new Set(conns.rows.flatMap((c) => c.tags))].sort(), [conns.rows])
  const save = async () => {
    setBusy(true)
    try {
      await api.post('/policies', {
        subject_type: subj.type, subject_id: subj.id, object_type: obj.type, object_ref: obj.ref,
        can_connect: connect, can_view_recordings: recordings, description: desc.trim(), ...(ttl ? { ttl_seconds: ttl } : {}),
      })
      invalidate('/policies', '/access', '/portal')
      toast.ok(t('Access granted'))
      onClose()
    } catch (e) {
      toast.err(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal wide title={t('Grant access')} icon={<ShieldCheck size={18} />} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" disabled={busy || !subj.id || !obj.ref || (!connect && !recordings)} onClick={save}>{t('Grant')}</button></>}>
      <div className="grid-2">
        <Field label={t('Who')}>
          <div className="seg seg-text">
            <button type="button" className={subj.type === 'user' ? 'on' : ''} disabled={!!subject} onClick={() => setSubj({ type: 'user', id: '' })}>{t('User')}</button>
            <button type="button" className={subj.type === 'group' ? 'on' : ''} disabled={!!subject} onClick={() => setSubj({ type: 'group', id: '' })}>{t('Group')}</button>
          </div>
        </Field>
        <Field label={subj.type === 'user' ? t('User') : t('Group')}>
          <select value={subj.id} disabled={!!subject} onChange={(e) => setSubj({ ...subj, id: e.target.value })}>
            <option value="">{t('Choose…')}</option>
            {subj.type === 'user'
              ? users.rows.map((u) => <option key={u.id} value={u.id}>{u.display_name ? `${u.display_name} (${u.username})` : u.username}</option>)
              : groups.rows.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </Field>
        <Field label={t('On')}>
          <div className="seg seg-text">
            {(['connection', 'folder', 'tag'] as const).map((k) => (
              <button key={k} type="button" className={obj.type === k ? 'on' : ''} disabled={!!object} onClick={() => setObj({ type: k, ref: '' })}>
                {k === 'connection' ? t('Connection') : k === 'folder' ? t('Folder') : t('Tag')}
              </button>
            ))}
          </div>
        </Field>
        <Field label={obj.type === 'connection' ? t('Connection') : obj.type === 'folder' ? t('Folder (and everything inside)') : t('Tag')}>
          {obj.type === 'connection' && (
            <select value={obj.ref} disabled={!!object} onChange={(e) => setObj({ ...obj, ref: e.target.value })}>
              <option value="">{t('Choose…')}</option>
              {conns.rows.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          )}
          {obj.type === 'folder' && (
            <select value={obj.ref} disabled={!!object} onChange={(e) => setObj({ ...obj, ref: e.target.value })}>
              <option value="">{t('Choose…')}</option>
              {folderTree(folders.rows).map(({ folder, depth }) => <option key={folder.id} value={folder.id}>{'  '.repeat(depth * 2)}{folder.name}</option>)}
            </select>
          )}
          {obj.type === 'tag' && (
            <>
              <input className="mono" list="dj-tags" value={obj.ref} disabled={!!object} placeholder="linux" onChange={(e) => setObj({ ...obj, ref: e.target.value.toLowerCase().trim() })} />
              <datalist id="dj-tags">{tags.map((x) => <option key={x} value={x} />)}</datalist>
            </>
          )}
        </Field>
        <Field label={t('Permissions')} span>
          <div className="row gap wrap">
            <label className="check"><input type="checkbox" checked={connect} onChange={(e) => setConnect(e.target.checked)} /> {t('Open sessions')}</label>
            <label className="check"><input type="checkbox" checked={recordings} onChange={(e) => setRecordings(e.target.checked)} /> {t('Watch its session recordings')}</label>
          </div>
        </Field>
        <Field label={t('Duration')} span help={t('Temporary access expires on its own (just-in-time).')}>
          <div className="seg seg-text wrap">
            {TTLS.map((x) => <button key={x.s} type="button" className={ttl === x.s ? 'on' : ''} onClick={() => setTTL(x.s)}>{x.label}</button>)}
          </div>
        </Field>
        <Field label={t('Reason')} span><input value={desc} placeholder={t('e.g. ticket OPS-1234, on-call this week')} onChange={(e) => setDesc(e.target.value)} /></Field>
      </div>
    </Modal>
  )
}

function EditPolicyDialog({ policy, onClose }: { policy: Policy; onClose: () => void }) {
  const names = usePolicyNames()
  const [connect, setConnect] = useState(policy.can_connect)
  const [recordings, setRecordings] = useState(policy.can_view_recordings)
  const [exp, setExp] = useState(policy.expires_at ? toLocalInput(policy.expires_at) : '')
  const [desc, setDesc] = useState(policy.description)
  const save = () =>
    api
      .patch(`/policies/${policy.id}`, { can_connect: connect, can_view_recordings: recordings, description: desc, expires_at: exp ? new Date(exp).toISOString() : null })
      .then(() => (invalidate('/policies', '/access', '/portal'), onClose()), toast.err)
  const s = names.subject(policy)
  const o = names.object(policy)
  return (
    <Modal title={t('Edit access')} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" disabled={!connect && !recordings} onClick={save}>{t('Save')}</button></>}>
      <p className="row gap">{s.icon} <strong>{s.name}</strong> → {o.icon} {o.name}</p>
      <div className="row gap wrap">
        <label className="check"><input type="checkbox" checked={connect} onChange={(e) => setConnect(e.target.checked)} /> {t('Open sessions')}</label>
        <label className="check"><input type="checkbox" checked={recordings} onChange={(e) => setRecordings(e.target.checked)} /> {t('Watch its session recordings')}</label>
      </div>
      <Field label={t('Expires')} help={t('Empty: permanent.')}>
        <div className="row gap">
          <input type="datetime-local" value={exp} onChange={(e) => setExp(e.target.value)} />
          {exp && <button className="btn btn-sm" onClick={() => setExp('')}>{t('Make permanent')}</button>}
        </div>
      </Field>
      <Field label={t('Reason')}><input value={desc} onChange={(e) => setDesc(e.target.value)} /></Field>
    </Modal>
  )
}

function toLocalInput(iso: string) {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}
