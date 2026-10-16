import { t } from '../i18n'
import { useMemo, useState } from 'react'
import { KeyRound, Plus, Search, X, Pencil, Trash2, RefreshCw, Lock } from 'lucide-react'
import { api } from '../lib/api'
import type { Secret } from '../lib/api'
import { invalidate } from '../lib/store'
import { ago, dateTime } from '../lib/format'
import { useSecrets } from '../lib/lookup'
import type { MenuEntry } from '../ui/ContextMenu'
import { DataTable, Empty, Spinner, Tag } from '../ui/common'
import { Modal, confirm, openDialog, toast } from '../ui/overlays'
import { Field } from '../components/FormBits'

function secretActions(s: Secret): MenuEntry[] {
  return [
    { header: s.name },
    { label: t('Edit…'), icon: <Pencil size={14} />, onClick: () => openDialog((c) => <SecretFormDialog initial={s} onClose={c} />) },
    { label: t('Replace the value…'), icon: <RefreshCw size={14} />, onClick: () => openDialog((c) => <SecretFormDialog initial={s} replace onClose={c} />) },
    'sep',
    {
      label: t('Delete'), icon: <Trash2 size={14} />, danger: true, onClick: async () => {
        const n = s.connection_count ?? 0
        if (!(await confirm({ title: t('Delete credential {0}?', s.name), body: n ? t('{0} connection(s) use it and will be left without a credential.', n) : undefined, danger: true, confirm: t('Delete') }))) return
        api.del(`/secrets/${s.id}`).then(() => invalidate('/secrets', '/connections'), toast.err)
      },
    },
  ]
}

export function Secrets() {
  const secrets = useSecrets()
  const [q, setQ] = useState('')
  const rows = useMemo(() => secrets.rows.filter((s) => `${s.name} ${s.username}`.toLowerCase().includes(q.toLowerCase())), [secrets.rows, q])
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <KeyRound size={20} />
          <h1>{t('Credentials')}</h1>
          <span className="count">{secrets.rows.length}</span>
          {secrets.loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Search credentials…')} value={q} onChange={(e) => setQ(e.target.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => openDialog((c) => <SecretFormDialog onClose={c} />)}><Plus size={14} /> {t('Credential')}</button>
        </div>
      </div>
      <div className="page-body">
        <p className="help row gap"><Lock size={13} /> {t('Encrypted in the vault (AES-256-GCM). Values are write-only: no screen or API ever shows them again, and users never see them when connecting.')}</p>
        <DataTable
          rows={rows}
          rowKey={(s) => s.id}
          rowMenu={secretActions}
          onOpen={(s) => openDialog((c) => <SecretFormDialog initial={s} onClose={c} />)}
          defaultSort={{ key: 'name', dir: 1 }}
          empty={secrets.data && <Empty icon={<KeyRound size={28} />} title={t('No credentials yet')} action={<button className="btn btn-primary" onClick={() => openDialog((c) => <SecretFormDialog onClose={c} />)}><Plus size={14} /> {t('New credential')}</button>} />}
          columns={[
            { key: 'name', label: t('Name'), sort: (s) => s.name, render: (s) => <strong>{s.name}</strong> },
            { key: 'user', label: t('Account'), sort: (s) => s.username, render: (s) => <span className="mono small">{s.username}</span> },
            { key: 'kind', label: t('Type'), sort: (s) => s.kind, render: (s) => <Tag>{s.kind === 'password' ? t('password') : t('private key')}</Tag> },
            { key: 'uses', label: t('Used by'), sort: (s) => s.connection_count ?? 0, render: (s) => t('{0} connection(s)', s.connection_count ?? 0) },
            { key: 'updated', label: t('Updated'), sort: (s) => s.updated_at, render: (s) => <span className="muted small" title={dateTime(s.updated_at)}>{ago(s.updated_at)}</span> },
          ]}
        />
      </div>
    </div>
  )
}

export function SecretFormDialog({ initial, replace, onClose, onCreated }: { initial?: Secret; replace?: boolean; onClose: () => void; onCreated?: (s: Secret) => void }) {
  const [name, setName] = useState(initial?.name ?? '')
  const [username, setUsername] = useState(initial?.username ?? '')
  const [kind, setKind] = useState<'password' | 'private_key'>(initial?.kind ?? 'password')
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const editingMeta = !!initial && !replace
  const loadFile = async (f: File | undefined) => f && setValue(await f.text())
  const save = async () => {
    setBusy(true)
    try {
      if (!initial) {
        const s = await api.post<Secret>('/secrets', { name, username, kind, value })
        onCreated?.(s)
      } else if (replace) {
        await api.patch(`/secrets/${initial.id}`, { kind, value })
      } else {
        await api.patch(`/secrets/${initial.id}`, { name, username })
      }
      invalidate('/secrets')
      toast.ok(t('Credential saved'))
      onClose()
    } catch (e) {
      toast.err(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal title={replace ? t('Replace the value of {0}', initial!.name) : initial ? t('Edit {0}', initial.name) : t('New credential')} icon={<KeyRound size={18} />} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" disabled={busy || (editingMeta ? !name || !username : !value || (!initial && (!name || !username)))} onClick={save}>{t('Save')}</button></>}>
      {!replace && (
        <div className="grid-2">
          <Field label={t('Name')}><input autoFocus value={name} placeholder="web-root" onChange={(e) => setName(e.target.value)} /></Field>
          <Field label={t('Account on the host')}><input className="mono" value={username} placeholder="root" onChange={(e) => setUsername(e.target.value)} /></Field>
        </div>
      )}
      {!editingMeta && (
        <>
          <Field label={t('Type')}>
            <div className="seg seg-text">
              <button type="button" className={kind === 'password' ? 'on' : ''} onClick={() => setKind('password')}>{t('Password')}</button>
              <button type="button" className={kind === 'private_key' ? 'on' : ''} onClick={() => setKind('private_key')}>{t('SSH private key')}</button>
            </div>
          </Field>
          {kind === 'password' ? (
            <Field label={t('Password')}><input type="password" autoComplete="new-password" value={value} onChange={(e) => setValue(e.target.value)} /></Field>
          ) : (
            <Field label={t('Private key')} help={<>{t('OpenSSH or PEM format, without passphrase.')} <label className="link">{t('Load file…')}<input type="file" hidden onChange={(e) => loadFile(e.target.files?.[0])} /></label></>}>
              <textarea className="mono" rows={7} spellCheck={false} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" value={value} onChange={(e) => setValue(e.target.value)} />
            </Field>
          )}
        </>
      )}
    </Modal>
  )
}
