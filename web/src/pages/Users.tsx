import { t } from '../i18n'
import { useMemo, useState } from 'react'
import { Users as UsersIcon, Plus, Search, X, Pencil, KeyRound, ShieldOff, Ban, CheckCircle2, Trash2, ShieldCheck, UsersRound, Server } from 'lucide-react'
import { api, enc } from '../lib/api'
import type { AccessEntry, Group, Policy, Role, User } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { go, href } from '../lib/router'
import { ago, dateTime } from '../lib/format'
import { getMe, isSuperadmin } from '../lib/session'
import { useUsers } from '../lib/lookup'
import type { MenuEntry } from '../ui/ContextMenu'
import { Avatar, DataTable, MenuButton, Pill, Props, Section, Spinner, Tag } from '../ui/common'
import { Drawer, Modal, confirm, openDialog, toast } from '../ui/overlays'
import { Field } from '../components/FormBits'
import { PolicyDialog, PolicyList } from './Policies'
import { ProtoTag } from './Portal'

export const ROLE_LABEL: Record<string, string> = {
  superadmin: t('Superadmin'),
  admin: t('Administrator'),
  auditor: t('Auditor'),
  user: t('User'),
}
const ROLE_HELP: Record<string, string> = {
  superadmin: t('Manages everything, including other superadmins.'),
  admin: t('Manages the catalog, users, groups and access.'),
  auditor: t('Reads the audit log and watches recordings.'),
  user: t('Opens the connections they are granted.'),
}

export function RoleTag({ role }: { role: string }) {
  const tone = role === 'superadmin' ? 'bad' : role === 'admin' ? 'warn' : role === 'auditor' ? 'info' : undefined
  return <Tag tone={tone}>{ROLE_LABEL[role] ?? role}</Tag>
}

function userActions(u: User): MenuEntry[] {
  const self = u.id === getMe()?.user.id
  const locked = u.role === 'superadmin' && !isSuperadmin()
  return [
    { header: u.username },
    { label: t('Open'), onClick: () => go('users', u.id) },
    { label: t('Edit…'), icon: <Pencil size={14} />, disabled: locked, onClick: () => openDialog((c) => <UserFormDialog initial={u} onClose={c} />) },
    { label: t('Grant access…'), icon: <ShieldCheck size={14} />, onClick: () => openDialog((c) => <PolicyDialog subject={{ type: 'user', id: u.id }} onClose={c} />) },
    'sep',
    u.source === 'local' && { label: t('Reset password…'), icon: <KeyRound size={14} />, disabled: locked, onClick: () => openDialog((c) => <ResetPasswordDialog user={u} onClose={c} />) },
    u.totp_enabled && { label: t('Reset TOTP'), icon: <ShieldOff size={14} />, disabled: locked, onClick: () => resetTOTP(u) },
    !self && { label: u.disabled ? t('Enable') : t('Disable'), icon: u.disabled ? <CheckCircle2 size={14} /> : <Ban size={14} />, disabled: locked, onClick: () => setDisabled(u, !u.disabled) },
    !self && {
      label: t('Delete'), icon: <Trash2 size={14} />, danger: true, disabled: locked, onClick: async () => {
        if (!(await confirm({ title: t('Delete {0}?', u.username), body: t('Their access grants are removed. Their audit history is kept.'), danger: true, confirm: t('Delete') }))) return
        api.del(`/users/${u.id}`).then(() => (invalidate('/users'), go('users')), toast.err)
      },
    },
  ]
}

async function resetTOTP(u: User) {
  if (!(await confirm({ title: t('Reset the TOTP of {0}?', u.username), body: t('They will sign in with the password alone until they enroll again.'), confirm: t('Reset') }))) return
  api.del(`/users/${u.id}/totp`).then(() => (invalidate('/users'), toast.ok(t('TOTP reset'))), toast.err)
}

async function setDisabled(u: User, disabled: boolean) {
  if (disabled && !(await confirm({ title: t('Disable {0}?', u.username), body: t('They cannot sign in and their web sessions end now. Open remote sessions are not cut.'), danger: true, confirm: t('Disable') }))) return
  api.patch(`/users/${u.id}`, { disabled }).then(() => invalidate('/users'), toast.err)
}

export function Users({ id, tab }: { id?: string; tab?: string }) {
  const users = useUsers()
  const [q, setQ] = useState('')
  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return users.rows.filter((u) => words.every((w) => `${u.username} ${u.display_name} ${u.email} ${u.role}`.toLowerCase().includes(w)))
  }, [users.rows, q])
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <UsersIcon size={20} />
          <h1>{t('Users')}</h1>
          <span className="count">{users.rows.length}</span>
          {users.loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Search by name, email, role…')} value={q} onChange={(e) => setQ(e.target.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => openDialog((c) => <UserFormDialog onClose={c} />)}><Plus size={14} /> {t('User')}</button>
        </div>
      </div>
      <div className="page-body">
        {users.error && <div className="alert alert-bad">{users.error.message}</div>}
        <DataTable
          rows={rows}
          rowKey={(u) => u.id}
          onOpen={(u) => go('users', u.id)}
          rowMenu={userActions}
          rowClass={(u) => (u.disabled ? 'dim' : '')}
          defaultSort={{ key: 'name', dir: 1 }}
          columns={[
            {
              key: 'name', label: t('Name'), sort: (u) => u.username, render: (u) => (
                <span className="cell-name">
                  <Avatar name={u.username} size={26} />
                  <span className="cell-name-text"><strong>{u.display_name || u.username}</strong>{u.display_name && <span className="muted small">{u.username}</span>}</span>
                </span>
              ),
            },
            { key: 'role', label: t('Role'), sort: (u) => u.role, render: (u) => <RoleTag role={u.role} /> },
            { key: 'mfa', label: 'TOTP', sort: (u) => (u.totp_enabled ? 1 : 0), render: (u) => (u.totp_enabled ? <Tag tone="ok">{t('on')}</Tag> : <span className="muted small">{t('off')}</span>) },
            { key: 'state', label: t('Status'), sort: (u) => (u.disabled ? 1 : 0), render: (u) => <Pill state={u.disabled ? 'disabled' : 'enabled'} /> },
            { key: 'login', label: t('Last login'), sort: (u) => u.last_login_at ?? '', render: (u) => <span className="muted small" title={dateTime(u.last_login_at)}>{u.last_login_at ? ago(u.last_login_at) : t('never')}</span> },
            { key: 'email', label: 'Email', render: (u) => <span className="muted small">{u.email}</span> },
          ]}
        />
      </div>
      {id && <UserDrawer id={id} tab={tab} onClose={() => go('users')} />}
    </div>
  )
}

function UserDrawer({ id, onClose }: { id: string; tab?: string; onClose: () => void }) {
  const { data: u, error } = useResource<User>(`/users/${enc(id)}`)
  const { data: groups } = useResource<Group[]>(`/users/${enc(id)}/groups`)
  const { data: access } = useResource<AccessEntry[]>(`/users/${enc(id)}/access`)
  const { data: policies } = useResource<Policy[]>(`/policies?subject_id=${enc(id)}`)
  return (
    <Drawer onClose={onClose} width={640}>
      {error && <div className="alert alert-bad">{error.message}</div>}
      {!u ? <Spinner /> : (
        <div className="drawer-body">
          <header className="record-head">
            <Avatar name={u.username} size={48} square />
            <div className="record-title">
              <h1>{u.display_name || u.username}</h1>
              <div className="row gap wrap">
                <RoleTag role={u.role} />
                <Pill state={u.disabled ? 'disabled' : 'enabled'} />
                {u.totp_enabled && <Tag tone="ok">TOTP</Tag>}
                <span className="muted small mono">{u.username}</span>
              </div>
            </div>
            <div className="record-actions"><MenuButton items={() => userActions(u)} className="btn btn-sm" /></div>
          </header>
          <Section title={t('Properties')}>
            <Props items={[
              ['Email', u.email || '—'],
              [t('Source'), u.source === 'local' ? t('local account') : u.source],
              [t('Last login'), u.last_login_at ? <span title={dateTime(u.last_login_at)}>{ago(u.last_login_at)}</span> : t('never')],
              [t('Created'), <span title={dateTime(u.created_at)}>{ago(u.created_at)}</span>],
            ]} />
          </Section>
          <Section title={t('Groups')}>
            {groups?.length ? (
              <span className="tags">{groups.map((g) => <a key={g.id} href={href('groups', g.id)}><Tag><UsersRound size={11} /> {g.name}</Tag></a>)}</span>
            ) : <span className="muted">{t('Not in any group.')}</span>}
          </Section>
          <Section title={t('Direct grants')} actions={<button className="btn btn-sm" onClick={() => openDialog((c) => <PolicyDialog subject={{ type: 'user', id: u.id }} onClose={c} />)}><Plus size={13} /> {t('Grant')}</button>}>
            <PolicyList rows={policies || []} hideSubject />
          </Section>
          <Section title={t('Effective access')}>
            <p className="help">{t('Everything this user can open right now, through direct grants and their groups.')}</p>
            {access?.length ? (
              <div className="rel-list">
                {access.map((a) => (
                  <a key={a.connection.id} className="rel-item" href={href('connections', a.connection.id)}>
                    <Server size={13} /> <strong>{a.connection.name}</strong> <ProtoTag p={a.connection.protocol} />
                    <span className="grow" />
                    <span className="muted small">{t('{0} grant(s)', a.grants.length)}</span>
                  </a>
                ))}
              </div>
            ) : <span className="muted">{t('No access.')}</span>}
          </Section>
        </div>
      )}
    </Drawer>
  )
}

export function UserFormDialog({ initial, onClose }: { initial?: User; onClose: () => void }) {
  const [v, setV] = useState({ username: initial?.username ?? '', display_name: initial?.display_name ?? '', email: initial?.email ?? '', role: (initial?.role ?? 'user') as Role, password: '' })
  const [busy, setBusy] = useState(false)
  const set = (p: Partial<typeof v>) => setV({ ...v, ...p })
  const roles: Role[] = isSuperadmin() ? ['user', 'auditor', 'admin', 'superadmin'] : ['user', 'auditor', 'admin']
  const save = async () => {
    setBusy(true)
    try {
      if (initial) {
        await api.patch(`/users/${initial.id}`, { display_name: v.display_name, email: v.email, role: v.role })
      } else {
        const u = await api.post<User>('/users', v)
        go('users', u.id)
      }
      invalidate('/users')
      toast.ok(initial ? t('User saved') : t('User {0} created', v.username))
      onClose()
    } catch (e) {
      toast.err(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal title={initial ? t('Edit {0}', initial.username) : t('New user')} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" disabled={busy || !v.username || (!initial && v.password.length < 10)} onClick={save}>{initial ? t('Save') : t('Create')}</button></>}>
      <div className="grid-2">
        <Field label={t('Username')}><input autoFocus={!initial} disabled={!!initial} className="mono" value={v.username} placeholder="ana" onChange={(e) => set({ username: e.target.value.toLowerCase() })} /></Field>
        <Field label={t('Display name')}><input value={v.display_name} placeholder="Ana Pérez" onChange={(e) => set({ display_name: e.target.value })} /></Field>
        <Field label="Email" span><input type="email" value={v.email} onChange={(e) => set({ email: e.target.value })} /></Field>
        {!initial && <Field label={t('Initial password')} span help={t('At least 10 characters. Ask them to change it on first login.')}><input type="password" autoComplete="new-password" value={v.password} onChange={(e) => set({ password: e.target.value })} /></Field>}
        <Field label={t('Role')} span help={ROLE_HELP[v.role]}>
          <select value={v.role} onChange={(e) => set({ role: e.target.value as Role })}>
            {roles.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
          </select>
        </Field>
      </div>
    </Modal>
  )
}

function ResetPasswordDialog({ user, onClose }: { user: User; onClose: () => void }) {
  const [pw, setPw] = useState('')
  return (
    <Modal title={t('Reset the password of {0}', user.username)} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" disabled={pw.length < 10} onClick={() => api.put(`/users/${user.id}/password`, { password: pw }).then(() => (toast.ok(t('Password changed; their sessions were closed.')), onClose()), toast.err)}>{t('Change')}</button></>}>
      <Field label={t('New password')} help={t('At least 10 characters. Their web sessions end.')}><input autoFocus type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
    </Modal>
  )
}

/** Picker used to add a user somewhere (group membership). */
export function UserPicker({ exclude, onPick, onClose, title }: { exclude: Set<string>; onPick: (u: User) => void; onClose: () => void; title: string }) {
  const users = useUsers()
  const [q, setQ] = useState('')
  const rows = users.rows.filter((u) => !exclude.has(u.id) && `${u.username} ${u.display_name}`.toLowerCase().includes(q.toLowerCase()))
  return (
    <Modal title={title} onClose={onClose}>
      <div className="search wide"><Search size={14} /><input autoFocus placeholder={t('Search…')} value={q} onChange={(e) => setQ(e.target.value)} /></div>
      <div className="rel-list picker">
        {rows.map((u) => (
          <button key={u.id} className="rel-item" onClick={() => (onPick(u), onClose())}>
            <Avatar name={u.username} size={22} /> <strong>{u.display_name || u.username}</strong> <span className="muted small">{u.username}</span>
          </button>
        ))}
        {!rows.length && <span className="muted">{t('No users to add.')}</span>}
      </div>
    </Modal>
  )
}

