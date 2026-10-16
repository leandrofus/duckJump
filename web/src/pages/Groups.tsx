import { t } from '../i18n'
import { useMemo, useState } from 'react'
import { UsersRound, Plus, Search, X, Pencil, Trash2, ShieldCheck, UserPlus, UserMinus } from 'lucide-react'
import { api, enc } from '../lib/api'
import type { Group, Policy, User } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { go, href } from '../lib/router'
import { useGroups } from '../lib/lookup'
import type { MenuEntry } from '../ui/ContextMenu'
import { Avatar, DataTable, Empty, MenuButton, Section, Spinner } from '../ui/common'
import { Drawer, Modal, confirm, openDialog, toast } from '../ui/overlays'
import { Field } from '../components/FormBits'
import { PolicyDialog, PolicyList } from './Policies'
import { RoleTag, UserPicker } from './Users'

function groupActions(g: Group): MenuEntry[] {
  return [
    { header: g.name },
    { label: t('Open'), onClick: () => go('groups', g.id) },
    { label: t('Edit…'), icon: <Pencil size={14} />, onClick: () => openDialog((c) => <GroupFormDialog initial={g} onClose={c} />) },
    { label: t('Grant access…'), icon: <ShieldCheck size={14} />, onClick: () => openDialog((c) => <PolicyDialog subject={{ type: 'group', id: g.id }} onClose={c} />) },
    'sep',
    {
      label: t('Delete'), icon: <Trash2 size={14} />, danger: true, onClick: async () => {
        if (!(await confirm({ title: t('Delete group {0}?', g.name), body: t('Its members keep their accounts but lose the access granted to the group.'), danger: true, confirm: t('Delete') }))) return
        api.del(`/groups/${g.id}`).then(() => (invalidate('/groups', '/policies'), go('groups')), toast.err)
      },
    },
  ]
}

export function Groups({ id }: { id?: string }) {
  const groups = useGroups()
  const [q, setQ] = useState('')
  const rows = useMemo(() => groups.rows.filter((g) => `${g.name} ${g.description}`.toLowerCase().includes(q.toLowerCase())), [groups.rows, q])
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <UsersRound size={20} />
          <h1>{t('Groups')}</h1>
          <span className="count">{groups.rows.length}</span>
          {groups.loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Search groups…')} value={q} onChange={(e) => setQ(e.target.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => openDialog((c) => <GroupFormDialog onClose={c} />)}><Plus size={14} /> {t('Group')}</button>
        </div>
      </div>
      <div className="page-body">
        <p className="help">{t('Grant access to groups instead of people: joining or leaving the group is all it takes.')}</p>
        <DataTable
          rows={rows}
          rowKey={(g) => g.id}
          onOpen={(g) => go('groups', g.id)}
          rowMenu={groupActions}
          defaultSort={{ key: 'name', dir: 1 }}
          empty={groups.data && <Empty icon={<UsersRound size={28} />} title={t('No groups yet')} action={<button className="btn btn-primary" onClick={() => openDialog((c) => <GroupFormDialog onClose={c} />)}><Plus size={14} /> {t('New group')}</button>} />}
          columns={[
            { key: 'name', label: t('Name'), sort: (g) => g.name, render: (g) => <strong>{g.name}</strong> },
            { key: 'members', label: t('Members'), sort: (g) => g.member_count ?? 0, render: (g) => g.member_count ?? 0 },
            { key: 'desc', label: t('Description'), render: (g) => <span className="muted">{g.description}</span> },
          ]}
        />
      </div>
      {id && <GroupDrawer id={id} onClose={() => go('groups')} />}
    </div>
  )
}

function GroupDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: g, error } = useResource<Group>(`/groups/${enc(id)}`)
  const { data: members } = useResource<User[]>(`/groups/${enc(id)}/members`)
  const { data: policies } = useResource<Policy[]>(`/policies?subject_id=${enc(id)}`)
  const add = (u: User) => api.put(`/groups/${id}/members/${u.id}`).then(() => invalidate(`/groups`, '/access', '/users/'), toast.err)
  const remove = (u: User) => api.del(`/groups/${id}/members/${u.id}`).then(() => invalidate(`/groups`, '/access', '/users/'), toast.err)
  return (
    <Drawer onClose={onClose} width={600}>
      {error && <div className="alert alert-bad">{error.message}</div>}
      {!g ? <Spinner /> : (
        <div className="drawer-body">
          <header className="record-head">
            <div className="record-title">
              <h1>{g.name}</h1>
              {g.description && <span className="muted">{g.description}</span>}
            </div>
            <div className="record-actions"><MenuButton items={() => groupActions(g)} className="btn btn-sm" /></div>
          </header>
          <Section title={t('Members ({0})', members?.length ?? 0)} actions={
            <button className="btn btn-sm" onClick={() => openDialog((c) => <UserPicker title={t('Add to {0}', g.name)} exclude={new Set((members || []).map((m) => m.id))} onPick={add} onClose={c} />)}>
              <UserPlus size={13} /> {t('Add')}
            </button>
          }>
            {members?.length ? (
              <div className="rel-list">
                {members.map((u) => (
                  <div key={u.id} className="rel-item">
                    <Avatar name={u.username} size={22} />
                    <a href={href('users', u.id)}><strong>{u.display_name || u.username}</strong></a>
                    <RoleTag role={u.role} />
                    <span className="grow" />
                    <button className="icon-btn" title={t('Remove from the group')} onClick={() => remove(u)}><UserMinus size={14} /></button>
                  </div>
                ))}
              </div>
            ) : <span className="muted">{t('No members.')}</span>}
          </Section>
          <Section title={t('Access granted to the group')} actions={<button className="btn btn-sm" onClick={() => openDialog((c) => <PolicyDialog subject={{ type: 'group', id: g.id }} onClose={c} />)}><Plus size={13} /> {t('Grant')}</button>}>
            <PolicyList rows={policies || []} hideSubject />
          </Section>
        </div>
      )}
    </Drawer>
  )
}

export function GroupFormDialog({ initial, onClose }: { initial?: Group; onClose: () => void }) {
  const [name, setName] = useState(initial?.name ?? '')
  const [desc, setDesc] = useState(initial?.description ?? '')
  const save = async () => {
    try {
      if (initial) await api.patch(`/groups/${initial.id}`, { name, description: desc })
      else go('groups', (await api.post<Group>('/groups', { name, description: desc })).id)
      invalidate('/groups')
      onClose()
    } catch (e) {
      toast.err(e)
    }
  }
  return (
    <Modal title={initial ? t('Edit {0}', initial.name) : t('New group')} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" disabled={!name.trim()} onClick={save}>{initial ? t('Save') : t('Create')}</button></>}>
      <Field label={t('Name')}><input autoFocus value={name} placeholder="ops" onChange={(e) => setName(e.target.value)} /></Field>
      <Field label={t('Description')}><input value={desc} onChange={(e) => setDesc(e.target.value)} /></Field>
    </Modal>
  )
}
