import { t } from '../i18n'
import { useState } from 'react'
import { Network, Plus, Pencil, Trash2, RefreshCw, Copy, Radio, ShieldAlert } from 'lucide-react'
import { api, enc } from '../lib/api'
import type { Agent, Site } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { go } from '../lib/router'
import { ago, copy, dateTime } from '../lib/format'
import type { MenuEntry } from '../ui/ContextMenu'
import { DataTable, Empty, MenuButton, Pill, Props, Section, Spinner, Tag } from '../ui/common'
import { Drawer, Modal, confirm, openDialog, prompt, toast } from '../ui/overlays'
import { Field } from '../components/FormBits'

function siteActions(s: Site): MenuEntry[] {
  return [
    { header: s.name },
    { label: t('Open'), onClick: () => go('sites', s.id) },
    {
      label: t('Rename…'), icon: <Pencil size={14} />, onClick: async () => {
        const name = await prompt({ title: t('Rename site'), label: t('Name'), value: s.name })
        if (name) api.patch(`/sites/${s.id}`, { name }).then(() => invalidate('/sites'), toast.err)
      },
    },
    s.kind === 'agent' && { label: t('Rotate agent token…'), icon: <RefreshCw size={14} />, onClick: () => rotate(s) },
    'sep',
    {
      label: t('Delete'), icon: <Trash2 size={14} />, danger: true, onClick: async () => {
        if (!(await confirm({ title: t('Delete site {0}?', s.name), body: t('Only sites no connection uses can be deleted. Connected agents are dropped.'), danger: true, confirm: t('Delete') }))) return
        api.del(`/sites/${s.id}`).then(() => (invalidate('/sites'), go('sites')), toast.err)
      },
    },
  ]
}

async function rotate(s: Site) {
  if (!(await confirm({ title: t('Rotate the token of {0}?', s.name), body: t('Agents using the current token are disconnected now and must be reconfigured with the new one.'), danger: true, confirm: t('Rotate') }))) return
  try {
    const r = await api.post<Site>(`/sites/${s.id}/token`)
    invalidate('/sites')
    openDialog((c) => <TokenDialog site={r} onClose={c} />)
  } catch (e) {
    toast.err(e)
  }
}

export function Sites({ id }: { id?: string }) {
  const { data: rows, loading } = useResource<Site[]>('/sites', { poll: 4000 })
  const sites = { rows: rows || [], loading }
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <Network size={20} />
          <h1>{t('Sites')}</h1>
          <span className="count">{sites.rows.length}</span>
          {sites.loading && <Spinner />}
        </div>
        <div className="page-actions">
          <button className="btn btn-primary btn-sm" onClick={() => openDialog((c) => <SiteFormDialog onClose={c} />)}><Plus size={14} /> {t('Site')}</button>
        </div>
      </div>
      <div className="page-body">
        <p className="help">{t('A site groups hosts by how they are reached: directly from duckjumpd, or through edge agents that connect outbound from closed networks (behind NAT or a firewall).')}</p>
        <DataTable
          rows={sites.rows}
          rowKey={(s) => s.id}
          onOpen={(s) => go('sites', s.id)}
          rowMenu={siteActions}
          defaultSort={{ key: 'name', dir: 1 }}
          empty={sites.rows.length === 0 && !sites.loading && <Empty icon={<Network size={28} />} title={t('No sites yet')}>{t('Connections without a site are reached directly. Create an agent site for hosts in closed networks.')}</Empty>}
          columns={[
            { key: 'name', label: t('Name'), sort: (s) => s.name, render: (s) => <strong>{s.name}</strong> },
            { key: 'kind', label: t('Type'), sort: (s) => s.kind, render: (s) => <Tag tone={s.kind === 'agent' ? 'info' : undefined}>{s.kind === 'agent' ? t('edge agent') : t('direct')}</Tag> },
            { key: 'agents', label: t('Agents'), sort: (s) => s.agents_online ?? -1, render: (s) => (s.kind === 'agent' ? <Pill state={(s.agents_online ?? 0) > 0 ? 'online' : 'offline'} label={t('{0} online', s.agents_online ?? 0)} /> : <span className="muted">—</span>) },
            { key: 'conns', label: t('Connections'), sort: (s) => s.connection_count ?? 0, render: (s) => s.connection_count ?? 0 },
            { key: 'desc', label: t('Description'), render: (s) => <span className="muted">{s.description}</span> },
          ]}
        />
      </div>
      {id && <SiteDrawer id={id} onClose={() => go('sites')} />}
    </div>
  )
}

function SiteDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: s, error } = useResource<Site>(`/sites/${enc(id)}`, { poll: 3000 })
  const { data: agents } = useResource<Agent[]>(s?.kind === 'agent' ? `/sites/${enc(id)}/agents` : null, { poll: 3000 })
  return (
    <Drawer onClose={onClose} width={620}>
      {error && <div className="alert alert-bad">{error.message}</div>}
      {!s ? <Spinner /> : (
        <div className="drawer-body">
          <header className="record-head">
            <div className="record-title">
              <h1>{s.name}</h1>
              <div className="row gap"><Tag tone={s.kind === 'agent' ? 'info' : undefined}>{s.kind === 'agent' ? t('edge agent') : t('direct')}</Tag></div>
            </div>
            <div className="record-actions"><MenuButton items={() => siteActions(s)} className="btn btn-sm" /></div>
          </header>
          <Section title={t('Properties')}>
            <Props items={[[t('Description'), s.description || '—'], [t('Created'), <span title={dateTime(s.created_at)}>{ago(s.created_at)}</span>]]} />
          </Section>
          {s.kind === 'agent' && (
            <>
              <Section title={t('Connected agents')} actions={<button className="btn btn-sm" onClick={() => rotate(s)}><RefreshCw size={13} /> {t('New token')}</button>}>
                {agents?.length ? (
                  <div className="rel-list">
                    {agents.map((a, i) => (
                      <div key={i} className="rel-item">
                        <Radio size={13} className="tone-ok" /> <strong>{a.name || t('(unnamed)')}</strong>
                        <span className="muted small mono">{a.remote_addr}</span>
                        <span className="grow" />
                        <span className="muted small" title={dateTime(a.connected_at)}>{t('since {0}', ago(a.connected_at))}</span>
                      </div>
                    ))}
                  </div>
                ) : <span className="muted">{t('No agent connected. Install one with the site token.')}</span>}
              </Section>
              <Section title={t('Install an agent')}>
                <AgentInstructions site={s} token="<TOKEN>" />
              </Section>
            </>
          )}
        </div>
      )}
    </Drawer>
  )
}

function AgentInstructions({ site, token }: { site?: Site; token: string }) {
  const [allow, setAllow] = useState('0.0.0.0/0:22,3389,5900')
  const [mode, setMode] = useState<'service' | 'manual'>('service')

  const envUrl = (import.meta.env.VITE_FRONTEND_URL as string | undefined) ||
    (import.meta.env.FRONTEND_URL as string | undefined) ||
    (import.meta.env.FRONTENDURL as string | undefined) ||
    (import.meta.env.DUCKJUMP_FRONTEND_URL as string | undefined)
  const frontendUrl = (site?.frontend_url || envUrl || `${location.protocol}//${location.host}`).replace(/\/+$/, '')
  const downloadUrl = site?.agent_download_url || `${frontendUrl}/agent/duckjump-agent`
  const installUrl = site?.agent_install_url || `${frontendUrl}/agent/install.sh`
  const defaultServer = site?.agent_server_url || `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/agent/connect`
  const [server, setServer] = useState(defaultServer)

  const cleanAllow = allow.trim() || '0.0.0.0/0:22,3389,5900'
  const cleanServer = server.trim() || defaultServer

  const serviceCmd = token && token !== '<TOKEN>'
    ? `curl -fsSLk "${installUrl}?token=${encodeURIComponent(token)}&server=${encodeURIComponent(cleanServer)}&allow=${encodeURIComponent(cleanAllow)}" | sudo bash`
    : `curl -fsSLk "${installUrl}?server=${encodeURIComponent(cleanServer)}&allow=${encodeURIComponent(cleanAllow)}" | sudo DUCKJUMP_AGENT_TOKEN="<TOKEN>" bash`

  const manualCmd = `curl -fsSLk ${downloadUrl} -o duckjump-agent && chmod +x duckjump-agent && \\\n  DUCKJUMP_AGENT_TOKEN=${token} ./duckjump-agent \\\n  -server ${cleanServer} \\\n  -allow ${cleanAllow}`

  const cmd = mode === 'service' ? serviceCmd : manualCmd

  const presets = [
    { label: '0.0.0.0/0', val: '0.0.0.0/0:22,3389,5900' },
    { label: '10.0.0.0/8', val: '10.0.0.0/8:22,3389,5900' },
    { label: '192.168.1.0/24', val: '192.168.1.0/24:22,3389,5900' },
    { label: '172.16.0.0/12', val: '172.16.0.0/12:22,3389,5900' },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <p className="help">
        {t('Run it on a machine inside the closed network. It only opens outbound connections. Adjust -allow to the networks and ports it may reach: the agent refuses everything else, whatever the bastion asks.')}
      </p>

      <div className="field">
        <span>{t('Allowed networks & ports (-allow)')}</span>
        <input
          value={allow}
          onChange={(e) => setAllow(e.target.value)}
          placeholder="0.0.0.0/0:22,3389,5900"
          className="mono"
        />
        <div className="row gap" style={{ marginTop: 4, flexWrap: 'wrap' }}>
          <span className="muted small">{t('Presets:')}</span>
          {presets.map((p) => (
            <button
              key={p.label}
              type="button"
              className={`btn btn-sm ${allow === p.val ? 'on' : 'btn-ghost'}`}
              style={{ height: 22, padding: '0 6px', fontSize: 11 }}
              onClick={() => setAllow(p.val)}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <div className="field">
        <span>{t('Gateway agent endpoint (-server)')}</span>
        <input
          value={server}
          onChange={(e) => setServer(e.target.value)}
          placeholder={defaultServer}
          className="mono"
        />
        <small className="help">
          {t('The WebSocket address where the agent connects (e.g. Tailscale or private IP).')}
        </small>
      </div>

      <div className="row gap" style={{ alignItems: 'center', justifyContent: 'space-between' }}>
        <div className="seg seg-text">
          <button
            type="button"
            className={mode === 'service' ? 'on' : ''}
            onClick={() => setMode('service')}
          >
            {t('Systemd service')}
          </button>
          <button
            type="button"
            className={mode === 'manual' ? 'on' : ''}
            onClick={() => setMode('manual')}
          >
            {t('Run directly')}
          </button>
        </div>
        {mode === 'service' && (
          <span className="muted small">{t('Installs and enables duckjump-agent.service')}</span>
        )}
      </div>

      <div className="code-block">
        <pre className="mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{cmd}</pre>
        <button
          className="icon-btn"
          title={t('Copy')}
          onClick={() => {
            copy(cmd.replace(/\\\n\s+/g, ' '))
            toast.ok(t('Copied'))
          }}
        >
          <Copy size={14} />
        </button>
      </div>
    </div>
  )
}

function TokenDialog({ site, onClose }: { site: Site; onClose: () => void }) {
  return (
    <Modal wide title={t('Agent token for {0}', site.name)} icon={<ShieldAlert size={18} className="tone-warn" />} onClose={onClose}
      footer={<button className="btn btn-primary" onClick={onClose}>{t('I saved it')}</button>}>
      <div className="alert alert-warn">{t('This is the only time the token is shown. Store it now: if it is lost, rotate it.')}</div>
      <div className="code-block">
        <pre className="mono">{site.agent_token}</pre>
        <button className="icon-btn" title={t('Copy')} onClick={() => (copy(site.agent_token || ''), toast.ok(t('Copied')))}><Copy size={14} /></button>
      </div>
      <AgentInstructions site={site} token={site.agent_token || ''} />
    </Modal>
  )
}

export function SiteFormDialog({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('')
  const [kind, setKind] = useState<'direct' | 'agent'>('agent')
  const [desc, setDesc] = useState('')
  const save = async () => {
    try {
      const s = await api.post<Site>('/sites', { name, kind, description: desc })
      invalidate('/sites')
      onClose()
      if (s.agent_token) openDialog((c) => <TokenDialog site={s} onClose={c} />)
      go('sites', s.id)
    } catch (e) {
      toast.err(e)
    }
  }
  return (
    <Modal title={t('New site')} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>{t('Cancel')}</button><button className="btn btn-primary" disabled={!name.trim()} onClick={save}>{t('Create')}</button></>}>
      <Field label={t('Name')}><input autoFocus value={name} placeholder={t('branch-office-1')} onChange={(e) => setName(e.target.value)} /></Field>
      <Field label={t('Type')}>
        <div className="seg seg-text">
          <button type="button" className={kind === 'agent' ? 'on' : ''} onClick={() => setKind('agent')}>{t('Edge agent (closed network)')}</button>
          <button type="button" className={kind === 'direct' ? 'on' : ''} onClick={() => setKind('direct')}>{t('Direct')}</button>
        </div>
      </Field>
      <Field label={t('Description')}><input value={desc} onChange={(e) => setDesc(e.target.value)} /></Field>
    </Modal>
  )
}
