import { t } from '../i18n'
import { useMemo, useState } from 'react'
import { MonitorSmartphone, Search, X, Star, TerminalSquare, Monitor, MonitorPlay, LayoutGrid, LayoutList, Copy } from 'lucide-react'
import type { PortalConnection } from '../lib/api'
import { useResource } from '../lib/store'
import { usePref } from '../lib/prefs'
import { href } from '../lib/router'
import { copy } from '../lib/format'
import { useMenu } from '../ui/ContextMenu'
import type { MenuEntry } from '../ui/ContextMenu'
import { DataTable, Empty, Spinner, Tag } from '../ui/common'
import { openSession } from '../App'
import type { Recent } from '../App'

export function protoIcon(p: string) {
  return p === 'rdp' ? Monitor : p === 'vnc' ? MonitorPlay : TerminalSquare
}

export function ProtoTag({ p }: { p: string }) {
  const Icon = protoIcon(p)
  return <Tag tone={p}><Icon size={11} /> {p.toUpperCase()}</Tag>
}

export function Portal() {
  const { data, loading, error } = useResource<PortalConnection[]>('/portal/connections')
  const [q, setQ] = useState('')
  const [layout, setLayout] = usePref<'cards' | 'table'>('portal.layout', 'cards')
  const [favs, setFavs] = usePref<Recent[]>('favorites', [])
  const menu = useMenu()
  const all = data || []
  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return all.filter((c) => words.every((w) => `${c.name} ${c.protocol} ${c.folder_path} ${c.environment} ${c.tags.join(' ')} ${c.description}`.toLowerCase().includes(w)))
  }, [all, q])
  const isFav = (c: PortalConnection) => favs.some((f) => f.id === c.id)
  const toggleFav = (c: PortalConnection) =>
    setFavs(isFav(c) ? favs.filter((f) => f.id !== c.id) : [...favs, { id: c.id, name: c.name, protocol: c.protocol }])
  const actions = (c: PortalConnection): MenuEntry[] => [
    { header: c.name },
    { label: t('Connect'), icon: <TerminalSquare size={14} />, onClick: () => openSession(c) },
    { label: t('Connect in a new tab'), onClick: () => window.open(href('session', c.id), '_blank') },
    'sep',
    { label: isFav(c) ? t('Remove from favorites') : t('Add to favorites'), icon: <Star size={14} />, onClick: () => toggleFav(c) },
    { label: t('Copy link'), icon: <Copy size={14} />, onClick: () => copy(location.origin + '/' + href('session', c.id)) },
  ]
  const groups = useMemo(() => {
    const m = new Map<string, PortalConnection[]>()
    for (const c of rows) {
      const g = c.folder_path || ''
      if (!m.has(g)) m.set(g, [])
      m.get(g)!.push(c)
    }
    return [...m.entries()].sort(([a], [b]) => (a === '' ? 1 : b === '' ? -1 : a.localeCompare(b)))
  }, [rows])

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <MonitorSmartphone size={20} />
          <h1>{t('My connections')}</h1>
          <span className="count">{all.length}</span>
          {loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="search">
            <Search size={14} />
            <input autoFocus placeholder={t('Search by name, folder, tag…')} value={q} onChange={(e) => setQ(e.target.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>
          <div className="seg">
            <button className={layout === 'cards' ? 'on' : ''} onClick={() => setLayout('cards')} title={t('Cards')}><LayoutGrid size={15} /></button>
            <button className={layout === 'table' ? 'on' : ''} onClick={() => setLayout('table')} title={t('Table')}><LayoutList size={15} /></button>
          </div>
        </div>
      </div>
      <div className="page-body">
        {error && <div className="alert alert-bad">{error.message}</div>}
        {data && all.length === 0 && (
          <Empty icon={<MonitorSmartphone size={28} />} title={t('No connections yet')}>
            {t('You have no access grants. Ask an administrator for access to the hosts you need.')}
          </Empty>
        )}
        {all.length > 0 && rows.length === 0 && <div className="muted">{t('No connection matches the search.')}</div>}
        {layout === 'cards'
          ? groups.map(([g, cs]) => (
              <section key={g || '_'} className="conn-group">
                <h2 className="subhead">{g || t('No folder')}</h2>
                <div className="conn-grid">
                  {cs.map((c) => {
                    const Icon = protoIcon(c.protocol)
                    return (
                      <div key={c.id} className="conn-card" role="button" tabIndex={0}
                        onClick={(e) => !(e.target as HTMLElement).closest('button') && openSession(c)}
                        onKeyDown={(e) => e.key === 'Enter' && openSession(c)}
                        onContextMenu={menu(() => actions(c))}>
                        <div className={`conn-icon proto-${c.protocol}`}><Icon size={20} /></div>
                        <div className="conn-text">
                          <strong className="ellipsis">{c.name}</strong>
                          <span className="muted small ellipsis">{[c.protocol.toUpperCase(), c.environment].filter(Boolean).join(' · ')}</span>
                          {c.description && <span className="muted small ellipsis">{c.description}</span>}
                        </div>
                        <button className={`icon-btn fav${isFav(c) ? ' on' : ''}`} title={t('Favorite')} onClick={() => toggleFav(c)}>
                          <Star size={15} />
                        </button>
                      </div>
                    )
                  })}
                </div>
              </section>
            ))
          : rows.length > 0 && (
              <DataTable
                rows={rows}
                rowKey={(c) => c.id}
                onOpen={openSession}
                rowMenu={actions}
                groupBy={(c) => c.folder_path}
                groupHeader={(g) => <strong>{g || t('No folder')}</strong>}
                defaultSort={{ key: 'name', dir: 1 }}
                columns={[
                  { key: 'name', label: t('Name'), sort: (c) => c.name, render: (c) => <strong>{c.name}</strong> },
                  { key: 'proto', label: t('Protocol'), sort: (c) => c.protocol, render: (c) => <ProtoTag p={c.protocol} /> },
                  { key: 'env', label: t('Environment'), sort: (c) => c.environment, render: (c) => c.environment || <span className="muted">—</span> },
                  { key: 'tags', label: t('Tags'), render: (c) => <span className="tags">{c.tags.map((x) => <Tag key={x}>{x}</Tag>)}</span> },
                  { key: 'go', label: '', width: 110, render: (c) => <button className="btn btn-sm" onClick={() => openSession(c)}><TerminalSquare size={13} /> {t('Connect')}</button> },
                ]}
              />
            )}
      </div>
    </div>
  )
}
