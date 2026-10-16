import { t, LANGUAGES, getLang, setLang } from './i18n'
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  MonitorSmartphone, Server, Users as UsersIcon, UsersRound, ShieldCheck, KeyRound, Network, ScrollText, History,
  Search, Plus, Languages, LogOut, Moon, Sun, Check, PanelLeftClose, PanelLeft, Star, Clock, UserCog, TerminalSquare, Settings as SettingsIcon,
} from 'lucide-react'
import { api, setUnauthorizedHandler } from './lib/api'
import type { Me, PortalConnection } from './lib/api'
import { invalidate, peek, useResource } from './lib/store'
import { usePref } from './lib/prefs'
import { go, href, useRoute } from './lib/router'
import { getMe, isAdmin, isAuditor, setMe } from './lib/session'
import { ContextMenuProvider, useMenu } from './ui/ContextMenu'
import type { MenuEntry } from './ui/ContextMenu'
import { OverlayHost, openDialog, toast } from './ui/overlays'
import { Avatar, Kbd, Spinner } from './ui/common'
import { Login } from './pages/Login'
import { Portal, protoIcon } from './pages/Portal'
import { SessionView } from './pages/SessionView'
import { Connections, ConnectionFormDialog } from './pages/Connections'
import { Users, UserFormDialog } from './pages/Users'
import { Groups, GroupFormDialog } from './pages/Groups'
import { Policies, PolicyDialog } from './pages/Policies'
import { Secrets, SecretFormDialog } from './pages/Secrets'
import { Sites, SiteFormDialog } from './pages/Sites'
import { AuditLog } from './pages/AuditLog'
import { Sessions } from './pages/Sessions'
import { Account } from './pages/Account'
import { Settings } from './pages/Settings'

export type Recent = { id: string; name: string; protocol: string }

interface NavItem {
  id: string
  label: string
  icon: typeof Server
  show?: () => boolean
}

const NAV_PORTAL: NavItem[] = [{ id: 'portal', label: t('My connections'), icon: MonitorSmartphone }]
const NAV_ADMIN: NavItem[] = [
  { id: 'connections', label: t('Connections'), icon: Server },
  { id: 'users', label: t('Users'), icon: UsersIcon },
  { id: 'groups', label: t('Groups'), icon: UsersRound },
  { id: 'policies', label: t('Access'), icon: ShieldCheck },
  { id: 'secrets', label: t('Credentials'), icon: KeyRound },
  { id: 'sites', label: t('Sites'), icon: Network },
  { id: 'settings', label: t('Settings'), icon: SettingsIcon },
]
const NAV_AUDIT: NavItem[] = [
  { id: 'sessions', label: t('Sessions'), icon: History },
  { id: 'audit', label: t('Audit log'), icon: ScrollText },
]
const allNav = () => [...NAV_PORTAL, ...(isAdmin() ? NAV_ADMIN : []), ...(isAuditor() ? NAV_AUDIT : [])]

export function openSession(c: { id: string; name: string; protocol: string }) {
  go('session', c.id)
}

function Sidebar({ section, collapsed, setCollapsed }: { section: string; collapsed: boolean; setCollapsed: (v: boolean) => void }) {
  const me = getMe()!
  const [favs, setFavs] = usePref<Recent[]>('favorites', [])
  const [recent, setRecent] = usePref<Recent[]>('recent', [])
  const menu = useMenu()
  const item = (n: NavItem) => (
    <a key={n.id} href={href(n.id)} className={`nav-item${section === n.id ? ' active' : ''}`} title={n.label}>
      <n.icon size={16} />
      {!collapsed && <span>{n.label}</span>}
    </a>
  )
  const connItem = (c: Recent, list: Recent[], set: (v: Recent[]) => void, removeLabel: string) => {
    const Icon = protoIcon(c.protocol)
    return (
      <a key={c.id} href={href('session', c.id)} className="nav-item sub" onContextMenu={menu(() => [
        { header: c.name },
        { label: t('Connect'), icon: <TerminalSquare size={14} />, onClick: () => openSession(c) },
        { label: t('Connect in a new tab'), onClick: () => window.open(href('session', c.id), '_blank') },
        'sep',
        { label: removeLabel, onClick: () => set(list.filter((x) => x.id !== c.id)) },
      ])}>
        <Icon size={13} className="muted" />
        <span className="ellipsis">{c.name}</span>
      </a>
    )
  }
  return (
    <aside className={`sidebar${collapsed ? ' collapsed' : ''}`}>
      <a className="workspace" href={href('portal')}>
        <img className="brand-logo" src="/duckjump-icon.svg" alt="" />
        {!collapsed && (
          <span className="workspace-text">
            <strong>DuckJump</strong>
            <span className="muted small ellipsis">{me.dev ? t('dev mode') : t('access bastion')}</span>
          </span>
        )}
      </a>
      <nav>{NAV_PORTAL.map(item)}</nav>
      {!collapsed && favs.length > 0 && (
        <div className="nav-section">
          <div className="nav-title"><Star size={12} /> {t('Favorites')}</div>
          {favs.map((c) => connItem(c, favs, setFavs, t('Remove from favorites')))}
        </div>
      )}
      {!collapsed && recent.length > 0 && (
        <div className="nav-section">
          <div className="nav-title"><Clock size={12} /> {t('Recent')}</div>
          {recent.slice(0, 6).map((c) => connItem(c, recent, setRecent, t('Remove from recent')))}
        </div>
      )}
      {isAdmin() && (
        <nav className="nav-section">
          {!collapsed && <div className="nav-title"><UserCog size={12} /> {t('Administration')}</div>}
          {NAV_ADMIN.map(item)}
        </nav>
      )}
      {isAuditor() && (
        <nav className="nav-section">
          {!collapsed && <div className="nav-title"><ScrollText size={12} /> {t('Audit')}</div>}
          {NAV_AUDIT.map(item)}
        </nav>
      )}
      <nav className="nav-bottom">
        <button className="nav-item" onClick={() => setCollapsed(!collapsed)} title={t('Collapse')}>
          {collapsed ? <PanelLeft size={16} /> : <PanelLeftClose size={16} />}
          {!collapsed && <span>{t('Collapse')}</span>}
        </button>
      </nav>
    </aside>
  )
}

// ---------- command palette ----------
interface Cmd {
  id: string
  label: string
  sub?: string
  icon: React.ReactNode
  group: string
  run: () => void
}

function Palette({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState('')
  const [i, setI] = useState(0)
  const list = useRef<HTMLDivElement>(null)
  const conns = peek<PortalConnection[]>('/portal/connections') || []
  const all: Cmd[] = useMemo(
    () => [
      ...conns.map((c) => {
        const Icon = protoIcon(c.protocol)
        return { id: c.id, label: c.name, sub: [c.protocol.toUpperCase(), c.folder_path, c.environment].filter(Boolean).join(' · '), icon: <Icon size={15} />, group: t('Connect'), run: () => openSession(c) }
      }),
      ...allNav().map((n) => ({ id: 'nav-' + n.id, label: t('Go to {0}', n.label), icon: <n.icon size={15} />, group: t('Navigation'), run: () => go(n.id) })),
      ...(isAdmin() ? createItems().filter((x): x is { label: string; icon: React.ReactElement; onClick: () => void } => !!x && typeof x === 'object' && 'onClick' in x).map((x) => ({ id: 'new-' + x.label, label: x.label, icon: x.icon, group: t('Create'), run: x.onClick })) : []),
      { id: 'account', label: t('My account'), icon: <UserCog size={15} />, group: t('Navigation'), run: () => go('account') },
    ],
    [conns],
  )
  const results = useMemo(() => {
    const words = q.toLowerCase().trim().split(/\s+/).filter(Boolean)
    if (!words.length) return all.slice(0, 50)
    return all.filter((c) => words.every((w) => `${c.label} ${c.sub ?? ''} ${c.group}`.toLowerCase().includes(w))).slice(0, 60)
  }, [q, all])
  useEffect(() => setI(0), [q])
  useEffect(() => {
    list.current?.querySelector('.active')?.scrollIntoView({ block: 'nearest' })
  }, [i])
  const run = (c: Cmd) => (onClose(), c.run())
  let lastGroup = ''
  return (
    <div className="modal-backdrop palette-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="palette">
        <div className="palette-input">
          <Search size={16} />
          <input
            autoFocus
            placeholder={t('Search a connection to open, or an action…')}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') (e.preventDefault(), setI(Math.min(i + 1, results.length - 1)))
              else if (e.key === 'ArrowUp') (e.preventDefault(), setI(Math.max(i - 1, 0)))
              else if (e.key === 'Enter' && results[i]) run(results[i])
              else if (e.key === 'Escape') onClose()
            }}
          />
          <Kbd>esc</Kbd>
        </div>
        <div className="palette-list" ref={list}>
          {results.length === 0 && <div className="muted center">{t('No results')}</div>}
          {results.map((c, idx) => {
            const header = c.group !== lastGroup ? (lastGroup = c.group) : null
            return (
              <div key={c.id}>
                {header && <div className="palette-group">{header}</div>}
                <button className={`palette-item${idx === i ? ' active' : ''}`} onMouseEnter={() => setI(idx)} onClick={() => run(c)}>
                  {c.icon}
                  <span className="grow ellipsis">{c.label}</span>
                  {c.sub && <span className="muted small ellipsis">{c.sub}</span>}
                </button>
              </div>
            )
          })}
        </div>
        <div className="palette-foot muted small">
          <Kbd>↑↓</Kbd> {t('navigate')} · <Kbd>↵</Kbd> {t('open')}
        </div>
      </div>
    </div>
  )
}

function createItems(): MenuEntry[] {
  return [
    { label: t('Connection'), icon: <Server size={14} />, onClick: () => openDialog((c) => <ConnectionFormDialog onClose={c} />) },
    { label: t('Credential'), icon: <KeyRound size={14} />, onClick: () => openDialog((c) => <SecretFormDialog onClose={c} />) },
    { label: t('Access grant'), icon: <ShieldCheck size={14} />, onClick: () => openDialog((c) => <PolicyDialog onClose={c} />) },
    'sep',
    { label: t('User'), icon: <UsersIcon size={14} />, onClick: () => openDialog((c) => <UserFormDialog onClose={c} />) },
    { label: t('Group'), icon: <UsersRound size={14} />, onClick: () => openDialog((c) => <GroupFormDialog onClose={c} />) },
    { label: t('Site'), icon: <Network size={14} />, onClick: () => openDialog((c) => <SiteFormDialog onClose={c} />) },
  ]
}

function UserMenu() {
  const me = getMe()!
  const menu = useMenu()
  const u = me.user
  const items = (): MenuEntry[] => [
    { header: u.display_name || u.username },
    { label: t('Role: {0}', u.role), disabled: true },
    'sep',
    !me.dev && { label: t('My account'), icon: <UserCog size={14} />, onClick: () => go('account') },
    { label: t('Language'), icon: <Languages size={14} />, submenu: LANGUAGES.map((l) => ({ label: l.label, checked: getLang() === l.id, onClick: () => setLang(l.id) })) },
    !me.dev && { label: t('Sign out'), icon: <LogOut size={14} />, onClick: () => api.post('/auth/logout').then(() => location.reload()) },
  ]
  return (
    <button
      className="user-chip"
      onClick={(e) => {
        const r = e.currentTarget.getBoundingClientRect()
        menu(items)({ preventDefault() {}, stopPropagation() {}, clientX: r.right - 220, clientY: r.bottom + 4 } as any)
      }}
      onContextMenu={menu(items)}
    >
      <Avatar name={u.username} size={26} />
      <span className="user-chip-text">
        <strong>{u.display_name || u.username}</strong>
        <span className="muted small">{u.role}</span>
      </span>
    </button>
  )
}

function Topbar({ onSearch }: { onSearch: () => void }) {
  const [theme, setTheme] = usePref<'auto' | 'light' | 'dark'>('theme', 'auto')
  const menu = useMenu()
  useEffect(() => {
    if (theme === 'auto') document.documentElement.removeAttribute('data-theme')
    else document.documentElement.setAttribute('data-theme', theme)
  }, [theme])
  return (
    <header className="topbar">
      <button className="searchbar" onClick={onSearch}>
        <Search size={15} />
        <span>{t('Open a connection…')}</span>
        <Kbd>Ctrl K</Kbd>
      </button>
      <span className="grow" />
      {getMe()?.dev && <span className="tag tag-warn" title={t('The gateway runs with -dev: there is no authentication.')}>{t('Dev mode')}</span>}
      {isAdmin() && (
        <button
          className="btn btn-primary btn-sm"
          onClick={(e) => {
            const r = e.currentTarget.getBoundingClientRect()
            menu(createItems)({ preventDefault() {}, stopPropagation() {}, clientX: r.left, clientY: r.bottom + 4 } as any)
          }}
        >
          <Plus size={15} /> {t('Create')}
        </button>
      )}
      <button className="icon-btn" title={t('Theme')} onClick={() => setTheme(theme === 'dark' ? 'light' : theme === 'light' ? 'auto' : 'dark')}>
        {theme === 'dark' ? <Moon size={16} /> : theme === 'light' ? <Sun size={16} /> : <Check size={16} />}
      </button>
      <UserMenu />
    </header>
  )
}

function Shell() {
  const route = useRoute()
  const [collapsed, setCollapsed] = usePref('sidebar.collapsed', false)
  const [palette, setPalette] = useState(false)
  useResource<PortalConnection[]>('/portal/connections') // warms the palette

  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPalette((p) => !p)
      } else if (e.key === '/' && !(e.target as HTMLElement).closest('input,textarea,select,.xterm')) {
        e.preventDefault()
        setPalette(true)
      }
    }
    window.addEventListener('keydown', on)
    return () => window.removeEventListener('keydown', on)
  }, [])

  const { section, id, tab } = route
  const forbidden = <div className="page"><div className="alert alert-bad">{t('You do not have access to this section.')}</div></div>
  const admin = (el: React.ReactNode) => (isAdmin() ? el : forbidden)
  const auditor = (el: React.ReactNode) => (isAuditor() ? el : forbidden)
  let page: React.ReactNode
  switch (section) {
    case 'session': page = <SessionView id={id!} />; break
    case 'connections': page = admin(<Connections id={id} />); break
    case 'users': page = admin(<Users id={id} tab={tab} />); break
    case 'groups': page = admin(<Groups id={id} />); break
    case 'policies': page = admin(<Policies />); break
    case 'secrets': page = admin(<Secrets />); break
    case 'sites': page = admin(<Sites id={id} />); break
    case 'audit': page = auditor(<AuditLog />); break
    case 'sessions': page = auditor(<Sessions id={id} />); break
    case 'settings': page = admin(<Settings />); break
    case 'account': page = <Account />; break
    default: page = <Portal />
  }
  return (
    <div className="app">
      <Sidebar section={section} collapsed={collapsed} setCollapsed={setCollapsed} />
      <div className="main">
        <Topbar onSearch={() => setPalette(true)} />
        <div className={`content${section === 'session' ? ' content-flush' : ''}`}>{page}</div>
      </div>
      {palette && <Palette onClose={() => setPalette(false)} />}
    </div>
  )
}

export function App() {
  const [auth, setAuth] = useState<'checking' | 'in' | 'out' | 'mfa'>('checking')
  const check = () =>
    api
      .get<Me>('/auth/me')
      .then((m) => {
        setMe(m)
        setAuth(m.mfa_pending ? 'mfa' : 'in')
      })
      .catch(() => (setMe(null), setAuth('out')))
  useEffect(() => {
    setUnauthorizedHandler(() => (setMe(null), invalidate(), setAuth('out')))
    check()
  }, [])
  return (
    <ContextMenuProvider>
      {auth === 'checking' && <div className="center page"><Spinner /></div>}
      {(auth === 'out' || auth === 'mfa') && (
        <Login mfa={auth === 'mfa'} onDone={() => check().then(() => toast.ok(t('Hello, {0}', getMe()?.user.display_name || getMe()?.user.username)))} />
      )}
      {auth === 'in' && <Shell />}
      <OverlayHost />
    </ContextMenuProvider>
  )
}
