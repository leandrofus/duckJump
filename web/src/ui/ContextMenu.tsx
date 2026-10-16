import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { ReactNode, MouseEvent as RMouseEvent } from 'react'
import { ChevronRight } from 'lucide-react'

export type MenuItem =
  | {
      label: string
      icon?: ReactNode
      onClick?: () => void
      danger?: boolean
      disabled?: boolean
      hint?: string // right-aligned text (shortcut, count…)
      checked?: boolean
      submenu?: MenuEntry[]
    }
  | { header: string }
  | 'sep'
export type MenuEntry = MenuItem | false | null | undefined | '' | 0

interface OpenMenu {
  x: number
  y: number
  items: MenuItem[]
  title?: string
}

const Ctx = createContext<(m: OpenMenu | null) => void>(() => {})

const clean = (items: MenuEntry[]): MenuItem[] => {
  const out = items.filter(Boolean) as MenuItem[]
  // drop leading/trailing/double separators left by conditional entries
  return out.filter((it, i) => it !== 'sep' || (i > 0 && i < out.length - 1 && out[i - 1] !== 'sep'))
}

export function ContextMenuProvider({ children }: { children: ReactNode }) {
  const [menu, setMenu] = useState<OpenMenu | null>(null)
  useEffect(() => {
    if (!menu) return
    const close = () => setMenu(null)
    window.addEventListener('blur', close)
    window.addEventListener('resize', close)
    return () => {
      window.removeEventListener('blur', close)
      window.removeEventListener('resize', close)
    }
  }, [menu])
  return (
    <Ctx.Provider value={setMenu}>
      {children}
      {menu && (
        <div
          className="ctx-backdrop"
          onMouseDown={(e) => e.target === e.currentTarget && setMenu(null)}
          onContextMenu={(e) => {
            e.preventDefault()
            setMenu(null)
          }}
        >
          <MenuPanel x={menu.x} y={menu.y} items={menu.items} title={menu.title} onClose={() => setMenu(null)} root />
        </div>
      )}
    </Ctx.Provider>
  )
}

function MenuPanel({
  x,
  y,
  items,
  title,
  onClose,
  root,
  alignRightOf,
}: {
  x: number
  y: number
  items: MenuItem[]
  title?: string
  onClose: () => void
  root?: boolean
  alignRightOf?: number
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState({ x, y })
  const [active, setActive] = useState(-1)
  const [sub, setSub] = useState<{ i: number; x: number; y: number; left: number } | null>(null)
  const selectable = items.map((it, i) => (typeof it === 'object' && 'label' in it && !it.disabled ? i : -1)).filter((i) => i >= 0)

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    let nx = x
    let ny = y
    if (nx + r.width > innerWidth - 8) nx = alignRightOf !== undefined ? alignRightOf - r.width : innerWidth - r.width - 8
    if (ny + r.height > innerHeight - 8) ny = Math.max(8, innerHeight - r.height - 8)
    setPos({ x: Math.max(8, nx), y: ny })
    if (root) el.focus()
  }, [x, y])

  const run = (it: MenuItem, i: number, el?: HTMLElement) => {
    if (typeof it !== 'object' || !('label' in it) || it.disabled) return
    if (it.submenu) {
      const r = (el ?? ref.current?.querySelectorAll<HTMLElement>('[data-idx]')[selectable.indexOf(i)])?.getBoundingClientRect()
      if (r) setSub({ i, x: r.right - 4, y: r.top - 5, left: r.left + 4 })
      return
    }
    onClose()
    it.onClick?.()
  }

  const onKey = (e: React.KeyboardEvent) => {
    if (sub && e.key !== 'Escape' && e.key !== 'ArrowLeft') return
    const at = selectable.indexOf(active)
    if (e.key === 'ArrowDown') setActive(selectable[(at + 1) % selectable.length])
    else if (e.key === 'ArrowUp') setActive(selectable[(at - 1 + selectable.length) % selectable.length])
    else if (e.key === 'Enter' || e.key === 'ArrowRight') {
      if (active >= 0) run(items[active], active, ref.current?.querySelector<HTMLElement>(`[data-idx="${active}"]`) ?? undefined)
    } else if (e.key === 'Escape' || e.key === 'ArrowLeft') {
      if (sub) setSub(null)
      else onClose()
    } else return
    e.preventDefault()
    e.stopPropagation()
  }

  return (
    <>
      <div
        ref={ref}
        className="ctx-menu"
        style={{ left: pos.x, top: pos.y }}
        tabIndex={-1}
        onKeyDown={onKey}
        onContextMenu={(e) => e.preventDefault()}
        role="menu"
      >
        {title && <div className="ctx-title">{title}</div>}
        {items.map((it, i) => {
          if (it === 'sep') return <div key={i} className="ctx-sep" />
          if ('header' in it) return <div key={i} className="ctx-header">{it.header}</div>
          return (
            <button
              key={i}
              data-idx={i}
              role="menuitem"
              className={`ctx-item${it.danger ? ' danger' : ''}${active === i ? ' active' : ''}`}
              disabled={it.disabled}
              onMouseEnter={(e) => {
                setActive(i)
                if (it.submenu) run(it, i, e.currentTarget)
                else setSub(null)
              }}
              onClick={(e) => run(it, i, e.currentTarget)}
            >
              <span className="ctx-icon">{it.checked !== undefined ? (it.checked ? '✓' : '') : it.icon}</span>
              <span className="ctx-label">{it.label}</span>
              {it.hint && <span className="ctx-hint">{it.hint}</span>}
              {it.submenu && <ChevronRight size={14} className="ctx-chevron" />}
            </button>
          )
        })}
      </div>
      {sub && typeof items[sub.i] === 'object' && 'submenu' in (items[sub.i] as object) && (
        <MenuPanel
          x={sub.x}
          y={sub.y}
          alignRightOf={sub.left}
          items={clean((items[sub.i] as { submenu: MenuEntry[] }).submenu)}
          onClose={onClose}
        />
      )}
    </>
  )
}

/** Returns an onContextMenu handler that opens a menu built lazily. */
export function useMenu() {
  const set = useContext(Ctx)
  return useCallback(
    (build: () => MenuEntry[], title?: string) => (e: RMouseEvent | MouseEvent) => {
      e.preventDefault()
      e.stopPropagation()
      const items = clean(build())
      if (items.length) set({ x: e.clientX, y: e.clientY, items, title })
    },
    [set],
  )
}

/** Opens a menu anchored below an element (for "⋯" buttons). */
export function useMenuAt() {
  const set = useContext(Ctx)
  return useCallback(
    (el: HTMLElement, items: MenuEntry[], title?: string) => {
      const r = el.getBoundingClientRect()
      set({ x: r.left, y: r.bottom + 4, items: clean(items), title })
    },
    [set],
  )
}
