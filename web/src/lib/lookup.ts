import type { Connection, Folder, Group, Secret, Site, User } from './api'
import { useResource } from './store'

// Shared admin collections, cached by the store and keyed by id.

function byId<T extends { id: string }>(rows: T[] | undefined) {
  const m = new Map<string, T>()
  rows?.forEach((r) => m.set(r.id, r))
  return m
}

export function useUsers() {
  const r = useResource<User[]>('/users')
  return { ...r, rows: r.data || [], map: byId(r.data) }
}
export function useGroups() {
  const r = useResource<Group[]>('/groups')
  return { ...r, rows: r.data || [], map: byId(r.data) }
}
export function useFolders() {
  const r = useResource<Folder[]>('/folders')
  const map = byId(r.data)
  return { ...r, rows: r.data || [], map, path: (id?: string | null) => folderPath(map, id) }
}
export function useConnections() {
  const r = useResource<Connection[]>('/connections')
  return { ...r, rows: r.data || [], map: byId(r.data) }
}
export function useSecrets() {
  const r = useResource<Secret[]>('/secrets')
  return { ...r, rows: r.data || [], map: byId(r.data) }
}
export function useSites() {
  const r = useResource<Site[]>('/sites')
  return { ...r, rows: r.data || [], map: byId(r.data) }
}

export function folderPath(map: Map<string, Folder>, id?: string | null) {
  const parts: string[] = []
  for (let depth = 0; id && depth < 64; depth++) {
    const f = map.get(id)
    if (!f) break
    parts.unshift(f.name)
    id = f.parent_id
  }
  return parts.join(' / ')
}

/** Ids of a folder and everything below it. */
export function subtree(rows: Folder[], id: string) {
  const out = new Set([id])
  let grew = true
  while (grew) {
    grew = false
    for (const f of rows) {
      if (f.parent_id && out.has(f.parent_id) && !out.has(f.id)) {
        out.add(f.id)
        grew = true
      }
    }
  }
  return out
}

/** Folders sorted as a tree, each with its depth (for indented selects). */
export function folderTree(rows: Folder[]) {
  const kids = new Map<string, Folder[]>()
  for (const f of rows) {
    const k = f.parent_id ?? ''
    if (!kids.has(k)) kids.set(k, [])
    kids.get(k)!.push(f)
  }
  const out: { folder: Folder; depth: number }[] = []
  const walk = (parent: string, depth: number) => {
    for (const f of (kids.get(parent) || []).sort((a, b) => a.name.localeCompare(b.name))) {
      out.push({ folder: f, depth })
      walk(f.id, depth + 1)
    }
  }
  walk('', 0)
  return out
}
