import { useEffect, useState } from 'react'

// Hash routes: #/<section>[/<id>[/<tab>]]
export interface Route {
  section: string
  id?: string
  tab?: string
  query: URLSearchParams
}

export function parse(hash = location.hash): Route {
  const [path, qs] = hash.replace(/^#\/?/, '').split('?')
  const parts = path.split('/').filter(Boolean).map(decodeURIComponent)
  return { section: parts[0] || 'portal', id: parts[1], tab: parts[2], query: new URLSearchParams(qs || '') }
}

export function href(section: string, id?: string, tab?: string) {
  return '#/' + [section, id, tab].filter((p) => p !== undefined && p !== '').map((p) => encodeURIComponent(p!)).join('/')
}

export function go(section: string, id?: string, tab?: string) {
  location.hash = href(section, id, tab)
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parse())
  useEffect(() => {
    const on = () => setRoute(parse())
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return route
}
