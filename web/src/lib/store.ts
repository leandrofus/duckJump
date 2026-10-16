import { useEffect, useState } from 'react'
import { api } from './api'

// A tiny resource cache: components subscribe to a key (an API path) and
// get stale-while-revalidate data. invalidate() refetches every subscriber
// whose key matches a prefix — the Docker event stream drives it.

interface Entry {
  data: any
  error: Error | null
  loading: boolean
  at: number
  promise?: Promise<void>
  listeners: Set<() => void>
}

const cache = new Map<string, Entry>()

function entry(key: string): Entry {
  let e = cache.get(key)
  if (!e) {
    e = { data: undefined, error: null, loading: false, at: 0, listeners: new Set() }
    cache.set(key, e)
  }
  return e
}

function emit(e: Entry) {
  e.listeners.forEach((l) => l())
}

export function fetchKey(key: string): Promise<void> {
  const e = entry(key)
  if (e.promise) return e.promise
  e.loading = true
  emit(e)
  e.promise = api
    .get(key)
    .then((d) => {
      e.data = d
      e.error = null
    })
    .catch((err) => {
      e.error = err
    })
    .finally(() => {
      e.loading = false
      e.at = Date.now()
      e.promise = undefined
      emit(e)
    })
  return e.promise
}

/** Refetch all cached resources whose key contains any of the fragments. */
export function invalidate(...fragments: string[]) {
  for (const [key, e] of cache) {
    if (e.listeners.size === 0) continue
    if (fragments.length === 0 || fragments.some((f) => key.includes(f))) fetchKey(key)
  }
}

export function setData(key: string, fn: (d: any) => any) {
  const e = entry(key)
  e.data = fn(e.data)
  emit(e)
}

export function useResource<T = any>(key: string | null, opts: { poll?: number } = {}) {
  const [, setTick] = useState(0)
  useEffect(() => {
    if (!key) return
    const e = entry(key)
    const l = () => setTick((n) => n + 1)
    e.listeners.add(l)
    if (e.data === undefined || Date.now() - e.at > 2000) fetchKey(key)
    const t = opts.poll ? setInterval(() => !document.hidden && fetchKey(key), opts.poll) : undefined
    return () => {
      e.listeners.delete(l)
      clearInterval(t)
    }
  }, [key, opts.poll])
  const e = key ? entry(key) : null
  return {
    data: e?.data as T | undefined,
    error: e?.error ?? null,
    loading: !!e?.loading,
    reload: () => (key ? fetchKey(key) : Promise.resolve()),
  }
}

/** Cached data for a key without subscribing (used by menu builders). */
export function peek<T = any>(key: string): T | undefined {
  return cache.get(key)?.data as T | undefined
}
