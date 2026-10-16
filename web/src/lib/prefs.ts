import { useEffect, useState } from 'react'

// Per-browser preferences (favorites, view modes, saved views…) in
// localStorage, with a same-tab change event so every hook stays in sync.

const KEY = (n: string) => 'duckjump:' + n

export function getPref<T>(name: string, initial: T): T {
  try {
    const raw = localStorage.getItem(KEY(name))
    return raw ? (JSON.parse(raw) as T) : initial
  } catch {
    return initial
  }
}

export function setPref<T>(name: string, v: T | ((prev: T) => T), initial?: T) {
  const next = typeof v === 'function' ? (v as (p: T) => T)(getPref(name, initial as T)) : v
  try {
    localStorage.setItem(KEY(name), JSON.stringify(next))
  } catch {}
  window.dispatchEvent(new CustomEvent('duckjump:pref', { detail: name }))
}

export function usePref<T>(name: string, initial: T): [T, (v: T | ((p: T) => T)) => void] {
  const [v, setV] = useState<T>(() => getPref(name, initial))
  useEffect(() => {
    const on = (ev: Event) => (ev as CustomEvent).detail === name && setV(getPref(name, initial))
    window.addEventListener('duckjump:pref', on)
    return () => window.removeEventListener('duckjump:pref', on)
  }, [name])
  return [v, (nv) => setPref(name, nv, initial)]
}
