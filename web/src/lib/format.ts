import { getLang, t } from '../i18n'

const rtf = new Intl.RelativeTimeFormat(getLang(), { numeric: 'auto' })

function toMs(input: number | string) {
  return typeof input === 'number' ? (input < 1e12 ? input * 1000 : input) : Date.parse(input)
}

export function ago(input: number | string | undefined | null) {
  if (!input) return '—'
  const s = (toMs(input) - Date.now()) / 1000
  const abs = Math.abs(s)
  if (abs < 45) return t('now')
  if (abs < 3600) return rtf.format(Math.round(s / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(s / 3600), 'hour')
  if (abs < 86400 * 30) return rtf.format(Math.round(s / 86400), 'day')
  if (abs < 86400 * 365) return rtf.format(Math.round(s / 86400 / 30), 'month')
  return rtf.format(Math.round(s / 86400 / 365), 'year')
}

export function dateTime(input: number | string | undefined | null) {
  if (!input) return '—'
  return new Date(toMs(input)).toLocaleString(getLang(), { dateStyle: 'medium', timeStyle: 'short' })
}

export function duration(from: string, to?: string | null) {
  const s = Math.max(0, Math.round(((to ? Date.parse(to) : Date.now()) - Date.parse(from)) / 1000))
  if (s < 60) return `${s} s`
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`
}

export function bytes(n?: number | null) {
  if (n === undefined || n === null || isNaN(n)) return '—'
  if (n < 1024) return `${Math.round(n)} B`
  const u = ['KB', 'MB', 'GB', 'TB']
  let i = -1
  do {
    n /= 1024
    i++
  } while (n >= 1024 && i < u.length - 1)
  return `${n.toFixed(n >= 100 ? 0 : 1)} ${u[i]}`
}

export function stateTone(state: string): 'ok' | 'warn' | 'bad' | 'idle' {
  switch (state) {
    case 'active':
    case 'online':
    case 'enabled':
      return 'ok'
    case 'expiring':
    case 'pending':
      return 'warn'
    case 'offline':
    case 'disabled':
    case 'expired':
    case 'error':
      return 'bad'
    default:
      return 'idle'
  }
}

export const stateLabel: Record<string, string> = {
  active: t('Active'),
  ended: t('Ended'),
  online: t('Online'),
  offline: t('Offline'),
  enabled: t('Enabled'),
  disabled: t('Disabled'),
  expired: t('Expired'),
  expiring: t('Expiring'),
  permanent: t('Permanent'),
}

export function hue(s: string) {
  let h = 0
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0
  return h % 360
}

export function copy(text: string): Promise<boolean> {
  if (navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text).then(() => true).catch(() => fallbackCopy(text))
  }
  return Promise.resolve(fallbackCopy(text))
}

function fallbackCopy(text: string): boolean {
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.focus()
    ta.select()
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  } catch {
    return false
  }
}
