// UI translations. English is the source language: every visible string is
// written in English and wrapped in t(); catalogs map English -> language.
// Placeholders are positional: t('Delete {0} containers', n).
import { es } from './es'


const catalogs: Record<string, Record<string, string>> = { es }

export const LANGUAGES = [
  { id: 'en', label: 'English' },
  { id: 'es', label: 'Español' },
  
]

function detect(): string {
  try {
    const saved = localStorage.getItem('duckjump:lang')
    if (saved) return JSON.parse(saved)
  } catch {}
  const nav = (navigator.languages?.[0] || navigator.language || 'en').slice(0, 2).toLowerCase()
  return catalogs[nav] ? nav : 'en'
}

let lang = detect()
document.documentElement.lang = lang

export const getLang = () => lang

/** Switches language; the page reloads so module-level labels refresh too. */
export function setLang(l: string) {
  try {
    localStorage.setItem('duckjump:lang', JSON.stringify(l))
  } catch {}
  location.reload()
}

type Arg = string | number | undefined | null

function format(s: string, args: Arg[]) {
  return args.length ? s.replace(/\{(\d+)\}/g, (_, i) => (args[+i] === undefined || args[+i] === null ? '' : String(args[+i]))) : s
}

export function t(msg: string, ...args: Arg[]): string {
  return format(catalogs[lang]?.[msg] ?? msg, args)
}

/**
 * Like t() with a disambiguating context, for words that translate
 * differently depending on gender/number (gettext msgctxt): catalogs may
 * hold 'f|All' (feminine) or 'pl|Stopped' (plural); falls back to t().
 */
export function tc(ctx: string, msg: string, ...args: Arg[]): string {
  return format(catalogs[lang]?.[ctx + '|' + msg] ?? catalogs[lang]?.[msg] ?? msg, args)
}
