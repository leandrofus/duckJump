import { getLang } from '../i18n'
import type { components } from './api-types'

// Thin client for duckjump-gw's /api/v1. Types come from the OpenAPI contract
// (bun run gen-api, generated from the gateway's inline comments).

export type Schemas = components['schemas']
export type User = Schemas['User']
export type Role = Schemas['Role']
export type Group = Schemas['Group']
export type Folder = Schemas['Folder']
export type Site = Schemas['Site']
export type Agent = Schemas['Agent']
export type Secret = Schemas['Secret']
export type Connection = Schemas['Connection']
export type Policy = Schemas['Policy']
export type AuditEvent = Schemas['AuditEvent']
export type Session = Schemas['Session']
export type PortalConnection = Schemas['PortalConnection']
export type AccessEntry = Schemas['AccessEntry']
export type Me = Schemas['Me']
export type TrayFile = Schemas['TrayFile']
export type HostListing = Schemas['HostListing']
export type AccessRequest = Schemas['AccessRequest']
export type AccessRequestTargets = Schemas['AccessRequestTargets']
export type CreateAccessRequest = Schemas['CreateAccessRequest']

export class ApiError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

let onUnauthorized: () => void = () => {}
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

const noRedirect = ['/auth/login', '/auth/totp', '/auth/me']

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch('/api/v1' + path, {
    method,
    // X-DuckJump-Request: required on every state-changing request (CSRF).
    headers: { 'X-DuckJump-Request': '1', 'Accept-Language': getLang(), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  })
  if (res.status === 401 && !noRedirect.includes(path)) onUnauthorized()
  const text = await res.text()
  let data: any = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = text
  }
  if (!res.ok) throw new ApiError(res.status, data?.error || 'error', data?.message || data?.error || res.statusText)
  return data as T
}

export const api = {
  get: <T = any>(p: string) => request<T>('GET', p),
  post: <T = any>(p: string, body?: unknown) => request<T>('POST', p, body),
  put: <T = any>(p: string, body?: unknown) => request<T>('PUT', p, body),
  patch: <T = any>(p: string, body: unknown) => request<T>('PATCH', p, body),
  del: <T = any>(p: string, body?: unknown) => request<T>('DELETE', p, body),
}

export const enc = encodeURIComponent

/** Uploads a file from this computer into my file tray. */
export async function uploadToTray(file: File): Promise<TrayFile> {
  const res = await fetch(`/api/v1/files?name=${enc(file.name)}`, {
    method: 'POST',
    headers: { 'X-DuckJump-Request': '1', 'Content-Type': 'application/octet-stream' },
    body: file,
    credentials: 'same-origin',
  })
  const data = await res.json().catch(() => null)
  if (!res.ok) throw new ApiError(res.status, data?.error || 'error', data?.message || res.statusText)
  return data as TrayFile
}

export function wsURL(path: string) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${location.host}/api/v1${path}`
}
