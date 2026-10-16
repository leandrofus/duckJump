import { t } from '../i18n'
import type { Me } from './api'

// The logged-in user, shared by the whole UI.
let current: Me | null = null
export const getMe = () => current
export const setMe = (m: Me | null) => {
  current = m
}
export const role = () => current?.user.role
export const isAdmin = () => role() === 'admin' || role() === 'superadmin'
export const isAuditor = () => isAdmin() || role() === 'auditor'
export const isSuperadmin = () => role() === 'superadmin'

/** A session error from the gateway, in the user's language when the code is known. */
export function sessionErrorText(m: { code?: string; message: string }): string {
  switch (m.code) {
    case 'session_terminated': return t('The session was terminated ({0}).', m.message)
    case 'access_revoked': return t('The session ended: {0}.', m.message)
    case 'host_key_unverified': return t('The server key has not been approved yet; nothing was sent to it. An admin must verify and approve it.')
    case 'host_key_mismatch': return t('The server key changed: {0}', m.message)
    default: return m.message
  }
}
