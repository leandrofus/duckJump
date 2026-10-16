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
