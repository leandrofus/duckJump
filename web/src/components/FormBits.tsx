import { t } from '../i18n'
import type { ReactNode } from 'react'
import { folderTree } from '../lib/lookup'
import type { Folder } from '../lib/api'

export function Field({ label, children, help, span }: { label: ReactNode; children: ReactNode; help?: ReactNode; span?: boolean }) {
  return (
    <label className={`field${span ? ' span-2' : ''}`}>
      <span>{label}</span>
      {children}
      {help && <small className="help">{help}</small>}
    </label>
  )
}

export function FolderSelect({ folders, value, onChange, exclude, rootLabel }: { folders: Folder[]; value: string; onChange: (v: string) => void; exclude?: Set<string>; rootLabel?: string }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{rootLabel ?? t('(no folder)')}</option>
      {folderTree(folders)
        .filter(({ folder }) => !exclude?.has(folder.id))
        .map(({ folder, depth }) => (
          <option key={folder.id} value={folder.id}>
            {'  '.repeat(depth * 2)}{folder.name}
          </option>
        ))}
    </select>
  )
}

/** Comma/space separated tags <-> string[]. */
export function TagsInput({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  return (
    <input
      className="mono"
      placeholder="linux, nginx, prod"
      defaultValue={value.join(', ')}
      onChange={(e) => onChange(e.target.value.split(/[\s,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean))}
    />
  )
}
