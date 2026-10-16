import { t } from '../i18n'
import { useEffect, useState } from 'react'
import { Settings as SettingsIcon, HardDrive, Save, AlertTriangle } from 'lucide-react'
import { api } from '../lib/api'
import type { Schemas } from '../lib/api'
import { bytes, dateTime } from '../lib/format'
import { Section, Spinner } from '../ui/common'
import { confirm, toast } from '../ui/overlays'

type RecSettings = Schemas['RecordingSettings']

const PRESETS = [0, 30, 90, 180, 365]

export function Settings() {
  const [cur, setCur] = useState<RecSettings | null>(null)
  const [days, setDays] = useState(0)
  const [preview, setPreview] = useState<RecSettings | null>(null)
  const [busy, setBusy] = useState(false)
  const load = () =>
    api.get<RecSettings>('/settings/recordings').then((s) => {
      setCur(s)
      setDays(s.retention_days)
      setPreview(s)
    }, toast.err)
  useEffect(() => void load(), [])
  // Live preview of what the chosen value would delete.
  useEffect(() => {
    if (!cur || days === cur.retention_days) return setPreview(cur)
    const id = setTimeout(() => api.get<RecSettings>(`/settings/recordings?retention_days=${days}`).then(setPreview, () => {}), 250)
    return () => clearTimeout(id)
  }, [days, cur])

  if (!cur) return <div className="center page"><Spinner /></div>
  const u = preview?.usage ?? cur.usage
  const changed = days !== cur.retention_days
  const save = async () => {
    if (u.purgeable > 0 && !(await confirm({
      title: t('Delete {0} recordings now?', u.purgeable),
      body: t('With {0} days of retention, {1} recordings ({2}) are already past the limit and will be deleted right away. This cannot be undone.', days, u.purgeable, bytes(u.purgeable_bytes)),
      danger: true, confirm: t('Save and delete'),
    }))) return
    setBusy(true)
    try {
      const r = await api.put<RecSettings>('/settings/recordings', { retention_days: days })
      setCur(r)
      setPreview(r)
      toast.ok(r.purged ? t('Retention saved; {0} recordings deleted ({1}).', r.purged, bytes(r.purged_bytes ?? 0)) : t('Retention saved'))
    } catch (e) {
      toast.err(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="page">
      <div className="page-head"><div className="page-title"><SettingsIcon size={20} /><h1>{t('Settings')}</h1></div></div>
      <div className="page-body narrow">
        <Section title={t('Session recordings')}>
          {!cur.recordings_dir_configured && (
            <div className="alert alert-warn row gap"><AlertTriangle size={14} /> {t('The gateway runs without -recordings: it cannot see the files, so it can neither play nor delete them.')}</div>
          )}
          <div className="kpis">
            <div className="kpi"><span className="kpi-label">{t('Stored recordings')}</span><span className="kpi-value">{cur.usage.recordings}</span></div>
            <div className="kpi"><span className="kpi-label">{t('Disk used')}</span><span className="kpi-value">{bytes(cur.usage.bytes)}</span></div>
            <div className="kpi"><span className="kpi-label">{t('Oldest')}</span><span className="kpi-value small">{dateTime(cur.usage.oldest_started_at)}</span></div>
          </div>
          <h3 className="subhead row gap"><HardDrive size={14} /> {t('Retention')}</h3>
          <p className="help">{t('How long recordings are kept after the session ends. Expired ones are deleted every hour; each deletion is recorded in the audit log. Sessions stay in the history after their recording is gone.')}</p>
          <div className="row gap wrap">
            <div className="seg seg-text wrap">
              {PRESETS.map((d) => (
                <button key={d} className={days === d ? 'on' : ''} onClick={() => setDays(d)}>{d === 0 ? t('Keep forever') : t('{0} days', d)}</button>
              ))}
            </div>
            <label className="row gap small">
              {t('or')} <input className="mono days-input" type="number" min={0} max={3650} value={days} onChange={(e) => setDays(Math.max(0, Math.min(3650, Number(e.target.value) || 0)))} /> {t('days')}
            </label>
          </div>
          {changed && (
            <p className={`help ${u.purgeable ? 'tone-warn' : ''}`}>
              {days === 0
                ? t('Nothing will be deleted.')
                : u.purgeable
                  ? t('Saving deletes {0} recordings ({1}) right away.', u.purgeable, bytes(u.purgeable_bytes))
                  : t('No current recording is past this limit.')}
            </p>
          )}
          <div><button className="btn btn-primary" disabled={!changed || busy} onClick={save}><Save size={14} /> {t('Save')}</button></div>
        </Section>
      </div>
    </div>
  )
}
