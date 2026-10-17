import { t } from '../i18n'
import { useEffect, useState } from 'react'
import { Settings as SettingsIcon, HardDrive, Save, AlertTriangle, ShieldCheck, Send, CheckCircle2, XCircle } from 'lucide-react'
import { api } from '../lib/api'
import type { Schemas } from '../lib/api'
import { bytes, dateTime, ago } from '../lib/format'
import { Section, Spinner, Tabs, Pill } from '../ui/common'
import { Field } from '../components/FormBits'
import { confirm, toast } from '../ui/overlays'

type RecSettings = Schemas['RecordingSettings']
type SIEMSettings = Schemas['SIEMSettings']
type SIEMTestResponse = Schemas['SIEMTestResponse']

const PRESETS = [0, 30, 90, 180, 365]

export function Settings() {
  const [activeTab, setActiveTab] = useState<'recordings' | 'siem'>('recordings')

  // ---------- Recordings Settings ----------
  const [cur, setCur] = useState<RecSettings | null>(null)
  const [days, setDays] = useState(0)
  const [preview, setPreview] = useState<RecSettings | null>(null)
  const [busy, setBusy] = useState(false)
  const loadRec = () =>
    api.get<RecSettings>('/settings/recordings').then((s) => {
      setCur(s)
      setDays(s.retention_days)
      setPreview(s)
    }, toast.err)
  useEffect(() => void loadRec(), [])

  useEffect(() => {
    if (!cur || days === cur.retention_days) return setPreview(cur)
    const id = setTimeout(() => api.get<RecSettings>(`/settings/recordings?retention_days=${days}`).then(setPreview, () => {}), 250)
    return () => clearTimeout(id)
  }, [days, cur])

  // ---------- SIEM Settings ----------
  const [siem, setSiem] = useState<SIEMSettings | null>(null)
  const [siemForm, setSiemForm] = useState({
    enabled: false,
    sink_type: 'syslog' as 'syslog' | 'webhook' | 'file',
    endpoint: '',
    format: 'cef' as 'json' | 'cef' | 'rfc5424',
    auth_header: '',
    tls_insecure: false,
    tls_ca_cert: '',
  })
  const [siemBusy, setSiemBusy] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<SIEMTestResponse | null>(null)

  const loadSiem = () =>
    api.get<SIEMSettings>('/settings/siem').then((s) => {
      setSiem(s)
      setSiemForm({
        enabled: s.enabled,
        sink_type: s.sink_type,
        endpoint: s.endpoint,
        format: s.format,
        auth_header: s.auth_header || '',
        tls_insecure: s.tls_insecure ?? false,
        tls_ca_cert: s.tls_ca_cert || '',
      })
    }, toast.err)

  useEffect(() => {
    if (activeTab === 'siem' && !siem) {
      void loadSiem()
    }
  }, [activeTab])

  if (!cur) return <div className="center page"><Spinner /></div>
  const u = preview?.usage ?? cur.usage
  const changed = days !== cur.retention_days

  const saveRec = async () => {
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

  const saveSiem = async () => {
    setSiemBusy(true)
    setTestResult(null)
    try {
      const updated = await api.put<SIEMSettings>('/settings/siem', siemForm)
      setSiem(updated)
      setSiemForm({
        enabled: updated.enabled,
        sink_type: updated.sink_type,
        endpoint: updated.endpoint,
        format: updated.format,
        auth_header: updated.auth_header || '',
        tls_insecure: updated.tls_insecure ?? false,
        tls_ca_cert: updated.tls_ca_cert || '',
      })
      toast.ok(t('Configuración SIEM guardada con éxito'))
    } catch (e) {
      toast.err(e)
    } finally {
      setSiemBusy(false)
    }
  }

  const runTestSiem = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await api.post<SIEMTestResponse>('/settings/siem/test', siemForm)
      setTestResult(res)
      if (res.ok) {
        toast.ok(t('Prueba exitosa: evento de prueba recibido por el SIEM'))
      } else {
        toast.err(res.message)
      }
    } catch (e) {
      toast.err(e)
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title"><SettingsIcon size={20} /><h1>{t('Settings')}</h1></div>
      </div>
      <div className="page-body narrow">
        <Tabs
          active={activeTab}
          onChange={(tab) => setActiveTab(tab as any)}
          tabs={[
            { id: 'recordings', label: <><HardDrive size={14} /> {t('Session recordings')}</> },
            { id: 'siem', label: <><ShieldCheck size={14} /> {t('SIEM Forwarding')}</> },
          ]}
        />

        {activeTab === 'recordings' && (
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
            <div><button className="btn btn-primary" disabled={!changed || busy} onClick={saveRec}><Save size={14} /> {t('Save')}</button></div>
          </Section>
        )}

        {activeTab === 'siem' && (
          <Section title={t('Reenvío de Auditoría a SIEM')}>
            {!siem ? (
              <div className="center" style={{ padding: '2rem' }}><Spinner /></div>
            ) : (
              <>
                <p className="help">
                  {t('Exporta automáticamente todos los eventos de auditoría y sesiones en tiempo real hacia tu plataforma SIEM (Splunk, Elastic, Microsoft Sentinel, IBM QRadar, Datadog) o servidor Syslog.')}
                </p>

                {/* KPIs & Live Status */}
                <div className="kpis" style={{ marginBottom: '1.5rem' }}>
                  <div className="kpi">
                    <span className="kpi-label">{t('Estado')}</span>
                    <span className="kpi-value small">
                      {siem.enabled ? (
                        siem.status?.last_error ? <Pill state="down" label={t('Error')} /> : <Pill state="up" label={t('Activo')} />
                      ) : (
                        <Pill state="unknown" label={t('Desactivado')} />
                      )}
                    </span>
                  </div>
                  <div className="kpi">
                    <span className="kpi-label">{t('Eventos exportados')}</span>
                    <span className="kpi-value">{siem.status?.total_exported || 0}</span>
                  </div>
                  <div className="kpi">
                    <span className="kpi-label">{t('Último envío')}</span>
                    <span className="kpi-value small">{siem.status?.last_exported_at ? ago(siem.status.last_exported_at) : '—'}</span>
                  </div>
                </div>

                {siem.status?.last_error && (
                  <div className="alert alert-bad row gap" style={{ marginBottom: '1.25rem' }}>
                    <AlertTriangle size={15} />
                    <div>
                      <strong>{t('Error de reenvío:')}</strong> {siem.status.last_error}
                      {siem.status.last_error_at && <span className="muted small" style={{ marginLeft: 6 }}>({ago(siem.status.last_error_at)})</span>}
                    </div>
                  </div>
                )}

                {testResult && (
                  <div className={`alert ${testResult.ok ? 'alert-ok' : 'alert-bad'} row gap`} style={{ marginBottom: '1.25rem' }}>
                    {testResult.ok ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                    <span>{testResult.message}</span>
                  </div>
                )}

                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <label className="row gap" style={{ cursor: 'pointer', fontWeight: 600 }}>
                    <input
                      type="checkbox"
                      checked={siemForm.enabled}
                      onChange={(e) => setSiemForm({ ...siemForm, enabled: e.target.checked })}
                    />
                    <span>{t('Habilitar reenvío de auditoría a SIEM')}</span>
                  </label>

                  <div className="grid-2">
                    <Field label={t('Tipo de destino')} help={t('Protocolo de transporte para el envío')}>
                      <select
                        value={siemForm.sink_type}
                        onChange={(e) => setSiemForm({ ...siemForm, sink_type: e.target.value as any })}
                      >
                        <option value="syslog">{t('Syslog (UDP, TCP o TLS / RFC 5425)')}</option>
                        <option value="webhook">{t('HTTP Webhook / Splunk HEC / Elastic')}</option>
                        <option value="file">{t('Archivo local (JSON Lines / WORM)')}</option>
                      </select>
                    </Field>

                    <Field label={t('Formato de eventos')} help={t('Estándar de formateo compatible')}>
                      <select
                        value={siemForm.format}
                        onChange={(e) => setSiemForm({ ...siemForm, format: e.target.value as any })}
                      >
                        <option value="cef">{t('CEF (Common Event Format - ArcSight / QRadar / Sentinel)')}</option>
                        <option value="json">{t('JSON / ECS (Elastic, Datadog, Cloud SIEM)')}</option>
                        <option value="rfc5424">{t('Syslog RFC 5424 Estructurado')}</option>
                      </select>
                    </Field>
                  </div>

                  <Field
                    label={t('Destino (Endpoint URL)')}
                    help={
                      siemForm.sink_type === 'syslog'
                        ? t('Formatos: syslog+tls://host:6514, syslog+tcp://host:514, syslog+udp://host:514 o syslog:')
                        : siemForm.sink_type === 'webhook'
                          ? t('Formatos: https://splunk:8088/services/collector o https://siem.corp/api/events')
                          : t('Formato: file:///var/log/duckjump/audit.jsonl')
                    }
                  >
                    <input
                      className="mono"
                      value={siemForm.endpoint}
                      placeholder={
                        siemForm.sink_type === 'syslog'
                          ? 'syslog+tls://siem.corp.internal:6514'
                          : siemForm.sink_type === 'webhook'
                            ? 'https://splunk.corp.internal:8088/services/collector'
                            : 'file:///var/log/duckjump/audit.jsonl'
                      }
                      onChange={(e) => setSiemForm({ ...siemForm, endpoint: e.target.value })}
                    />
                  </Field>

                  {siemForm.sink_type === 'webhook' && (
                    <Field
                      label={t('Encabezado de autorización (Token / API Key)')}
                      help={t('Ejemplo: "Splunk b5f28...", "Bearer eyJhbGci...", o "Token secret"')}
                    >
                      <input
                        className="mono"
                        type="text"
                        placeholder={siem.has_auth_header ? t('(Token guardado: escribe para cambiarlo)') : 'Bearer <token>'}
                        value={siemForm.auth_header}
                        onChange={(e) => setSiemForm({ ...siemForm, auth_header: e.target.value })}
                      />
                    </Field>
                  )}

                  {(siemForm.sink_type === 'syslog' || siemForm.sink_type === 'webhook') && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 4 }}>
                      <label className="row gap small" style={{ cursor: 'pointer' }}>
                        <input
                          type="checkbox"
                          checked={siemForm.tls_insecure}
                          onChange={(e) => setSiemForm({ ...siemForm, tls_insecure: e.target.checked })}
                        />
                        <span>{t('Omitir verificación del certificado TLS (InsecureSkipVerify)')}</span>
                      </label>

                      <Field
                        label={t('Certificado CA personalizado (Opcional, formato PEM)')}
                        help={t('Útil para servidores Syslog TLS o Splunk HEC con certificados firmados por una CA privada interna')}
                      >
                        <textarea
                          className="mono"
                          rows={3}
                          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                          value={siemForm.tls_ca_cert}
                          onChange={(e) => setSiemForm({ ...siemForm, tls_ca_cert: e.target.value })}
                        />
                      </Field>
                    </div>
                  )}

                  <div className="row gap" style={{ marginTop: 8 }}>
                    <button
                      className="btn btn-primary"
                      disabled={siemBusy || (siemForm.enabled && !siemForm.endpoint.trim())}
                      onClick={saveSiem}
                    >
                      <Save size={14} /> {t('Guardar configuración')}
                    </button>

                    <button
                      className="btn"
                      disabled={testing || !siemForm.endpoint.trim()}
                      onClick={runTestSiem}
                    >
                      {testing ? <Spinner /> : <Send size={14} />} {t('Probar conexión')}
                    </button>
                  </div>
                </div>
              </>
            )}
          </Section>
        )}
      </div>
    </div>
  )
}
