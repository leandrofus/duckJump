import { t } from '../i18n'
import { useEffect, useRef, useState } from 'react'
import * as AsciinemaPlayer from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'
import { Download, Loader2, Radio } from 'lucide-react'
import { enc } from '../lib/api'
import type { Session } from '../lib/api'
import { bytes } from '../lib/format'

/** Plays a session recording (asciicast v2). The gateway serves it gzipped
 *  and audits every download as recording.view. */
export function RecordingPlayer({ session }: { session: Session }) {
  const host = useRef<HTMLDivElement>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [attempt, setAttempt] = useState(0)
  const live = !session.ended_at
  const url = `/api/v1/audit/sessions/${enc(session.id)}/recording`
  useEffect(() => {
    if (!host.current) return
    let player: AsciinemaPlayer.Player | undefined
    let cancelled = false
    setLoading(true)
    setError('')
    // Fetch first so a 403/404/410 shows a message instead of an empty player.
    fetch(url, { credentials: 'same-origin' })
      .then(async (r) => {
        if (!r.ok) throw new Error((await r.json().catch(() => null))?.message || r.statusText)
        return r.text()
      })
      .then((cast) => {
        if (cancelled || !host.current) return
        if (!cast.trim()) throw new Error(t('nothing has been recorded yet'))
        host.current.innerHTML = ''
        // Passed as data (not a blob: URL) so the CSP can keep connect-src 'self'.
        player = AsciinemaPlayer.create({ data: cast }, host.current, {
          fit: 'width', idleTimeLimit: 2, preload: true, theme: 'asciinema',
          terminalFontFamily: '"JetBrains Mono", ui-monospace, monospace',
        })
      })
      .catch((e) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
      player?.dispose()
    }
  }, [session.id, attempt])
  return (
    <div className="recording">
      {live && (
        <div className="alert alert-warn row gap">
          <Radio size={14} /> {t('The session is still open: this is what was recorded up to now.')}
          <button className="link" onClick={() => setAttempt((n) => n + 1)}>{t('Refresh')}</button>
        </div>
      )}
      {error ? (
        <div className="alert alert-bad">{t('Could not load the recording: {0}', error)}</div>
      ) : (
        <div className="recording-frame">
          {loading && (
            <div className="recording-loading">
              <Loader2 size={18} className="spin" />
              <span>{session.recording_bytes ? t('Loading the recording ({0} compressed)…', bytes(session.recording_bytes)) : t('Loading the recording…')}</span>
              {(session.recording_bytes ?? 0) > 2e6 && <span className="muted small">{t('Long recordings can take a few seconds to prepare.')}</span>}
            </div>
          )}
          <div ref={host} className="recording-host" />
        </div>
      )}
      <a className="btn btn-sm" href={url} download><Download size={13} /> {t('Download .cast')}</a>
    </div>
  )
}
