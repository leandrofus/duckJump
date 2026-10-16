import { t } from '../i18n'
import { useEffect, useRef, useState } from 'react'
import { Play, Pause, Download, Loader2, Radio, MousePointer2 } from 'lucide-react'
import { enc } from '../lib/api'
import type { Session } from '../lib/api'
import { bytes } from '../lib/format'
import { Painter, parseDisplay, parseRecording } from '../lib/gfx'
import type { GfxRecord } from '../lib/gfx'

const fmt = (s: number) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`

/** Plays a graphical session recording (DJGFX1): the display operations
 *  replayed on a canvas with their timing, plus the user's pointer. */
export function GfxPlayer({ session }: { session: Session }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [recs, setRecs] = useState<GfxRecord[] | null>(null)
  const [error, setError] = useState('')
  const [playing, setPlaying] = useState(false)
  const [pos, setPos] = useState(0)
  const [speed, setSpeed] = useState(1)
  const [pointer, setPointer] = useState<{ x: number; y: number } | null>(null)
  const [size, setSize] = useState({ w: 0, h: 0 })
  const st = useRef({ i: 0, painter: null as Painter | null, start: 0, base: 0, timer: 0 })
  const url = `/api/v1/audit/sessions/${enc(session.id)}/recording`
  const duration = recs?.length ? recs[recs.length - 1].t : 0

  useEffect(() => {
    fetch(url, { credentials: 'same-origin' })
      .then(async (r) => {
        if (!r.ok) throw new Error((await r.json().catch(() => null))?.message || r.statusText)
        return r.arrayBuffer()
      })
      .then((buf) => {
        const { records } = parseRecording(buf)
        if (!records.length) throw new Error(t('nothing has been recorded yet'))
        setRecs(records)
      })
      .catch((e) => setError(e.message))
  }, [session.id])

  const apply = (r: GfxRecord) => {
    if (r.kind === 1) {
      const op = parseDisplay(r.payload)
      if (!op) return
      if (op.op === 'size') setSize({ w: op.w, h: op.h })
      if (op.op !== 'sync' && op.op !== 'cursor') st.current.painter!.push(op)
    } else if (r.kind === 2 && r.payload[0] === 0x02) {
      const v = new DataView(r.payload.buffer, r.payload.byteOffset)
      setPointer({ x: v.getUint16(1), y: v.getUint16(3) })
    }
  }

  // Jump to a time: replay everything up to it from the start.
  const seek = async (target: number) => {
    if (!recs || !canvasRef.current) return
    st.current.painter = new Painter(canvasRef.current)
    let i = 0
    while (i < recs.length && recs[i].t <= target) apply(recs[i++])
    await st.current.painter.idle()
    st.current.i = i
    st.current.base = target
    st.current.start = performance.now()
    setPos(target)
  }

  useEffect(() => {
    if (recs) void seek(0)
  }, [recs])

  useEffect(() => {
    if (!playing || !recs) return
    st.current.start = performance.now()
    st.current.base = pos
    const tick = () => {
      const now = st.current.base + ((performance.now() - st.current.start) / 1000) * speed
      while (st.current.i < recs.length && recs[st.current.i].t <= now) apply(recs[st.current.i++])
      setPos(Math.min(now, duration))
      if (st.current.i >= recs.length) return setPlaying(false)
      st.current.timer = requestAnimationFrame(tick)
    }
    st.current.timer = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(st.current.timer)
  }, [playing, speed, recs])

  const live = !session.ended_at
  return (
    <div className="recording">
      {live && <div className="alert alert-warn row gap"><Radio size={14} /> {t('The session is still open: this is what was recorded up to now.')}</div>}
      {error && <div className="alert alert-bad">{t('Could not load the recording: {0}', error)}</div>}
      {!error && (
        <div className="recording-frame gfx-frame">
          {!recs && (
            <div className="recording-loading">
              <Loader2 size={18} className="spin" />
              <span>{session.recording_bytes ? t('Loading the recording ({0} compressed)…', bytes(session.recording_bytes)) : t('Loading the recording…')}</span>
            </div>
          )}
          <div className="gfx-stage">
            <canvas ref={canvasRef} />
            {pointer && size.w > 0 && (
              <MousePointer2 className="gfx-pointer" size={18} style={{ left: `${(pointer.x / size.w) * 100}%`, top: `${(pointer.y / size.h) * 100}%` }} />
            )}
          </div>
          {recs && (
            <div className="gfx-controls">
              <button className="icon-btn" onClick={() => (pos >= duration ? seek(0).then(() => setPlaying(true)) : setPlaying(!playing))}>{playing ? <Pause size={16} /> : <Play size={16} />}</button>
              <span className="mono small">{fmt(pos)} / {fmt(duration)}</span>
              <input type="range" className="grow" min={0} max={duration} step={0.1} value={pos} onChange={(e) => { setPlaying(false); void seek(Number(e.target.value)) }} />
              <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
                {[1, 2, 4, 8].map((s) => <option key={s} value={s}>{s}×</option>)}
              </select>
            </div>
          )}
        </div>
      )}
      <a className="btn btn-sm" href={url} download><Download size={13} /> {t('Download recording')}</a>
    </div>
  )
}
