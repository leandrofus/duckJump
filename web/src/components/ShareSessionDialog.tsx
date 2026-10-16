import { t } from '../i18n'
import { useEffect, useState } from 'react'
import { Copy, Shield, Users, Check } from 'lucide-react'
import { api, enc } from '../lib/api'
import { Modal, toast } from '../ui/overlays'
import { Avatar } from '../ui/common'

export interface Participant {
  id: string
  user_id: string
  username: string
  is_owner: boolean
  has_control: boolean
}

export function ShareSessionDialog({
  sessionId,
  connectionId,
  participants,
  myId,
  isOwner,
  hasControl,
  controllerName,
  onYieldControl,
  onTakeControl,
  onClose,
}: {
  sessionId: string
  connectionId: string
  participants: Participant[]
  myId?: string
  isOwner: boolean
  hasControl: boolean
  controllerName?: string
  onYieldControl: (participantId: string) => void
  onTakeControl: () => void
  onClose: () => void
}) {
  const [shareToken, setShareToken] = useState<string>('')
  const [copied, setCopied] = useState(false)

  const loadShare = async () => {
    try {
      const res = await api.get<{ share_token: string }>(`/sessions/${enc(sessionId)}/share`)
      setShareToken(res.share_token)
    } catch {
      // If error (e.g. non-owner), join link might be without token for connection users
    }
  }

  useEffect(() => {
    if (isOwner) {
      loadShare()
    }
  }, [sessionId, isOwner])

  const joinUrl = shareToken
    ? `${window.location.origin}${window.location.pathname}#/session/${encodeURIComponent(connectionId)}?join=${encodeURIComponent(sessionId)}&token=${encodeURIComponent(shareToken)}`
    : `${window.location.origin}${window.location.pathname}#/session/${encodeURIComponent(connectionId)}?join=${encodeURIComponent(sessionId)}`

  const copyLink = () => {
    navigator.clipboard.writeText(joinUrl).then(() => {
      setCopied(true)
      toast.ok(t('Invite link copied to clipboard'))
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <Modal
      title={t('Share session')}
      icon={<Users size={18} />}
      onClose={onClose}
    >
      <div className="share-dialog-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {isOwner && (
          <div className="share-link-section">
            <label className="label" style={{ fontWeight: 600, display: 'block', marginBottom: 6 }}>
              {t('Invite link')}
            </label>
            <p className="help" style={{ marginBottom: 8 }}>
              {t('Anyone with an account who opens this link can join this session in real time.')}
            </p>
            <div className="row gap" style={{ display: 'flex', alignItems: 'center' }}>
              <input
                type="text"
                readOnly
                className="input grow mono small"
                value={joinUrl}
                style={{ flexGrow: 1 }}
                onClick={(e) => (e.target as HTMLInputElement).select()}
              />
              <button className="btn btn-primary" onClick={copyLink} title={t('Copy link')}>
                {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? t('Copied') : t('Copy')}
              </button>
            </div>
          </div>
        )}

        <div className="participants-section">
          <div className="row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <div>
              <span style={{ fontWeight: 600 }}>{t('Connected participants ({0})', participants.length)}</span>
              {controllerName && <span className="muted small" style={{ marginLeft: 8 }}>· {t('Controller: {0}', controllerName)}</span>}
            </div>
            {isOwner && !hasControl && (
              <button className="btn btn-xs btn-primary" onClick={onTakeControl}>
                <Shield size={12} /> {t('Reclaim control')}
              </button>
            )}
          </div>

          <div className="participants-list" style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 240, overflowY: 'auto' }}>
            {participants.map((p) => {
              const isMe = p.id === myId
              return (
                <div
                  key={p.id}
                  className="participant-row row gap"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '8px 12px',
                    borderRadius: 6,
                    background: 'var(--bg-subtle, rgba(255,255,255,0.04))',
                    border: p.has_control ? '1px solid var(--primary, #38bdf8)' : '1px solid transparent',
                  }}
                >
                  <Avatar name={p.username} size={28} />
                  <div style={{ flexGrow: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <strong className="ellipsis">{p.username}</strong>
                      {isMe && <span className="muted small">({t('You')})</span>}
                    </div>
                    <div className="row gap small muted" style={{ marginTop: 2, display: 'flex', gap: 6 }}>
                      {p.is_owner && <span className="pill pill-muted">{t('Owner')}</span>}
                      {p.has_control ? (
                        <span className="pill pill-active" style={{ color: 'var(--primary, #38bdf8)' }}>
                          {t('Has control')}
                        </span>
                      ) : (
                        <span className="pill pill-idle">{t('View-only')}</span>
                      )}
                    </div>
                  </div>

                  <div className="participant-actions">
                    {(hasControl || isOwner) && !p.has_control && (
                      <button
                        className="btn btn-sm btn-outline"
                        onClick={() => {
                          onYieldControl(p.id)
                          toast.ok(t('Control yielded to {0}', p.username))
                        }}
                      >
                        {t('Yield control')}
                      </button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </Modal>
  )
}
