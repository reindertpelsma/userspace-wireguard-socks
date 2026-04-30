import { useState } from 'react'
import styles from './PeerCard.module.css'
import type { Peer } from '../../../types/shared'

interface Props {
  peer: Peer
  status: Record<string, unknown> | null
}

export function PeerCard({ peer, status }: Props) {
  const [expanded, setExpanded] = useState(false)

  // Find peer status from /v1/status response
  const peerStatus = findPeerStatus(status, peer.publicKey)

  return (
    <div className={styles.card}>
      <button className={styles.header} onClick={() => setExpanded(e => !e)}>
        <div className={styles.headerLeft}>
          <span className={`${styles.dot} ${peerStatus ? styles.dotActive : ''}`} />
          <span className={styles.pubkey}>{peer.publicKey.slice(0, 16)}…</span>
        </div>
        <div className={styles.headerRight}>
          {peer.endpoint && <span className={styles.chip}>{peer.endpoint}</span>}
          <span className={styles.chevron}>{expanded ? '▲' : '▼'}</span>
        </div>
      </button>

      {expanded && (
        <div className={styles.body}>
          <Row label="Public key" value={peer.publicKey} mono />
          {peer.presharedKey && <Row label="PSK" value="••••••••" mono />}
          {peer.endpoint && <Row label="Endpoint" value={peer.endpoint} mono />}
          <Row label="Allowed IPs" value={peer.allowedIPs.join(', ')} mono />
          {peer.keepalive ? <Row label="Keepalive" value={`${peer.keepalive}s`} /> : null}
          {peerStatus && (
            <>
              <Row label="Last HS" value={formatHandshake(peerStatus)} />
              <Row label="RX / TX" value={formatTraffic(peerStatus)} />
            </>
          )}
        </div>
      )}
    </div>
  )
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className={styles.row}>
      <span className={styles.rowLabel}>{label}</span>
      <span className={`${styles.rowValue} ${mono ? styles.mono : ''}`}>{value}</span>
    </div>
  )
}

function findPeerStatus(status: Record<string, unknown> | null, pubkey: string) {
  if (!status) return null
  const peers = (status as Record<string, unknown[]>).peers
  if (!Array.isArray(peers)) return null
  return peers.find((p: unknown) => (p as Record<string, unknown>).public_key === pubkey) ?? null
}

function formatHandshake(p: unknown): string {
  const s = p as Record<string, unknown>
  if (s.last_handshake_time) {
    const t = new Date(s.last_handshake_time as string)
    return t.toLocaleTimeString()
  }
  return 'never'
}

function formatTraffic(p: unknown): string {
  const s = p as Record<string, unknown>
  const rx = Number(s.receive_bytes ?? 0)
  const tx = Number(s.transmit_bytes ?? 0)
  return `${fmtBytes(rx)} / ${fmtBytes(tx)}`
}

function fmtBytes(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB`
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} KB`
  return `${n} B`
}
