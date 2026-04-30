import { useState, useEffect } from 'react'
import styles from './ConnectionDetail.module.css'
import type { Connection } from '../../../types/shared'
import { Toggle } from './Toggle'
import { PeerCard } from './PeerCard'
import { KeyField } from './KeyField'

interface Props {
  connection: Connection
  onEdit: () => void
  onDelete: (id: string) => void
  onToggle: (id: string, on: boolean) => Promise<{ ok: boolean; error?: string }>
  onOpenBrowser: (url: string) => Promise<unknown>
}

export function ConnectionDetail({ connection, onEdit, onDelete, onToggle, onOpenBrowser }: Props) {
  const [status, setStatus] = useState<Record<string, unknown> | null>(null)
  const [browserUrl, setBrowserUrl] = useState('https://example.com')
  const [deleteConfirm, setDeleteConfirm] = useState(false)

  useEffect(() => {
    if (!connection.running) { setStatus(null); return }
    const poll = () => window.uwg.getStatus(connection.id).then(setStatus)
    poll()
    const t = setInterval(poll, 3000)
    return () => clearInterval(t)
  }, [connection.id, connection.running])

  const handleDelete = () => {
    if (!deleteConfirm) { setDeleteConfirm(true); return }
    onDelete(connection.id)
  }

  return (
    <div className={styles.detail}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <h1 className={styles.name}>{connection.name || 'Unnamed'}</h1>
          {connection.running && connection.socksPort && (
            <span className={styles.badge}>
              SOCKS5 :{connection.socksPort}
            </span>
          )}
        </div>
        <div className={styles.headerRight}>
          <Toggle
            checked={!!connection.running}
            onChange={on => onToggle(connection.id, on)}
          />
          <button className={styles.editBtn} onClick={onEdit}>Edit</button>
          <button
            className={`${styles.deleteBtn} ${deleteConfirm ? styles.deleteConfirm : ''}`}
            onClick={handleDelete}
            onBlur={() => setDeleteConfirm(false)}
          >
            {deleteConfirm ? 'Confirm?' : 'Delete'}
          </button>
        </div>
      </div>

      {/* Browser launcher */}
      {connection.running && (
        <div className={styles.browserBar}>
          <input
            className={styles.browserInput}
            value={browserUrl}
            onChange={e => setBrowserUrl(e.target.value)}
            placeholder="https://example.com"
            onKeyDown={e => e.key === 'Enter' && onOpenBrowser(browserUrl)}
          />
          <button className={styles.browserBtn} onClick={() => onOpenBrowser(browserUrl)}>
            Open Browser
          </button>
        </div>
      )}

      <div className={styles.body}>
        {/* Interface section */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Interface</h2>
          <div className={styles.fields}>
            <KeyField label="Private key" value={connection.privateKey} secret />
            {connection.addresses?.length ? (
              <Field label="Addresses" value={connection.addresses.join(', ')} />
            ) : null}
            {connection.listenPort ? (
              <Field label="Listen port" value={String(connection.listenPort)} />
            ) : null}
            {connection.dns ? (
              <Field label="DNS" value={connection.dns} />
            ) : null}
            <Field label="MTU" value={String(connection.mtu ?? 1420)} />
          </div>
        </section>

        {/* Peers section */}
        {connection.peers?.length > 0 && (
          <section className={styles.section}>
            <h2 className={styles.sectionTitle}>Peers ({connection.peers.length})</h2>
            <div className={styles.peers}>
              {connection.peers.map((peer, i) => (
                <PeerCard key={i} peer={peer} status={status} />
              ))}
            </div>
          </section>
        )}

        {/* Live status */}
        {status && (
          <section className={styles.section}>
            <h2 className={styles.sectionTitle}>Status</h2>
            <pre className={styles.statusJson}>
              {JSON.stringify(status, null, 2)}
            </pre>
          </section>
        )}
      </div>
    </div>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className={styles.field}>
      <span className={styles.fieldLabel}>{label}</span>
      <span className={styles.fieldValue}>{value}</span>
    </div>
  )
}
