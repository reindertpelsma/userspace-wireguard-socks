import { useState, useCallback, type ReactNode } from 'react'
import styles from './ConnectionEditor.module.css'
import type { Connection, Peer } from '../../../types/shared'

interface Props {
  initial?: Connection
  onSave: (c: Connection) => void
  onCancel: () => void
}

type EditMode = 'form' | 'text'

function newId() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36)
}

function emptyConnection(): Connection {
  return {
    id: newId(),
    name: '',
    privateKey: '',
    addresses: [],
    listenPort: undefined,
    dns: '',
    mtu: 1420,
    peers: [],
  }
}

export function ConnectionEditor({ initial, onSave, onCancel }: Props) {
  const [mode, setMode] = useState<EditMode>('form')
  const [conn, setConn] = useState<Connection>(initial ?? emptyConnection())
  const [rawText, setRawText] = useState(initial?.wgConfig ?? '')
  const [importError, setImportError] = useState<string | null>(null)

  const set = useCallback(<K extends keyof Connection>(k: K, v: Connection[K]) => {
    setConn(c => ({ ...c, [k]: v }))
  }, [])

  const handleImport = async () => {
    const result = await window.uwg.importFile()
    if (!result) return
    setRawText(result.content)
    setMode('text')
    setImportError(null)
  }

  const handleSave = () => {
    if (mode === 'text') {
      // Parse raw wg-quick conf
      const parsed = parseWgConfig(rawText)
      if (!parsed) { setImportError('Could not parse WireGuard config'); return }
      onSave({ ...conn, ...parsed, id: conn.id, wgConfig: rawText })
    } else {
      if (!conn.name.trim()) { setImportError('Name is required'); return }
      if (!conn.privateKey.trim()) { setImportError('Private key is required'); return }
      onSave({ ...conn, wgConfig: undefined })
    }
  }

  const updatePeer = (i: number, peer: Peer) => {
    const peers = [...conn.peers]
    peers[i] = peer
    set('peers', peers)
  }

  const removePeer = (i: number) => {
    set('peers', conn.peers.filter((_, j) => j !== i))
  }

  const addPeer = () => {
    set('peers', [...conn.peers, { publicKey: '', allowedIPs: [] }])
  }

  return (
    <div className={styles.editor}>
      <div className={styles.header}>
        <h1 className={styles.title}>{initial ? 'Edit connection' : 'New connection'}</h1>
        <div className={styles.tabs}>
          <button
            className={`${styles.tab} ${mode === 'form' ? styles.tabActive : ''}`}
            onClick={() => setMode('form')}
          >Form</button>
          <button
            className={`${styles.tab} ${mode === 'text' ? styles.tabActive : ''}`}
            onClick={() => setMode('text')}
          >Config text</button>
        </div>
        <div className={styles.headerActions}>
          <button className={styles.importBtn} onClick={handleImport}>Import .conf / .zip</button>
        </div>
      </div>

      <div className={styles.body}>
        {importError && <div className={styles.error}>{importError}</div>}

        {mode === 'form' ? (
          <>
            <Section title="Interface">
              <Field label="Name" required>
                <input
                  className={styles.input}
                  value={conn.name}
                  onChange={e => set('name', e.target.value)}
                  placeholder="My VPN"
                />
              </Field>
              <Field label="Private key" required>
                <input
                  className={styles.input}
                  value={conn.privateKey}
                  onChange={e => set('privateKey', e.target.value)}
                  placeholder="base64 WireGuard private key"
                  type="password"
                  autoComplete="off"
                />
              </Field>
              <Field label="Addresses">
                <input
                  className={styles.input}
                  value={(conn.addresses ?? []).join(', ')}
                  onChange={e => set('addresses', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                  placeholder="10.0.0.2/32, fd00::2/128"
                />
              </Field>
              <Field label="Listen port">
                <input
                  className={styles.input}
                  value={conn.listenPort ?? ''}
                  onChange={e => set('listenPort', e.target.value ? Number(e.target.value) : undefined)}
                  placeholder="51820 (optional)"
                  type="number"
                />
              </Field>
              <Field label="DNS">
                <input
                  className={styles.input}
                  value={conn.dns ?? ''}
                  onChange={e => set('dns', e.target.value)}
                  placeholder="1.1.1.1, 8.8.8.8 (optional)"
                />
              </Field>
              <Field label="MTU">
                <input
                  className={styles.input}
                  value={conn.mtu ?? 1420}
                  onChange={e => set('mtu', Number(e.target.value) || 1420)}
                  type="number"
                  min={1280}
                  max={9000}
                />
              </Field>
            </Section>

            <Section title="Peers" action={<button className={styles.addPeerBtn} onClick={addPeer}>+ Add peer</button>}>
              {conn.peers.length === 0 && (
                <p className={styles.noPeers}>No peers yet. Add one or import a config file.</p>
              )}
              {conn.peers.map((peer, i) => (
                <PeerEditor key={i} peer={peer} onChange={p => updatePeer(i, p)} onRemove={() => removePeer(i)} />
              ))}
            </Section>

            <Section title="Proxy (optional)">
              <Field label="Upstream SOCKS5">
                <input
                  className={styles.input}
                  value={conn.proxy?.socks5 ?? ''}
                  onChange={e => set('proxy', { ...conn.proxy, socks5: e.target.value })}
                  placeholder="socks5://127.0.0.1:1080"
                />
              </Field>
              <Field label="Upstream HTTP">
                <input
                  className={styles.input}
                  value={conn.proxy?.http ?? ''}
                  onChange={e => set('proxy', { ...conn.proxy, http: e.target.value })}
                  placeholder="http://proxy:3128"
                />
              </Field>
            </Section>
          </>
        ) : (
          <div className={styles.textSection}>
            <p className={styles.textHint}>Paste or edit a wg-quick .conf file. The Name field below is still required for the connection list.</p>
            <Field label="Name" required>
              <input
                className={styles.input}
                value={conn.name}
                onChange={e => set('name', e.target.value)}
                placeholder="My VPN"
              />
            </Field>
            <textarea
              className={styles.textarea}
              value={rawText}
              onChange={e => setRawText(e.target.value)}
              placeholder={'[Interface]\nPrivateKey = ...\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = ...\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0'}
              spellCheck={false}
            />
          </div>
        )}
      </div>

      <div className={styles.footer}>
        <button className={styles.cancelBtn} onClick={onCancel}>Cancel</button>
        <button className={styles.saveBtn} onClick={handleSave}>
          {initial ? 'Save changes' : 'Create connection'}
        </button>
      </div>
    </div>
  )
}

function Section({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <section className={styles.section}>
      <div className={styles.sectionHeader}>
        <h2 className={styles.sectionTitle}>{title}</h2>
        {action}
      </div>
      <div className={styles.sectionBody}>{children}</div>
    </section>
  )
}

function Field({ label, children, required }: { label: string; children: ReactNode; required?: boolean }) {
  return (
    <div className={styles.field}>
      <label className={styles.fieldLabel}>
        {label}{required && <span className={styles.req}>*</span>}
      </label>
      {children}
    </div>
  )
}

function PeerEditor({ peer, onChange, onRemove }: { peer: Peer; onChange: (p: Peer) => void; onRemove: () => void }) {
  return (
    <div className={styles.peerEditor}>
      <div className={styles.peerHeader}>
        <span className={styles.peerTitle}>
          {peer.publicKey ? `${peer.publicKey.slice(0, 12)}…` : 'New peer'}
        </span>
        <button className={styles.removePeerBtn} onClick={onRemove}>Remove</button>
      </div>
      <div className={styles.peerFields}>
        <Field label="Public key" required>
          <input
            className={styles.input}
            value={peer.publicKey}
            onChange={e => onChange({ ...peer, publicKey: e.target.value })}
            placeholder="base64 WireGuard public key"
          />
        </Field>
        <Field label="PSK">
          <input
            className={styles.input}
            value={peer.presharedKey ?? ''}
            onChange={e => onChange({ ...peer, presharedKey: e.target.value || undefined })}
            placeholder="optional preshared key"
            type="password"
          />
        </Field>
        <Field label="Endpoint">
          <input
            className={styles.input}
            value={peer.endpoint ?? ''}
            onChange={e => onChange({ ...peer, endpoint: e.target.value || undefined })}
            placeholder="vpn.example.com:51820"
          />
        </Field>
        <Field label="Allowed IPs">
          <input
            className={styles.input}
            value={peer.allowedIPs.join(', ')}
            onChange={e => onChange({ ...peer, allowedIPs: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })}
            placeholder="0.0.0.0/0, ::/0"
          />
        </Field>
        <Field label="Keepalive">
          <input
            className={styles.input}
            value={peer.keepalive ?? ''}
            onChange={e => onChange({ ...peer, keepalive: e.target.value ? Number(e.target.value) : undefined })}
            type="number"
            placeholder="25 (seconds, optional)"
          />
        </Field>
      </div>
    </div>
  )
}

// Minimal wg-quick parser
function parseWgConfig(text: string): Partial<Connection> | null {
  try {
    const lines = text.split('\n').map(l => l.trim())
    let section = ''
    const iface: Partial<Connection> = { peers: [] }
    let currentPeer: Partial<Peer> = {}

    const commitPeer = () => {
      if (currentPeer.publicKey) {
        iface.peers!.push({
          publicKey: currentPeer.publicKey,
          presharedKey: currentPeer.presharedKey,
          endpoint: currentPeer.endpoint,
          allowedIPs: currentPeer.allowedIPs ?? [],
          keepalive: currentPeer.keepalive,
        })
      }
      currentPeer = {}
    }

    for (const line of lines) {
      if (!line || line.startsWith('#')) continue
      if (line === '[Interface]') { commitPeer(); section = 'interface'; continue }
      if (line === '[Peer]') { commitPeer(); section = 'peer'; continue }
      const eq = line.indexOf('=')
      if (eq < 0) continue
      const key = line.slice(0, eq).trim()
      const val = line.slice(eq + 1).trim()

      if (section === 'interface') {
        if (key === 'PrivateKey') iface.privateKey = val
        else if (key === 'Address') iface.addresses = val.split(',').map(s => s.trim())
        else if (key === 'ListenPort') iface.listenPort = Number(val)
        else if (key === 'DNS') iface.dns = val
        else if (key === 'MTU') iface.mtu = Number(val)
      } else if (section === 'peer') {
        if (key === 'PublicKey') currentPeer.publicKey = val
        else if (key === 'PresharedKey') currentPeer.presharedKey = val
        else if (key === 'Endpoint') currentPeer.endpoint = val
        else if (key === 'AllowedIPs') currentPeer.allowedIPs = val.split(',').map(s => s.trim())
        else if (key === 'PersistentKeepalive') currentPeer.keepalive = Number(val)
      }
    }
    commitPeer()
    return iface.privateKey ? iface : null
  } catch (_) {
    return null
  }
}
