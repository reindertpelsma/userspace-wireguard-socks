import styles from './ConnectionList.module.css'
import type { Connection } from '../../../types/shared'
import { Toggle } from './Toggle'

interface Props {
  connections: Connection[]
  selectedId?: string
  onSelect: (c: Connection) => void
  onToggle: (id: string, on: boolean) => Promise<{ ok: boolean; error?: string }>
}

export function ConnectionList({ connections, selectedId, onSelect, onToggle }: Props) {
  if (connections.length === 0) {
    return (
      <div className={styles.empty}>
        <span>No connections yet</span>
      </div>
    )
  }

  return (
    <ul className={styles.list}>
      {connections.map(conn => (
        <li
          key={conn.id}
          className={`${styles.item} ${conn.id === selectedId ? styles.active : ''}`}
        >
          <button className={styles.itemBtn} onClick={() => onSelect(conn)}>
            <span className={`${styles.dot} ${conn.running ? styles.dotOn : ''}`} />
            <span className={styles.name}>{conn.name || 'Unnamed'}</span>
          </button>
          <div className={styles.toggleWrap} onClick={e => e.stopPropagation()}>
            <Toggle
              checked={!!conn.running}
              onChange={on => onToggle(conn.id, on)}
              small
            />
          </div>
        </li>
      ))}
    </ul>
  )
}
