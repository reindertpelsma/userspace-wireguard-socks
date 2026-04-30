import { useState, useEffect, useCallback } from 'react'
import { ConnectionList } from './components/ConnectionList'
import { ConnectionDetail } from './components/ConnectionDetail'
import { ConnectionEditor } from './components/ConnectionEditor'
import type { Connection } from '../../types/shared'
import styles from './App.module.css'

type View = 'list' | 'detail' | 'edit-new' | 'edit-existing'

export default function App() {
  const [connections, setConnections] = useState<Connection[]>([])
  const [selected, setSelected] = useState<Connection | null>(null)
  const [view, setView] = useState<View>('list')
  const [binaryPath, setBinaryPath] = useState<string>('')

  useEffect(() => {
    window.uwg.listConnections().then(setConnections)
    window.uwg.resolveBinary().then(setBinaryPath)
  }, [])

  const persist = useCallback(async (updated: Connection[]) => {
    setConnections(updated)
    await window.uwg.saveConnections(updated)
  }, [])

  const handleToggle = useCallback(async (id: string, on: boolean) => {
    const result = await window.uwg.toggleConnection(id, on)
    if (result.ok) {
      setConnections(prev => prev.map(c =>
        c.id === id ? { ...c, running: on, socksPort: result.socksPort } : c
      ))
      if (selected?.id === id) {
        setSelected(prev => prev ? { ...prev, running: on, socksPort: result.socksPort } : prev)
      }
    }
    return result
  }, [selected])

  const handleSaveEdit = useCallback(async (conn: Connection) => {
    const updated = view === 'edit-new'
      ? [...connections, conn]
      : connections.map(c => c.id === conn.id ? conn : c)
    await persist(updated)
    setSelected(conn)
    setView('detail')
  }, [connections, view, persist])

  const handleDelete = useCallback(async (id: string) => {
    // Stop if running
    const conn = connections.find(c => c.id === id)
    if (conn?.running) await window.uwg.toggleConnection(id, false)
    const updated = connections.filter(c => c.id !== id)
    await persist(updated)
    setSelected(null)
    setView('list')
  }, [connections, persist])

  const handleSelect = useCallback((conn: Connection) => {
    setSelected(conn)
    setView('detail')
  }, [])

  const handleNewConnection = useCallback(() => {
    setSelected(null)
    setView('edit-new')
  }, [])

  const handleEditSelected = useCallback(() => {
    setView('edit-existing')
  }, [])

  const handleBack = useCallback(() => {
    if (view === 'detail' || view === 'edit-new') {
      setView('list')
    } else if (view === 'edit-existing') {
      setView('detail')
    }
  }, [view])

  return (
    <div className={styles.app}>
      <aside className={styles.sidebar}>
        <div className={styles.sidebarHeader}>
          <span className={styles.logo}>uwgsocks</span>
          <button className={styles.addBtn} onClick={handleNewConnection} title="New connection">+</button>
        </div>
        <ConnectionList
          connections={connections}
          selectedId={selected?.id}
          onSelect={handleSelect}
          onToggle={handleToggle}
        />
        <div className={styles.sidebarFooter}>
          <span className={styles.binaryHint} title={binaryPath}>
            {binaryPath ? `bin: ${binaryPath.split('/').pop()}` : 'uwgsocks not found'}
          </span>
        </div>
      </aside>

      <main className={styles.main}>
        {view === 'list' && (
          <div className={styles.emptyState}>
            <p>Select a connection or create a new one</p>
            <button className={styles.primaryBtn} onClick={handleNewConnection}>
              Add connection
            </button>
          </div>
        )}
        {(view === 'detail') && selected && (
          <ConnectionDetail
            connection={selected}
            onEdit={handleEditSelected}
            onDelete={handleDelete}
            onToggle={handleToggle}
            onOpenBrowser={(url) => window.uwg.openBrowser(selected.id, url)}
          />
        )}
        {(view === 'edit-new' || view === 'edit-existing') && (
          <ConnectionEditor
            initial={view === 'edit-existing' ? selected ?? undefined : undefined}
            onSave={handleSaveEdit}
            onCancel={handleBack}
          />
        )}
      </main>
    </div>
  )
}
