import * as fs from 'fs'
import * as path from 'path'
import { app } from 'electron'
import type { Connection } from '../types/shared'

function storePath(): string {
  return path.join(app.getPath('userData'), 'connections.json')
}

export function loadConnections(): Connection[] {
  try {
    const raw = fs.readFileSync(storePath(), 'utf-8')
    const parsed = JSON.parse(raw)
    // Strip runtime state on load
    return (parsed as Connection[]).map(c => ({ ...c, running: false, socksPort: undefined }))
  } catch (_) {
    return []
  }
}

export function saveConnections(connections: Connection[]) {
  // Strip runtime state before persisting
  const toSave = connections.map(({ running: _r, socksPort: _s, ...rest }) => rest)
  fs.mkdirSync(path.dirname(storePath()), { recursive: true })
  fs.writeFileSync(storePath(), JSON.stringify(toSave, null, 2), { mode: 0o600 })
}
