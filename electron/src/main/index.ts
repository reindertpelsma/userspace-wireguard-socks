import { app, BrowserWindow, ipcMain, dialog, session } from 'electron'
import * as path from 'path'
import * as fs from 'fs'
import { UwgSocksManager } from './uwgsocks-manager'
import { loadConnections, saveConnections } from './store'
import type { Connection, IpcAPI } from '../types/shared'

let mainWindow: BrowserWindow | null = null
const manager = new UwgSocksManager()

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 960,
    height: 700,
    minWidth: 700,
    minHeight: 500,
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    backgroundColor: '#1a1a2e',
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  })

  if (process.env.NODE_ENV === 'development') {
    mainWindow.loadURL('http://localhost:5173')
  } else {
    mainWindow.loadFile(path.join(__dirname, '../../renderer/index.html'))
  }

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

app.whenReady().then(() => {
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  manager.stopAll()
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => {
  manager.stopAll()
})

// IPC: list connections
ipcMain.handle('connections:list', async () => {
  return loadConnections()
})

// IPC: save connections (full replace)
ipcMain.handle('connections:save', async (_e, connections: Connection[]) => {
  saveConnections(connections)
  return { ok: true }
})

// IPC: toggle connection on/off
ipcMain.handle('connections:toggle', async (_e, id: string, on: boolean) => {
  const connections = loadConnections()
  const conn = connections.find(c => c.id === id)
  if (!conn) return { ok: false, error: 'not found' }
  if (on) {
    const result = await manager.start(conn)
    if (result.ok) {
      conn.running = true
      conn.socksPort = result.socksPort
      saveConnections(connections)
    }
    return result
  } else {
    await manager.stop(id)
    conn.running = false
    conn.socksPort = undefined
    saveConnections(connections)
    return { ok: true }
  }
})

// IPC: get live status for a connection
ipcMain.handle('connections:status', async (_e, id: string) => {
  return manager.getStatus(id)
})

// IPC: open browser window for a connection
ipcMain.handle('connections:open-browser', async (_e, id: string, url: string) => {
  const state = manager.getRunningState(id)
  if (!state) return { ok: false, error: 'connection not running' }
  openBrowserWindow(state.socksPort, url)
  return { ok: true }
})

// IPC: import config file
ipcMain.handle('connections:import-file', async () => {
  const result = await dialog.showOpenDialog({
    filters: [
      { name: 'WireGuard Config', extensions: ['conf', 'zip'] },
      { name: 'All Files', extensions: ['*'] },
    ],
    properties: ['openFile'],
  })
  if (result.canceled || result.filePaths.length === 0) return null
  const p = result.filePaths[0]
  const content = fs.readFileSync(p, 'utf-8')
  return { path: p, content }
})

// IPC: resolve uwgsocks binary path
ipcMain.handle('binary:resolve', async () => {
  return manager.resolveBinaryPath()
})

function openBrowserWindow(socksPort: number, startUrl: string) {
  // Each browser window gets its own partition so proxy settings don't
  // bleed into the main UI session.
  const partition = `persist:uwg-browser-${socksPort}`
  const ses = session.fromPartition(partition)

  ses.setProxy({
    proxyRules: `socks5://127.0.0.1:${socksPort}`,
    proxyBypassRules: '<local>',
  }).then(() => {
    const win = new BrowserWindow({
      width: 1280,
      height: 800,
      titleBarStyle: process.platform === 'darwin' ? 'default' : 'default',
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        session: ses,
      },
    })
    win.setMenuBarVisibility(false)
    win.webContents.on('did-finish-load', () => {
      win.setTitle(win.webContents.getTitle() + ' — via uwgsocks')
    })
    win.loadURL(startUrl || 'https://example.com')
  })
}
