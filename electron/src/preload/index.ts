import { contextBridge, ipcRenderer } from 'electron'
import type { IpcAPI, Connection } from '../types/shared'

const api: IpcAPI = {
  listConnections: () => ipcRenderer.invoke('connections:list'),
  saveConnections: (c: Connection[]) => ipcRenderer.invoke('connections:save', c),
  toggleConnection: (id: string, on: boolean) => ipcRenderer.invoke('connections:toggle', id, on),
  getStatus: (id: string) => ipcRenderer.invoke('connections:status', id),
  openBrowser: (id: string, url?: string) => ipcRenderer.invoke('connections:open-browser', id, url ?? 'https://example.com'),
  importFile: () => ipcRenderer.invoke('connections:import-file'),
  resolveBinary: () => ipcRenderer.invoke('binary:resolve'),
}

contextBridge.exposeInMainWorld('uwg', api)
