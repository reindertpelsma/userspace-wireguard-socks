export interface Peer {
  publicKey: string
  presharedKey?: string
  endpoint?: string
  allowedIPs: string[]
  keepalive?: number
}

export interface Connection {
  id: string
  name: string
  privateKey: string
  addresses?: string[]
  listenPort?: number
  dns?: string
  mtu?: number
  peers: Peer[]
  wgConfig?: string   // raw wg-quick .conf text (alternative to structured fields)
  proxy?: {
    socks5?: string
    http?: string
  }
  // runtime-only (not persisted)
  running?: boolean
  socksPort?: number
}

export interface IpcAPI {
  listConnections: () => Promise<Connection[]>
  saveConnections: (c: Connection[]) => Promise<{ ok: boolean }>
  toggleConnection: (id: string, on: boolean) => Promise<{ ok: boolean; socksPort?: number; error?: string }>
  getStatus: (id: string) => Promise<Record<string, unknown> | null>
  openBrowser: (id: string, url?: string) => Promise<{ ok: boolean; error?: string }>
  importFile: () => Promise<{ path: string; content: string } | null>
  resolveBinary: () => Promise<string>
}
