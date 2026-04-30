import * as childProcess from 'child_process'
import * as path from 'path'
import * as fs from 'fs'
import * as os from 'os'
import * as net from 'net'
import type { Connection } from '../types/shared'

interface RunningState {
  proc: childProcess.ChildProcess
  socksPort: number
  apiPort: number
  configPath: string
  wgConfigPath: string
  id: string
}

export class UwgSocksManager {
  private running = new Map<string, RunningState>()

  resolveBinaryPath(): string {
    // Look for uwgsocks in common locations
    const candidates = [
      // Next to the Electron app (production install)
      path.join(process.resourcesPath ?? '', 'uwgsocks'),
      // Repo root (development)
      path.join(__dirname, '..', '..', '..', '..', 'uwgsocks'),
      path.join(os.homedir(), 'userspace-wireguard-socks', 'uwgsocks'),
      // System PATH
      'uwgsocks',
    ]
    for (const c of candidates) {
      try {
        if (c === 'uwgsocks') {
          // Check PATH
          childProcess.execSync('which uwgsocks', { stdio: 'ignore' })
          return 'uwgsocks'
        }
        if (fs.existsSync(c)) return c
      } catch (_) {}
    }
    return 'uwgsocks'
  }

  async start(conn: Connection): Promise<{ ok: boolean; socksPort?: number; error?: string }> {
    if (this.running.has(conn.id)) {
      await this.stop(conn.id)
    }

    const socksPort = await this.findFreePort(1080)
    const apiPort = await this.findFreePort(socksPort + 1)
    const { configPath, wgConfigPath } = await this.writeConfig(conn, socksPort, apiPort)

    const binary = this.resolveBinaryPath()
    const proc = childProcess.spawn(binary, ['--config', configPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    proc.stdout?.on('data', (d: Buffer) => process.stdout.write(`[${conn.id}] ${d}`))
    proc.stderr?.on('data', (d: Buffer) => process.stderr.write(`[${conn.id}] ${d}`))

    proc.on('exit', (_code) => {
      this.running.delete(conn.id)
      try { fs.unlinkSync(configPath) } catch (_) {}
      try { fs.unlinkSync(wgConfigPath) } catch (_) {}
    })

    this.running.set(conn.id, { proc, socksPort, apiPort, configPath, wgConfigPath, id: conn.id })

    // Wait briefly for the process to start
    await new Promise(r => setTimeout(r, 600))

    if (proc.exitCode !== null) {
      return { ok: false, error: `uwgsocks exited with code ${proc.exitCode}` }
    }

    return { ok: true, socksPort }
  }

  async stop(id: string): Promise<void> {
    const state = this.running.get(id)
    if (!state) return
    state.proc.kill('SIGTERM')
    this.running.delete(id)
    try { fs.unlinkSync(state.configPath) } catch (_) {}
    try { fs.unlinkSync(state.wgConfigPath) } catch (_) {}
  }

  stopAll() {
    for (const [id] of this.running) {
      this.stop(id).catch(() => {})
    }
  }

  async getStatus(id: string): Promise<Record<string, unknown> | null> {
    const state = this.running.get(id)
    if (!state) return null
    try {
      const resp = await fetch(`http://127.0.0.1:${state.apiPort}/v1/status`, {
        signal: AbortSignal.timeout(2000),
      })
      if (!resp.ok) return null
      return resp.json()
    } catch (_) {
      return null
    }
  }

  getRunningState(id: string): RunningState | undefined {
    return this.running.get(id)
  }

  private async writeConfig(conn: Connection, socksPort: number, apiPort: number): Promise<{ configPath: string; wgConfigPath: string }> {
    const tmpDir = os.tmpdir()
    const tag = `${conn.id}-${Date.now()}`
    const configPath = path.join(tmpDir, `uwgsocks-${tag}.yaml`)
    const wgConfigPath = path.join(tmpDir, `uwgsocks-${tag}.conf`)

    // Write wg-quick config
    const wgText = conn.wgConfig || this.buildWgConfig(conn)
    fs.writeFileSync(wgConfigPath, wgText, { mode: 0o600 })

    // Write uwgsocks YAML (references the wg-quick file)
    const yaml = [
      `wireguard:`,
      `  config_file: ${JSON.stringify(wgConfigPath)}`,
      `  mtu: ${conn.mtu ?? 1420}`,
      `proxy:`,
      `  socks5:`,
      `    listen: "127.0.0.1:${socksPort}"`,
      `api:`,
      `  listen: "127.0.0.1:${apiPort}"`,
    ].join('\n')

    fs.writeFileSync(configPath, yaml, { mode: 0o600 })
    return { configPath, wgConfigPath }
  }

  private buildWgConfig(conn: Connection): string {
    const lines: string[] = [
      '[Interface]',
      `PrivateKey = ${conn.privateKey}`,
      `Address = ${(conn.addresses ?? []).join(', ')}`,
    ]
    if (conn.listenPort) lines.push(`ListenPort = ${conn.listenPort}`)
    if (conn.dns) lines.push(`DNS = ${conn.dns}`)

    for (const peer of conn.peers ?? []) {
      lines.push('[Peer]')
      lines.push(`PublicKey = ${peer.publicKey}`)
      if (peer.presharedKey) lines.push(`PresharedKey = ${peer.presharedKey}`)
      if (peer.endpoint) lines.push(`Endpoint = ${peer.endpoint}`)
      if (peer.allowedIPs) lines.push(`AllowedIPs = ${peer.allowedIPs.join(', ')}`)
      if (peer.keepalive) lines.push(`PersistentKeepalive = ${peer.keepalive}`)
    }
    return lines.join('\n')
  }

  private findFreePort(start: number): Promise<number> {
    return new Promise((resolve, reject) => {
      const srv = net.createServer()
      srv.listen(start, '127.0.0.1', () => {
        const addr = srv.address() as net.AddressInfo
        srv.close(() => resolve(addr.port))
      })
      srv.on('error', () => {
        this.findFreePort(start + 1).then(resolve, reject)
      })
    })
  }
}
