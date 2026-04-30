/// <reference types="vite/client" />

import type { IpcAPI } from '../../types/shared'

declare global {
  interface Window {
    uwg: IpcAPI
  }
}
