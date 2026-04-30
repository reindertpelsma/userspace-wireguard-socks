import { useState } from 'react'
import styles from './Toggle.module.css'

interface Props {
  checked: boolean
  onChange: (on: boolean) => Promise<unknown>
  small?: boolean
}

export function Toggle({ checked, onChange, small }: Props) {
  const [busy, setBusy] = useState(false)

  const handle = async () => {
    if (busy) return
    setBusy(true)
    try {
      await onChange(!checked)
    } finally {
      setBusy(false)
    }
  }

  return (
    <button
      className={`${styles.toggle} ${checked ? styles.on : ''} ${small ? styles.small : ''} ${busy ? styles.busy : ''}`}
      onClick={handle}
      aria-pressed={checked}
      aria-label={checked ? 'Disconnect' : 'Connect'}
    >
      <span className={styles.thumb} />
    </button>
  )
}
