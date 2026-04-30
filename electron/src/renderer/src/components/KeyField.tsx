import { useState } from 'react'
import styles from './KeyField.module.css'

interface Props {
  label: string
  value: string
  secret?: boolean
}

export function KeyField({ label, value, secret }: Props) {
  const [revealed, setRevealed] = useState(false)
  const display = secret && !revealed
    ? '•'.repeat(Math.min(value.length, 44))
    : value

  return (
    <div className={styles.field}>
      <span className={styles.label}>{label}</span>
      <span className={styles.value}>{display}</span>
      {secret && (
        <button
          className={styles.eyeBtn}
          onClick={() => setRevealed(r => !r)}
          title={revealed ? 'Hide' : 'Reveal'}
        >
          {revealed ? '🙈' : '👁'}
        </button>
      )}
    </div>
  )
}
