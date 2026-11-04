import { useSyncExternalStore } from 'react'

// Which relay the Relay page and the Configuration page are looking at. It is
// shared between them and remembered for the browser session.
const storageKey = 'gsp.relay'
let current = ''
try {
  current = sessionStorage.getItem(storageKey) ?? ''
} catch {
  /* ignore */
}
const listeners = new Set<() => void>()

export function setSelectedRelay(name: string) {
  current = name
  try {
    sessionStorage.setItem(storageKey, name)
  } catch {
    /* ignore */
  }
  listeners.forEach((l) => l())
}

const subscribe = (l: () => void) => {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}

/** The selected relay among names: the remembered one if it still exists, else the first. */
export function useSelectedRelay(names: string[]): [string, (name: string) => void] {
  const stored = useSyncExternalStore(subscribe, () => current)
  return [names.includes(stored) ? stored : (names[0] ?? ''), setSelectedRelay]
}
