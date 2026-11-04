import { useCallback, useEffect, useRef, useState } from 'react'

/** Loads data now and then every `every` ms; `reload` fetches again at once. */
export function usePolling<T>(load: () => Promise<T>, every = 0): {
  data: T | null
  error: string | null
  reload: () => void
} {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const loadRef = useRef(load)
  useEffect(() => {
    loadRef.current = load
  })

  const reload = useCallback(() => {
    loadRef.current()
      .then((d) => {
        setData(d)
        setError(null)
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
  }, [])

  useEffect(() => {
    reload()
    if (!every) return
    const timer = setInterval(reload, every)
    return () => clearInterval(timer)
  }, [reload, every])

  return { data, error, reload }
}

export const message = (e: unknown) => (e instanceof Error ? e.message : String(e))
