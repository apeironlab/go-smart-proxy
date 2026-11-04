import { useEffect, useRef, useState } from 'react'

/** The result of `load`, fetched now and then every `every` ms (null until the first answer). */
export function usePolled<T>(load: () => Promise<T>, every: number): T | null {
  const [data, setData] = useState<T | null>(null)
  const loadRef = useRef(load)
  useEffect(() => {
    loadRef.current = load
  })
  useEffect(() => {
    let alive = true
    const run = () => {
      loadRef.current().then((d) => { if (alive) setData(d) }).catch(() => {})
    }
    run()
    const timer = setInterval(run, every)
    return () => {
      alive = false
      clearInterval(timer)
    }
  }, [every])
  return data
}
