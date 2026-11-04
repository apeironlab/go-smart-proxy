export const fmtDate = (v?: string | number | null) => {
  if (v === undefined || v === null || v === 0 || v === '') return '-'
  const d = typeof v === 'number' ? new Date(v * 1000) : new Date(v)
  return Number.isNaN(d.getTime()) ? '-' : d.toLocaleString()
}

export function fmtDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d) return `${d}d ${h}h`
  if (h) return `${h}h ${m}m`
  return `${m}m`
}

export function fmtAgo(v: string | number | undefined, now = Date.now()): string {
  if (!v) return '-'
  const t = typeof v === 'number' ? v * 1000 : new Date(v).getTime()
  return fmtDuration((now - t) / 1000)
}
