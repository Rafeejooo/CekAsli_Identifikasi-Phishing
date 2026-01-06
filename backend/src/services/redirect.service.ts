import { RedirectResult } from '../types'

const MAX_REDIRECTS = 5
const TIMEOUT_MS = 5000

export interface RedirectResultExtended extends RedirectResult {
  unreachable: boolean
  error?: string
}

/**
 * Follow redirects and capture the full chain
 */
export async function expandRedirect(url: string): Promise<RedirectResultExtended> {
  const chain: string[] = [url]
  let current = url
  const visited = new Set<string>()
  let unreachable = false
  let errorMessage: string | undefined

  for (let i = 0; i < MAX_REDIRECTS; i++) {
    // Prevent infinite loops
    if (visited.has(current)) {
      break
    }
    visited.add(current)

    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS)

      const res = await fetch(current, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'PhishGuard/1.0 Security Scanner'
        }
      })

      clearTimeout(timeoutId)

      const location = res.headers.get('location')
      
      // No redirect, we've reached the final destination
      if (!location) {
        break
      }

      // Resolve relative URLs
      current = new URL(location, current).toString()
      chain.push(current)

    } catch (error: any) {
      // If request fails, mark as unreachable
      console.error(`Redirect expansion error at ${current}:`, error)
      
      // Check specific error types
      if (error?.cause?.code === 'ENOTFOUND') {
        unreachable = true
        errorMessage = 'Domain tidak ditemukan (tidak terdaftar atau sudah tidak aktif)'
      } else if (error?.cause?.code === 'ECONNREFUSED') {
        unreachable = true
        errorMessage = 'Koneksi ditolak oleh server'
      } else if (error?.name === 'AbortError') {
        unreachable = true
        errorMessage = 'Server tidak merespons (timeout)'
      } else {
        unreachable = true
        errorMessage = 'Gagal mengakses URL'
      }
      break
    }
  }

  return {
    chain,
    finalUrl: current,
    unreachable,
    error: errorMessage
  }
}
