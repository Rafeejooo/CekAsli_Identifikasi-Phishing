import { UrlValidation } from '../types'

// Tracking parameters to remove
const TRACKING_PARAMS = [
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'fbclid',
  'gclid',
  'ref',
  'source',
  'mc_eid',
  'mc_cid'
]

// Private IP ranges
const PRIVATE_IP_PATTERNS = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^127\./,
  /^0\./,
  /^localhost$/i
]

/**
 * Validate URL before processing
 */
export function validateUrl(input: string): UrlValidation {
  if (!input || typeof input !== 'string') {
    return { valid: false, error: 'URL tidak boleh kosong' }
  }

  const trimmed = input.trim()
  
  if (trimmed.length === 0) {
    return { valid: false, error: 'URL tidak boleh kosong' }
  }

  if (trimmed.length > 2048) {
    return { valid: false, error: 'URL terlalu panjang (maksimal 2048 karakter)' }
  }

  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch {
    return { valid: false, error: 'Format URL tidak valid' }
  }

  // Only allow http and https
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, error: 'URL harus menggunakan http atau https' }
  }

  // Block private IPs and localhost
  const hostname = parsed.hostname.toLowerCase()
  for (const pattern of PRIVATE_IP_PATTERNS) {
    if (pattern.test(hostname)) {
      return { valid: false, error: 'URL dengan IP private atau localhost tidak diizinkan' }
    }
  }

  return { valid: true }
}

/**
 * Normalize URL for consistent analysis
 */
export function normalizeUrl(input: string): string {
  const url = new URL(input.trim())
  
  // Remove hash/fragment
  url.hash = ''
  
  // Remove tracking parameters
  for (const param of TRACKING_PARAMS) {
    url.searchParams.delete(param)
  }
  
  // Lowercase hostname
  let normalized = url.toString().toLowerCase()
  
  // Remove trailing slash (except for root path)
  if (normalized.endsWith('/') && url.pathname !== '/') {
    normalized = normalized.slice(0, -1)
  }
  
  return normalized
}

/**
 * Extract parts of URL for analysis
 */
export function parseUrlParts(input: string) {
  const url = new URL(input)
  
  return {
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port,
    pathname: url.pathname,
    search: url.search,
    hash: url.hash,
    origin: url.origin
  }
}
