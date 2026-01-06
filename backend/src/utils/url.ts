/**
 * URL utility functions
 */

// List of known URL shortener domains
export const URL_SHORTENERS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'goo.gl',
  'ow.ly',
  'buff.ly',
  'adf.ly',
  'j.mp',
  'tr.im',
  'v.gd',
  'cutt.ly',
  'shorturl.at',
  'rb.gy',
  'clck.ru',
  's.id',
  'rebrand.ly'
]

// List of risky TLDs often used in phishing
export const RISKY_TLDS = [
  '.tk',
  '.ml',
  '.ga',
  '.cf',
  '.gq',
  '.xyz',
  '.top',
  '.work',
  '.click',
  '.link',
  '.info',
  '.online',
  '.site',
  '.website',
  '.space',
  '.pw',
  '.cc',
  '.ws'
]

// Trusted/popular domains that are often impersonated
export const IMPERSONATED_BRANDS = [
  'paypal',
  'google',
  'facebook',
  'microsoft',
  'apple',
  'amazon',
  'netflix',
  'instagram',
  'whatsapp',
  'linkedin',
  'twitter',
  'dropbox',
  'chase',
  'wellsfargo',
  'bankofamerica',
  'citibank',
  'usbank'
]

/**
 * Extract domain from URL
 */
export function extractDomain(url: string): string {
  try {
    const parsed = new URL(url)
    return parsed.hostname
  } catch {
    return ''
  }
}

/**
 * Check if URL uses a known shortener
 */
export function isUrlShortener(url: string): boolean {
  const domain = extractDomain(url).toLowerCase()
  return URL_SHORTENERS.some(shortener => 
    domain === shortener || domain.endsWith('.' + shortener)
  )
}

/**
 * Check if domain has risky TLD
 */
export function hasRiskyTld(url: string): boolean {
  const domain = extractDomain(url).toLowerCase()
  return RISKY_TLDS.some(tld => domain.endsWith(tld))
}

/**
 * Count subdomains in URL
 */
export function countSubdomains(url: string): number {
  const domain = extractDomain(url)
  const parts = domain.split('.')
  // Subtract 2 for the main domain and TLD
  return Math.max(0, parts.length - 2)
}

/**
 * Check if URL contains IP address instead of domain
 */
export function isIpBasedUrl(url: string): boolean {
  const domain = extractDomain(url)
  // IPv4 pattern
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/
  // IPv6 pattern (simplified)
  const ipv6Pattern = /^\[.*\]$/
  return ipv4Pattern.test(domain) || ipv6Pattern.test(domain)
}

/**
 * Check if URL might be impersonating a popular brand
 */
export function checkBrandImpersonation(url: string): string | null {
  const domain = extractDomain(url).toLowerCase()
  
  for (const brand of IMPERSONATED_BRANDS) {
    // Check if brand name appears in domain but it's not the official domain
    if (domain.includes(brand) && !domain.endsWith(`.${brand}.com`)) {
      // Additional check for common impersonation patterns
      const officialDomains = [
        `${brand}.com`,
        `www.${brand}.com`,
        `${brand}.net`,
        `${brand}.org`
      ]
      
      if (!officialDomains.includes(domain)) {
        return brand
      }
    }
  }
  
  return null
}

/**
 * Detect homoglyph characters (look-alike characters)
 */
export function detectHomoglyphs(url: string): boolean {
  const domain = extractDomain(url).toLowerCase()
  
  // Homoglyph mapping: number/symbol -> letter they represent
  const homoglyphMap: Record<string, string> = {
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '6': 'g',
    '7': 't',
    '8': 'b',
    '9': 'g',
  }
  
  // Normalize domain by replacing homoglyphs with their letter equivalents
  let normalizedDomain = domain
  for (const [digit, letter] of Object.entries(homoglyphMap)) {
    normalizedDomain = normalizedDomain.split(digit).join(letter)
  }
  
  console.log(`[Homoglyph] Original: ${domain}, Normalized: ${normalizedDomain}`)
  
  // Check if normalized domain contains any impersonated brand
  for (const brand of IMPERSONATED_BRANDS) {
    // If brand appears in normalized domain but NOT in original domain
    if (normalizedDomain.includes(brand) && !domain.includes(brand)) {
      console.log(`[Homoglyph] Detected impersonation of: ${brand}`)
      return true
    }
  }
  
  // Also check for common letter substitution patterns
  const letterSubstitutions: [string, string][] = [
    ['rn', 'm'],   // 'rn' looks like 'm'
    ['vv', 'w'],   // 'vv' looks like 'w'
    ['cl', 'd'],   // 'cl' looks like 'd'
  ]
  
  let substitutedDomain = normalizedDomain
  for (const [pattern, replacement] of letterSubstitutions) {
    substitutedDomain = substitutedDomain.split(pattern).join(replacement)
  }
  
  for (const brand of IMPERSONATED_BRANDS) {
    if (substitutedDomain.includes(brand) && !domain.includes(brand)) {
      console.log(`[Homoglyph] Detected letter substitution impersonation of: ${brand}`)
      return true
    }
  }
  
  return false
}
