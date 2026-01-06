import { VirusTotalResult, VirusTotalFullReport } from '../types'

const VT_API = 'https://www.virustotal.com/api/v3'
const API_KEY = process.env.VIRUS_TOTAL_KEY

/**
 * Encode URL to base64 URL-safe format for VirusTotal API
 */
function encodeUrlId(url: string): string {
  return Buffer.from(url)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Sleep helper for polling
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * Check URL with VirusTotal API
 * Returns analysis stats or null if not available
 */
export async function checkVirusTotal(url: string): Promise<VirusTotalResult | null> {
  if (!API_KEY) {
    console.warn('VirusTotal API key not configured')
    return null
  }

  const urlId = encodeUrlId(url)

  try {
    // 1. Try GET existing analysis
    console.log(`[VirusTotal] Checking URL: ${url}`)
    console.log(`[VirusTotal] URL ID: ${urlId}`)
    
    const response = await fetch(`${VT_API}/urls/${urlId}`, {
      method: 'GET',
      headers: { 
        'x-apikey': API_KEY,
        'Accept': 'application/json'
      }
    })

    console.log(`[VirusTotal] GET Response status: ${response.status}`)

    if (response.ok) {
      const body = await response.json() as any
      const stats = body.data?.attributes?.last_analysis_stats

      if (stats) {
        console.log(`[VirusTotal] Found existing analysis:`, stats)
        return {
          malicious: stats.malicious ?? 0,
          suspicious: stats.suspicious ?? 0,
          harmless: stats.harmless ?? 0,
          undetected: stats.undetected ?? 0
        }
      }
    }

    // 2. If not found (404) → submit URL for scanning and wait for result
    if (response.status === 404) {
      console.log(`[VirusTotal] URL not found, submitting for scan...`)
      const analysisId = await submitUrlForScan(url)
      
      if (analysisId) {
        // Wait and poll for result
        console.log(`[VirusTotal] Submitted, analysis ID: ${analysisId}`)
        const result = await pollAnalysisResult(analysisId)
        if (result) return result
      }
    }

    return null

  } catch (error) {
    console.error('[VirusTotal] Check error:', error)
    return null
  }
}

/**
 * Submit URL to VirusTotal for scanning
 */
async function submitUrlForScan(url: string): Promise<string | null> {
  if (!API_KEY) return null

  try {
    const response = await fetch(`${VT_API}/urls`, {
      method: 'POST',
      headers: {
        'x-apikey': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`
    })

    console.log(`[VirusTotal] Submit response status: ${response.status}`)

    if (response.ok) {
      const body = await response.json() as any
      console.log(`[VirusTotal] Submit response:`, JSON.stringify(body).slice(0, 200))
      return body.data?.id ?? null
    }

    const errorText = await response.text()
    console.error(`[VirusTotal] Submit error: ${response.status} - ${errorText}`)
    return null
  } catch (error) {
    console.error('[VirusTotal] Submit error:', error)
    return null
  }
}

/**
 * Poll for analysis result
 */
async function pollAnalysisResult(analysisId: string, maxAttempts = 3): Promise<VirusTotalResult | null> {
  if (!API_KEY) return null

  for (let i = 0; i < maxAttempts; i++) {
    await sleep(3000) // Wait 3 seconds between attempts
    
    try {
      console.log(`[VirusTotal] Polling attempt ${i + 1}/${maxAttempts}...`)
      
      const response = await fetch(`${VT_API}/analyses/${analysisId}`, {
        method: 'GET',
        headers: { 
          'x-apikey': API_KEY,
          'Accept': 'application/json'
        }
      })

      if (response.ok) {
        const body = await response.json() as any
        const status = body.data?.attributes?.status
        const stats = body.data?.attributes?.stats

        console.log(`[VirusTotal] Analysis status: ${status}`)

        if (status === 'completed' && stats) {
          console.log(`[VirusTotal] Analysis completed:`, stats)
          return {
            malicious: stats.malicious ?? 0,
            suspicious: stats.suspicious ?? 0,
            harmless: stats.harmless ?? 0,
            undetected: stats.undetected ?? 0
          }
        }
      }
    } catch (error) {
      console.error(`[VirusTotal] Poll error:`, error)
    }
  }

  console.log(`[VirusTotal] Analysis still in progress after ${maxAttempts} attempts`)
  return null
}

/**
 * Get full URL report from VirusTotal (for AI analysis)
 * Includes categories, reputation, and detailed scan results
 */
export async function getVirusTotalFullReport(url: string): Promise<VirusTotalFullReport | null> {
  if (!API_KEY) {
    console.warn('VirusTotal API key not configured')
    return null
  }

  const urlId = encodeUrlId(url)

  try {
    const response = await fetch(`${VT_API}/urls/${urlId}`, {
      method: 'GET',
      headers: { 
        'x-apikey': API_KEY,
        'Accept': 'application/json'
      }
    })

    if (!response.ok) return null

    const body = await response.json() as any
    const attrs = body.data?.attributes

    if (!attrs) return null

    return {
      url: attrs.url,
      finalUrl: attrs.last_final_url ?? attrs.url,
      title: attrs.title ?? null,
      
      stats: {
        malicious: attrs.last_analysis_stats?.malicious ?? 0,
        suspicious: attrs.last_analysis_stats?.suspicious ?? 0,
        harmless: attrs.last_analysis_stats?.harmless ?? 0,
        undetected: attrs.last_analysis_stats?.undetected ?? 0
      },
      
      // Categories assigned by security vendors
      categories: attrs.categories ?? {},
      
      // Reputation score (-100 to 100, lower is worse)
      reputation: attrs.reputation ?? 0,
      
      // Total votes from community
      votes: {
        harmless: attrs.total_votes?.harmless ?? 0,
        malicious: attrs.total_votes?.malicious ?? 0
      },
      
      // Threat names detected
      threatNames: attrs.threat_names ?? [],
      
      // Last analysis date
      lastAnalysisDate: attrs.last_analysis_date 
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
      
      // HTTP response info
      httpInfo: {
        statusCode: attrs.last_http_response_code ?? null,
        contentType: attrs.last_http_response_content_type ?? null,
        contentLength: attrs.last_http_response_content_length ?? null
      },
      
      // Redirection chain
      redirectionChain: attrs.redirection_chain ?? [],
      
      // Outgoing links found on the page
      outgoingLinks: attrs.outgoing_links ?? [],
      
      // HTML meta tags
      htmlMeta: attrs.html_meta ?? {}
    }
  } catch (error) {
    console.error('VirusTotal full report error:', error)
    return null
  }
}
