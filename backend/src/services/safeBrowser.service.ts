import { request } from 'undici'

const SAFE_BROWSING_API = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

interface SafeBrowsingResponse {
  matches?: Array<{
    threatType: string
    platformType: string
    threat: { url: string }
  }>
}

/**
 * Check URL against Google Safe Browsing API
 */
export async function checkSafeBrowsing(url: string): Promise<boolean> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY
  
  // Skip if no API key configured
  if (!apiKey) {
    console.warn('Google Safe Browsing API key not configured')
    return false
  }

  try {
    const res = await request(`${SAFE_BROWSING_API}?key=${apiKey}`, {
      method: 'POST',
      body: JSON.stringify({
        client: {
          clientId: 'phishguard',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION'
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      }),
      headers: {
        'Content-Type': 'application/json'
      },
      bodyTimeout: 10000,
      headersTimeout: 10000
    })

    const body = await res.body.json() as SafeBrowsingResponse
    
    // If matches array exists and has items, URL is flagged
    return !!(body.matches && body.matches.length > 0)

  } catch (error) {
    console.error('Google Safe Browsing API error:', error)
    // Return false on error to avoid false positives
    return false
  }
}
