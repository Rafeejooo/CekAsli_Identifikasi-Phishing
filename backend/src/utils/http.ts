interface HttpOptions {
  method?: 'GET' | 'POST' | 'HEAD'
  headers?: Record<string, string>
  body?: string
  timeout?: number
}

interface HttpResponse {
  statusCode: number
  headers: Headers
  body: string
}

/**
 * Make an HTTP request with proper error handling
 */
export async function httpRequest(
  url: string, 
  options: HttpOptions = {}
): Promise<HttpResponse> {
  const {
    method = 'GET',
    headers = {},
    body,
    timeout = 10000
  } = options

  try {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), timeout)

    const res = await fetch(url, {
      method,
      headers: {
        'User-Agent': 'PhishGuard/1.0 Security Scanner',
        ...headers
      },
      body,
      signal: controller.signal
    })

    clearTimeout(timeoutId)
    const responseBody = await res.text()

    return {
      statusCode: res.status,
      headers: res.headers,
      body: responseBody
    }
  } catch (error) {
    throw new Error(`HTTP request failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Check if a URL is reachable
 */
export async function isUrlReachable(url: string, timeout: number = 5000): Promise<boolean> {
  try {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), timeout)

    const res = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal
    })

    clearTimeout(timeoutId)
    return res.status >= 200 && res.status < 400
  } catch {
    return false
  }
}
