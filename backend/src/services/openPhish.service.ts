import { prisma } from '../config/db'

/**
 * Check URL against local OpenPhish database
 */
export async function checkOpenPhish(url: string): Promise<boolean> {
  try {
    // Normalize URL for lookup (remove trailing slash, lowercase)
    const normalizedUrl = url.toLowerCase().replace(/\/$/, '')
    
    const found = await prisma.openPhishEntry.findFirst({
      where: {
        OR: [
          { url: normalizedUrl },
          { url: normalizedUrl + '/' },
          { url: url }
        ]
      }
    })
    
    return !!found
  } catch (error) {
    console.error('OpenPhish lookup error:', error)
    return false
  }
}

/**
 * Check if domain exists in OpenPhish database
 */
export async function checkOpenPhishDomain(domain: string): Promise<boolean> {
  try {
    const found = await prisma.openPhishEntry.findFirst({
      where: {
        url: {
          contains: domain.toLowerCase()
        }
      }
    })
    
    return !!found
  } catch (error) {
    console.error('OpenPhish domain lookup error:', error)
    return false
  }
}
