import Redis from 'ioredis'

let redis: Redis | null = null

export function getRedis(): Redis | null {
  if (!process.env.REDIS_URL) {
    return null
  }
  
  if (!redis) {
    redis = new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 3,
      lazyConnect: true,
    })
    
    redis.on('error', (err) => {
      console.error('Redis connection error:', err)
    })
    
    redis.on('connect', () => {
      console.log('✅ Redis connected')
    })
  }
  
  return redis
}

// Cache helpers
export async function getCache(key: string): Promise<string | null> {
  const client = getRedis()
  if (!client) return null
  
  try {
    return await client.get(key)
  } catch {
    return null
  }
}

export async function setCache(key: string, value: string, ttlSeconds: number = 3600): Promise<void> {
  const client = getRedis()
  if (!client) return
  
  try {
    await client.setex(key, ttlSeconds, value)
  } catch (err) {
    console.error('Cache set error:', err)
  }
}

// Generate cache key for URL check
export function getCacheKey(url: string): string {
  return `phishguard:url:${Buffer.from(url).toString('base64')}`
}
