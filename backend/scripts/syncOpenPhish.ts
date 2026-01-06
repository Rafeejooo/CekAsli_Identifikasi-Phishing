/**
 * Script to sync OpenPhish feed to local database
 * Run with: npm run sync:openphish
 */
import 'dotenv/config'
import { PrismaClient } from '../src/generated/prisma'
import { PrismaPg } from '@prisma/adapter-pg'
import { Pool } from 'pg'

// Create PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
})

// Create Prisma adapter
const adapter = new PrismaPg(pool)

// Create Prisma client with adapter
const prisma = new PrismaClient({ adapter })

const OPENPHISH_FEED_URL = 'https://openphish.com/feed.txt'

async function syncOpenPhish() {
  console.log('🔄 Starting OpenPhish sync...')
  
  try {
    // Fetch the feed using native fetch
    console.log(`📥 Fetching feed from ${OPENPHISH_FEED_URL}`)
    const response = await fetch(OPENPHISH_FEED_URL, {
      method: 'GET',
    })
    
    if (!response.ok) {
      throw new Error(`Failed to fetch feed: HTTP ${response.status}`)
    }
    
    const body = await response.text()
    const urls = body
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && line.startsWith('http'))
    
    console.log(`📋 Found ${urls.length} URLs in feed`)
    
    if (urls.length === 0) {
      console.log('⚠️  No URLs found in feed')
      return
    }
    
    // Clear old entries (optional - comment out to keep history)
    console.log('🗑️  Clearing old entries...')
    await prisma.openPhishEntry.deleteMany({})
    
    // Insert new entries in batches
    const BATCH_SIZE = 500
    let inserted = 0
    
    for (let i = 0; i < urls.length; i += BATCH_SIZE) {
      const batch = urls.slice(i, i + BATCH_SIZE)
      
      await prisma.openPhishEntry.createMany({
        data: batch.map(url => ({ url })),
        skipDuplicates: true
      })
      
      inserted += batch.length
      console.log(`✅ Inserted ${inserted}/${urls.length} entries`)
    }
    
    console.log(`\n🎉 Sync complete! ${urls.length} phishing URLs loaded.`)
    
    // Show sample
    const sample = await prisma.openPhishEntry.findMany({ take: 5 })
    console.log('\n📌 Sample entries:')
    sample.forEach(entry => console.log(`   - ${entry.url}`))
    
  } catch (error) {
    console.error('❌ Sync failed:', error)
    process.exit(1)
  } finally {
    await prisma.$disconnect()
    await pool.end()
  }
}

// Run the sync
syncOpenPhish()
