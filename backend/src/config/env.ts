import { z } from 'zod'

// Environment variables schema
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().default('4001').transform(Number),
  DATABASE_URL: z.string(),
  REDIS_URL: z.string().optional(),
  GOOGLE_SAFE_BROWSING_KEY: z.string().optional(),
  VIRUS_TOTAL_KEY: z.string().optional(),
})

// Parse and validate environment variables
function validateEnv() {
  const parsed = envSchema.safeParse(process.env)
  
  if (!parsed.success) {
    console.error('❌ Invalid environment variables:')
    console.error(parsed.error.flatten().fieldErrors)
    throw new Error('Invalid environment variables')
  }
  
  return parsed.data
}

export const env = validateEnv()
