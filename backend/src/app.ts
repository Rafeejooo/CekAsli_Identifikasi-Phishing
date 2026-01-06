import 'dotenv/config'
import Fastify from 'fastify'
import rateLimit from '@fastify/rate-limit'
import cors from '@fastify/cors'

export const app = Fastify({ 
  logger: {
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug'
  }
})

// Register plugins
app.register(cors, {
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com'] // Update with your production domain
    : true,
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true
})

app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  errorResponseBuilder: () => ({
    statusCode: 429,
    error: 'Too Many Requests',
    message: 'Terlalu banyak request. Silakan tunggu sebentar.'
  })
})

// Health check endpoint
app.get('/health', async () => ({
  status: 'ok',
  timestamp: new Date().toISOString()
}))
