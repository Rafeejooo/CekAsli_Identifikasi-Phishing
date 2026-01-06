import { app } from './app'
import './routes/checkUrl.route'

const PORT = Number(process.env.PORT) || 4001

const start = async () => {
  try {
    await app.listen({ 
      port: PORT,
      host: '0.0.0.0' 
    })
    console.log(`🚀 PhishGuard API running on http://localhost:${PORT}`)
    console.log(`📋 Health check: http://localhost:${PORT}/health`)
  } catch (err) {
    app.log.error(err)
    process.exit(1)
  }
}

start()
