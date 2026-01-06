import { app } from '../app'
import { checkUrlController, advancedAnalysisController } from '../controllers/checkUrl.controller'

// Basic URL check endpoint
app.post('/api/check-url', {
  schema: {
    body: {
      type: 'object',
      required: ['url'],
      properties: {
        url: { type: 'string' }
      }
    }
  }
}, checkUrlController)

// Advanced analysis endpoint (includes VirusTotal)
app.post('/api/advanced-analysis', {
  schema: {
    body: {
      type: 'object',
      required: ['url'],
      properties: {
        url: { type: 'string' }
      }
    }
  }
}, advancedAnalysisController)
