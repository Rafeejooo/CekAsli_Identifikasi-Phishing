import { AIAnalysisInput, AIAnalysisResult } from '../types'

// AI Provider configuration
const AI_PROVIDER = process.env.AI_PROVIDER ?? 'openai' // 'openai' | 'anthropic' | 'gemini'
const AI_API_KEY = process.env.AI_API_KEY
const AI_MODEL = process.env.AI_MODEL ?? 'gpt-4o-mini'

// API endpoints for different providers
const AI_ENDPOINTS: Record<string, string> = {
  openai: 'https://api.openai.com/v1/chat/completions',
  anthropic: 'https://api.anthropic.com/v1/messages',
  gemini: 'https://generativelanguage.googleapis.com/v1beta/models'
}

/**
 * System prompt for AI phishing analysis
 */
const SYSTEM_PROMPT = `Anda adalah PhishGuard AI, seorang ahli keamanan siber yang menganalisis URL untuk mendeteksi phishing.

Tugas Anda:
1. Analisis URL dan data yang diberikan
2. Tentukan tingkat risiko: low, medium, high, atau critical
3. Berikan confidence score (0-100)
4. Jelaskan alasan keputusan Anda
5. Berikan rekomendasi keamanan

Output harus dalam format JSON dengan struktur:
{
  "riskLevel": "low|medium|high|critical",
  "confidence": 0-100,
  "summary": "Ringkasan singkat dalam bahasa Indonesia",
  "reasoning": ["Alasan 1", "Alasan 2", ...],
  "recommendations": ["Rekomendasi 1", "Rekomendasi 2", ...],
  "technicalDetails": {
    "suspiciousPatterns": ["Pattern 1", ...],
    "similarToKnownPhishing": true/false,
    "brandImpersonation": "Nama brand jika ada, atau null"
  }
}

Fokus pada:
- Domain yang mencurigakan (typosquatting, subdomain aneh)
- Redirect chains yang panjang
- Hasil scan VirusTotal
- Kategori dan reputasi dari vendor keamanan
- Pola URL yang umum digunakan phishing`

/**
 * Analyze URL with AI
 */
export async function analyzeWithAI(input: AIAnalysisInput): Promise<AIAnalysisResult | null> {
  if (!AI_API_KEY) {
    console.warn('AI API key not configured')
    return null
  }

  const userPrompt = buildUserPrompt(input)

  try {
    switch (AI_PROVIDER) {
      case 'openai':
        return await callOpenAI(userPrompt)
      case 'anthropic':
        return await callAnthropic(userPrompt)
      case 'gemini':
        return await callGemini(userPrompt)
      default:
        console.error(`Unknown AI provider: ${AI_PROVIDER}`)
        return null
    }
  } catch (error) {
    console.error('AI analysis error:', error)
    return null
  }
}

/**
 * Build user prompt from analysis input
 */
function buildUserPrompt(input: AIAnalysisInput): string {
  let prompt = `Analisis URL berikut untuk mendeteksi phishing:\n\n`
  prompt += `URL Asli: ${input.url}\n`
  prompt += `URL Akhir: ${input.finalUrl}\n`
  prompt += `Skor Awal: ${input.basicScore}/100\n`
  prompt += `Verdict Awal: ${input.basicVerdict}\n\n`

  if (input.redirectChain && input.redirectChain.length > 1) {
    prompt += `Redirect Chain:\n`
    input.redirectChain.forEach((url, i) => {
      prompt += `  ${i + 1}. ${url}\n`
    })
    prompt += '\n'
  }

  if (input.indicators.length > 0) {
    prompt += `Indikator yang Ditemukan:\n`
    input.indicators.forEach(ind => {
      const icon = ind.type === 'danger' ? '🔴' : ind.type === 'warning' ? '🟡' : '🟢'
      prompt += `  ${icon} ${ind.text}\n`
    })
    prompt += '\n'
  }

  if (input.virusTotal) {
    const vt = input.virusTotal
    prompt += `Data VirusTotal:\n`
    prompt += `  - Malicious: ${vt.stats.malicious}\n`
    prompt += `  - Suspicious: ${vt.stats.suspicious}\n`
    prompt += `  - Harmless: ${vt.stats.harmless}\n`
    prompt += `  - Undetected: ${vt.stats.undetected}\n`
    prompt += `  - Reputasi: ${vt.reputation}\n`
    
    if (vt.threatNames && vt.threatNames.length > 0) {
      prompt += `  - Threat Names: ${vt.threatNames.join(', ')}\n`
    }
    
    if (vt.categories && Object.keys(vt.categories).length > 0) {
      prompt += `  - Kategori: ${JSON.stringify(vt.categories)}\n`
    }
    
    if (vt.title) {
      prompt += `  - Page Title: ${vt.title}\n`
    }
  }

  prompt += `\nBerikan analisis lengkap dalam format JSON.`
  
  return prompt
}

/**
 * Call OpenAI API
 */
async function callOpenAI(userPrompt: string): Promise<AIAnalysisResult | null> {
  const response = await fetch(AI_ENDPOINTS.openai, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${AI_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: AI_MODEL,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: userPrompt }
      ],
      temperature: 0.3,
      response_format: { type: 'json_object' }
    })
  })

  if (!response.ok) {
    throw new Error(`OpenAI API error: ${response.status}`)
  }

  const data = await response.json() as any
  const content = data.choices?.[0]?.message?.content
  
  if (!content) return null
  
  return parseAIResponse(content)
}

/**
 * Call Anthropic Claude API
 */
async function callAnthropic(userPrompt: string): Promise<AIAnalysisResult | null> {
  const response = await fetch(AI_ENDPOINTS.anthropic, {
    method: 'POST',
    headers: {
      'x-api-key': AI_API_KEY!,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: AI_MODEL || 'claude-3-haiku-20240307',
      max_tokens: 1024,
      system: SYSTEM_PROMPT,
      messages: [
        { role: 'user', content: userPrompt }
      ]
    })
  })

  if (!response.ok) {
    throw new Error(`Anthropic API error: ${response.status}`)
  }

  const data = await response.json() as any
  const content = data.content?.[0]?.text
  
  if (!content) return null
  
  return parseAIResponse(content)
}

/**
 * Call Google Gemini API
 */
async function callGemini(userPrompt: string): Promise<AIAnalysisResult | null> {
  const model = AI_MODEL || 'gemini-1.5-flash'
  const endpoint = `${AI_ENDPOINTS.gemini}/${model}:generateContent?key=${AI_API_KEY}`
  
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      contents: [{
        parts: [{
          text: `${SYSTEM_PROMPT}\n\n${userPrompt}`
        }]
      }],
      generationConfig: {
        temperature: 0.3,
        responseMimeType: 'application/json'
      }
    })
  })

  if (!response.ok) {
    throw new Error(`Gemini API error: ${response.status}`)
  }

  const data = await response.json() as any
  const content = data.candidates?.[0]?.content?.parts?.[0]?.text
  
  if (!content) return null
  
  return parseAIResponse(content)
}

/**
 * Parse AI response to AIAnalysisResult
 */
function parseAIResponse(content: string): AIAnalysisResult | null {
  try {
    // Try to extract JSON from response
    let jsonStr = content
    
    // Handle markdown code blocks
    const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/)
    if (jsonMatch) {
      jsonStr = jsonMatch[1]
    }
    
    const parsed = JSON.parse(jsonStr.trim())
    
    // Validate required fields
    if (!parsed.riskLevel || !parsed.summary) {
      return null
    }
    
    return {
      riskLevel: parsed.riskLevel,
      confidence: parsed.confidence ?? 70,
      summary: parsed.summary,
      reasoning: parsed.reasoning ?? [],
      recommendations: parsed.recommendations ?? [],
      technicalDetails: parsed.technicalDetails ?? {
        suspiciousPatterns: [],
        similarToKnownPhishing: false,
        brandImpersonation: null
      }
    }
  } catch (error) {
    console.error('Failed to parse AI response:', error)
    return null
  }
}

/**
 * Check if AI analysis is available
 */
export function isAIAvailable(): boolean {
  return !!AI_API_KEY
}
