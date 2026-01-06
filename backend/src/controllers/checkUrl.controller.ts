import { FastifyRequest, FastifyReply } from 'fastify'
import { expandRedirect } from '../services/redirect.service'
import { analyzeScam } from '../services/scamAnalysis.service'
import { checkSafeBrowsing } from '../services/safeBrowser.service'
import { checkOpenPhish } from '../services/openPhish.service'
import { checkVirusTotal, getVirusTotalFullReport } from '../services/virusTotal.service'
import { normalizeUrl, validateUrl } from '../services/urlNormalizer.service'
import { analyzeWithAI, isAIAvailable } from '../services/aiAnalysis.service'
import { prisma } from '../config/db'
import { 
  CheckUrlResponse, 
  Indicator, 
  AdvancedAnalysisResponse,
  VirusTotalFullReport,
  AIAnalysisInput,
  AIAnalysisResult
} from '../types'

export async function checkUrlController(
  req: FastifyRequest<{ Body: { url: string } }>,
  reply: FastifyReply
) {
  const inputUrl = req.body.url

  // 0. Validate input URL
  const validation = validateUrl(inputUrl)
  if (!validation.valid) {
    return reply.status(400).send({
      error: 'Invalid URL',
      message: validation.error
    })
  }

  try {
    // 1. Normalize URL
    const normalizedUrl = normalizeUrl(inputUrl)

    // 2. Redirect expansion
    const redirectResult = await expandRedirect(normalizedUrl)
    const { chain, finalUrl, unreachable, error: redirectError } = redirectResult

    // 3. Rule-based analysis (check all URLs in chain)
    const ruleResult = analyzeScam(finalUrl)
    
    // Also analyze original URL for additional indicators
    const originalAnalysis = analyzeScam(normalizedUrl)
    const combinedIndicators: Indicator[] = [
      ...ruleResult.indicators.map(text => ({ type: 'warning' as const, text })),
      ...originalAnalysis.indicators
        .filter(i => !ruleResult.indicators.includes(i))
        .map(text => ({ type: 'warning' as const, text }))
    ]

    // Add unreachable domain indicator (highly suspicious)
    let unreachableScore = 0
    if (unreachable) {
      combinedIndicators.push({ 
        type: 'danger', 
        text: redirectError || 'Domain tidak dapat diakses' 
      })
      unreachableScore = 50 // Suspicious - domain doesn't exist or is down
    }

    // 4. Google Safe Browsing (check final URL) - skip if unreachable
    let gsbHit = false
    if (!unreachable) {
      gsbHit = await checkSafeBrowsing(finalUrl)
      if (gsbHit) {
        combinedIndicators.push({ type: 'danger', text: 'Ditemukan di Google Safe Browsing' })
      }
    }

    // 5. OpenPhish (check final URL)
    const openPhishHit = await checkOpenPhish(finalUrl)
    if (openPhishHit) {
      combinedIndicators.push({ type: 'danger', text: 'Ditemukan di database OpenPhish' })
    }

    // 6. Calculate final score
    let score = Math.max(ruleResult.score, originalAnalysis.score) + unreachableScore
    if (gsbHit) score += 80
    if (openPhishHit) score += 100

    // Cap score at 100
    score = Math.min(score, 100)

    // 7. Determine verdict
    let verdict: 'SAFE' | 'SUSPICIOUS' | 'PHISHING'
    if (gsbHit || openPhishHit || score >= 70) {
      verdict = 'PHISHING'
    } else if (score >= 40) {
      verdict = 'SUSPICIOUS'
    } else {
      verdict = 'SAFE'
    }

    // Add positive indicators for safe URLs
    if (verdict === 'SAFE') {
      combinedIndicators.push(
        { type: 'positive', text: 'Tidak ditemukan di database phishing' },
        { type: 'positive', text: 'URL lolos pemeriksaan keamanan' }
      )
    }

    // 8. Store result in database
    await prisma.urlCheck.create({
      data: {
        originalUrl: inputUrl,
        finalUrl,
        verdict,
        score
      }
    })

    // 9. Build response
    const response: CheckUrlResponse = {
      status: verdict.toLowerCase() as 'safe' | 'suspicious' | 'phishing',
      score,
      message: getVerdictMessage(verdict),
      indicators: combinedIndicators,
      analyzedUrl: inputUrl,
      finalUrl,
      redirectChain: chain.length > 1 ? chain : undefined,
      sources: {
        googleSafeBrowsing: gsbHit,
        openPhish: openPhishHit
      },
      // Advanced analysis is available if VirusTotal API key is configured
      advancedAvailable: !!process.env.VIRUS_TOTAL_KEY,
      // AI analysis is available if AI API key is configured
      aiAvailable: isAIAvailable()
    }

    return reply.send(response)

  } catch (error) {
    req.log.error(error, 'Error analyzing URL')
    return reply.status(500).send({
      error: 'Analysis failed',
      message: 'Terjadi kesalahan saat menganalisis URL. Silakan coba lagi.'
    })
  }
}

/**
 * Advanced Analysis Controller - includes VirusTotal scan and AI analysis preparation
 */
export async function advancedAnalysisController(
  req: FastifyRequest<{ Body: { url: string; includeAI?: boolean } }>,
  reply: FastifyReply
) {
  const { url: inputUrl, includeAI = false } = req.body

  // Validate input URL
  const validation = validateUrl(inputUrl)
  if (!validation.valid) {
    return reply.status(400).send({
      error: 'Invalid URL',
      message: validation.error
    })
  }

  try {
    // Normalize URL
    const normalizedUrl = normalizeUrl(inputUrl)

    // Expand redirects to get final URL
    const { chain, finalUrl } = await expandRedirect(normalizedUrl)

    // Run scam analysis for context
    const ruleResult = analyzeScam(finalUrl)
    const basicIndicators: Indicator[] = ruleResult.indicators.map(text => ({ 
      type: 'warning' as const, 
      text 
    }))

    // VirusTotal full report (includes more data for AI)
    const vtFullReport = await getVirusTotalFullReport(finalUrl)
    
    // Also get basic stats for backward compatibility
    const vtResult = vtFullReport?.stats ?? await checkVirusTotal(finalUrl)

    const indicators: Indicator[] = [...basicIndicators]
    let additionalScore = 0

    if (vtResult) {
      // Add VirusTotal indicators
      if (vtResult.malicious > 0) {
        additionalScore += Math.min(vtResult.malicious * 10, 100)
        indicators.push({
          type: 'danger',
          text: `VirusTotal: ${vtResult.malicious} vendor mendeteksi sebagai malicious`
        })
      }
      
      if (vtResult.suspicious > 0) {
        additionalScore += Math.min(vtResult.suspicious * 5, 50)
        indicators.push({
          type: 'warning',
          text: `VirusTotal: ${vtResult.suspicious} vendor mendeteksi sebagai suspicious`
        })
      }

      if (vtResult.harmless > 0 && vtResult.malicious === 0 && vtResult.suspicious === 0) {
        indicators.push({
          type: 'positive',
          text: `VirusTotal: ${vtResult.harmless} vendor menandai sebagai aman`
        })
      }

      if (vtResult.undetected > 0) {
        indicators.push({
          type: 'positive',
          text: `VirusTotal: ${vtResult.undetected} vendor tidak mendeteksi ancaman`
        })
      }

      // Add reputation info if available
      if (vtFullReport?.reputation !== undefined) {
        if (vtFullReport.reputation < -20) {
          indicators.push({
            type: 'danger',
            text: `Reputasi komunitas: ${vtFullReport.reputation} (buruk)`
          })
          additionalScore += 30
        } else if (vtFullReport.reputation < 0) {
          indicators.push({
            type: 'warning',
            text: `Reputasi komunitas: ${vtFullReport.reputation} (kurang baik)`
          })
          additionalScore += 15
        } else if (vtFullReport.reputation > 20) {
          indicators.push({
            type: 'positive',
            text: `Reputasi komunitas: ${vtFullReport.reputation} (baik)`
          })
        }
      }

      // Add threat names if any
      if (vtFullReport?.threatNames && vtFullReport.threatNames.length > 0) {
        indicators.push({
          type: 'danger',
          text: `Ancaman terdeteksi: ${vtFullReport.threatNames.slice(0, 3).join(', ')}`
        })
        additionalScore += 50
      }

      // Add category info
      if (vtFullReport?.categories) {
        const categories = Object.values(vtFullReport.categories)
        const dangerousCategories = categories.filter(c => 
          /phishing|malware|spam|scam|fraud|suspicious/i.test(c)
        )
        if (dangerousCategories.length > 0) {
          indicators.push({
            type: 'danger',
            text: `Kategori berbahaya: ${dangerousCategories.join(', ')}`
          })
          additionalScore += 40
        }
      }
    } else {
      indicators.push({
        type: 'warning',
        text: 'VirusTotal: URL belum pernah dianalisis atau sedang dalam proses scan'
      })
    }

    // Calculate combined score
    const baseScore = ruleResult.score
    const score = Math.min(baseScore + additionalScore, 100)

    // Determine verdict
    let verdict: 'SAFE' | 'SUSPICIOUS' | 'PHISHING'
    if (vtResult && vtResult.malicious > 2) {
      verdict = 'PHISHING'
    } else if (vtResult && vtResult.malicious > 0) {
      verdict = 'SUSPICIOUS'
    } else if (vtResult && vtResult.suspicious > 0) {
      verdict = 'SUSPICIOUS'
    } else if (score >= 70) {
      verdict = 'PHISHING'
    } else if (score >= 40) {
      verdict = 'SUSPICIOUS'
    } else {
      verdict = 'SAFE'
    }

    // Prepare AI analysis input (for future AI integration)
    const aiInput: AIAnalysisInput = {
      url: inputUrl,
      finalUrl,
      basicScore: baseScore,
      basicVerdict: verdict.toLowerCase() as 'safe' | 'suspicious' | 'phishing',
      indicators,
      virusTotal: vtFullReport,
      redirectChain: chain.length > 1 ? chain : undefined
    }

    // TODO: If includeAI is true, call AI service here
    let aiAnalysis: AIAnalysisResult | null = null
    if (includeAI && isAIAvailable()) {
      aiAnalysis = await analyzeWithAI(aiInput)
    } else if (includeAI) {
      // Use mock AI if real AI is not available
      aiAnalysis = generateMockAIAnalysis(verdict, vtResult, indicators)
    }

    const response: AdvancedAnalysisResponse = {
      status: verdict.toLowerCase() as 'safe' | 'suspicious' | 'phishing',
      score,
      message: getAdvancedVerdictMessage(verdict, vtResult),
      indicators,
      virusTotal: vtResult,
      virusTotalFull: vtFullReport,
      aiAnalysis,
      aiInputPreview: includeAI ? undefined : aiInput, // Show what AI would receive
      analyzedUrl: inputUrl,
      finalUrl,
      redirectChain: chain.length > 1 ? chain : undefined
    }

    return reply.send(response)

  } catch (error) {
    req.log.error(error, 'Error in advanced analysis')
    return reply.status(500).send({
      error: 'Advanced analysis failed',
      message: 'Terjadi kesalahan saat melakukan analisis lanjutan. Silakan coba lagi.'
    })
  }
}

/**
 * Generate mock AI analysis (placeholder until AI service is implemented)
 */
function generateMockAIAnalysis(
  verdict: string, 
  vtResult: any, 
  indicators: Indicator[]
): AIAnalysisResult {
  const dangerCount = indicators.filter(i => i.type === 'danger').length
  const warningCount = indicators.filter(i => i.type === 'warning').length
  
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low'
  if (verdict === 'PHISHING' || dangerCount >= 2) {
    riskLevel = 'critical'
  } else if (verdict === 'SUSPICIOUS' || dangerCount >= 1) {
    riskLevel = 'high'
  } else if (warningCount >= 2) {
    riskLevel = 'medium'
  }

  return {
    riskLevel,
    confidence: vtResult ? 85 : 60,
    summary: verdict === 'PHISHING' 
      ? 'URL ini memiliki karakteristik yang sangat mencurigakan dan kemungkinan besar adalah phishing.'
      : verdict === 'SUSPICIOUS'
      ? 'URL ini menunjukkan beberapa tanda mencurigakan yang perlu diwaspadai.'
      : 'URL ini tampak aman berdasarkan analisis yang dilakukan.',
    reasoning: indicators.map(i => i.text),
    recommendations: [
      verdict !== 'SAFE' ? 'Jangan memasukkan informasi pribadi atau kredensial' : 'URL aman untuk dikunjungi',
      verdict !== 'SAFE' ? 'Verifikasi URL dengan sumber resmi' : 'Tetap waspada terhadap permintaan data sensitif',
      'Gunakan password manager untuk menghindari phishing',
      'Aktifkan 2FA untuk akun penting'
    ],
    technicalDetails: {
      suspiciousPatterns: indicators.filter(i => i.type !== 'positive').map(i => i.text),
      similarToKnownPhishing: vtResult?.malicious > 0,
      brandImpersonation: null
    }
  }
}

function getVerdictMessage(verdict: string): string {
  switch (verdict) {
    case 'PHISHING':
      return 'BAHAYA! URL ini terdeteksi sebagai phishing'
    case 'SUSPICIOUS':
      return 'URL ini mencurigakan, berhati-hatilah'
    case 'SAFE':
    default:
      return 'URL ini aman untuk dikunjungi'
  }
}

function getAdvancedVerdictMessage(verdict: string, vtResult: any): string {
  if (!vtResult) {
    return 'URL sedang diproses oleh VirusTotal. Coba lagi dalam beberapa saat.'
  }
  
  switch (verdict) {
    case 'PHISHING':
      return `BAHAYA! ${vtResult.malicious} vendor keamanan mendeteksi URL ini berbahaya`
    case 'SUSPICIOUS':
      return `WASPADA! ${vtResult.suspicious} vendor keamanan menandai URL ini mencurigakan`
    case 'SAFE':
    default:
      return 'URL ini tidak terdeteksi berbahaya oleh VirusTotal'
  }
}
