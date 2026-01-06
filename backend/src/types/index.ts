// Type definitions for PhishGuard Backend

export interface Indicator {
  type: 'positive' | 'warning' | 'danger'
  text: string
}

export interface VirusTotalResult {
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
}

// Full VirusTotal report for AI analysis
export interface VirusTotalFullReport {
  url: string
  finalUrl: string
  title: string | null
  
  stats: VirusTotalResult
  
  // Categories from security vendors (e.g., {"Forcepoint": "business"})
  categories: Record<string, string>
  
  // Community reputation score (-100 to 100)
  reputation: number
  
  // Community votes
  votes: {
    harmless: number
    malicious: number
  }
  
  // Threat names detected by vendors
  threatNames: string[]
  
  // Last analysis timestamp
  lastAnalysisDate: string | null
  
  // HTTP response info
  httpInfo: {
    statusCode: number | null
    contentType: string | null
    contentLength: number | null
  }
  
  // URL redirection chain
  redirectionChain: string[]
  
  // Outgoing links found
  outgoingLinks: string[]
  
  // HTML meta tags
  htmlMeta: Record<string, string[]>
}

// AI Analysis input parameters
export interface AIAnalysisInput {
  url: string
  finalUrl: string
  
  // Basic analysis results
  basicScore: number
  basicVerdict: 'safe' | 'suspicious' | 'phishing'
  indicators: Indicator[]
  
  // VirusTotal data for AI context
  virusTotal?: VirusTotalFullReport | null
  
  // Additional context
  redirectChain?: string[]
  domainAge?: number | null
  sslInfo?: {
    valid: boolean
    issuer?: string
    expiresAt?: string
  } | null
}

// AI Analysis response
export interface AIAnalysisResult {
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  confidence: number // 0-100
  summary: string
  reasoning: string[]
  recommendations: string[]
  technicalDetails?: {
    suspiciousPatterns: string[]
    similarToKnownPhishing: boolean
    brandImpersonation: string | null
  }
}

export interface AdvancedAnalysis {
  virusTotal?: VirusTotalResult | null
  virusTotalFull?: VirusTotalFullReport | null
  aiAnalysis?: AIAnalysisResult | null
  analyzed: boolean
}

export interface CheckUrlResponse {
  status: 'safe' | 'suspicious' | 'phishing'
  score: number
  message: string
  indicators: Indicator[]
  analyzedUrl: string
  finalUrl: string
  redirectChain?: string[]
  sources: {
    googleSafeBrowsing: boolean
    openPhish: boolean
  }
  // Flag to indicate if advanced analysis is available
  advancedAvailable: boolean
  // Flag to indicate if AI analysis is available
  aiAvailable?: boolean
}

export interface AdvancedAnalysisResponse {
  status: 'safe' | 'suspicious' | 'phishing'
  score: number
  message: string
  indicators: Indicator[]
  virusTotal: VirusTotalResult | null
  virusTotalFull?: VirusTotalFullReport | null
  aiAnalysis?: AIAnalysisResult | null
  aiInputPreview?: AIAnalysisInput // Preview of what AI would receive
  analyzedUrl: string
  finalUrl?: string
  redirectChain?: string[]
}

export interface CheckUrlRequest {
  url: string
}

export interface ScamRule {
  name: string
  weight: number
  test: (url: string) => boolean
}

export interface ScamAnalysisResult {
  score: number
  indicators: string[]
}

export interface RedirectResult {
  chain: string[]
  finalUrl: string
}

export interface UrlValidation {
  valid: boolean
  error?: string
}
