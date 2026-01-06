import { scamRules } from '../rules/scamRules'
import { ScamAnalysisResult } from '../types'

/**
 * Analyze URL for scam indicators using rule engine
 */
export function analyzeScam(url: string): ScamAnalysisResult {
  let score = 0
  const indicators: string[] = []

  for (const rule of scamRules) {
    try {
      if (rule.test(url)) {
        score += rule.weight
        indicators.push(rule.name)
      }
    } catch (error) {
      // Skip rule if it throws an error
      console.error(`Rule "${rule.name}" failed:`, error)
    }
  }

  // Cap score at 100
  return { 
    score: Math.min(score, 100), 
    indicators 
  }
}
