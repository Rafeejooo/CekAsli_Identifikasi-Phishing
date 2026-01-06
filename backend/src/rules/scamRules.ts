import { ScamRule } from '../types'
import { 
  isUrlShortener, 
  hasRiskyTld, 
  countSubdomains, 
  isIpBasedUrl,
  checkBrandImpersonation,
  detectHomoglyphs,
  extractDomain
} from '../utils/url'

export const scamRules: ScamRule[] = [
  {
    name: 'URL menggunakan layanan shortener',
    weight: 15,
    test: (url: string) => isUrlShortener(url)
  },
  {
    name: 'URL menggunakan alamat IP langsung',
    weight: 35,
    test: (url: string) => isIpBasedUrl(url)
  },
  {
    name: 'Terlalu banyak subdomain (lebih dari 3)',
    weight: 25,
    test: (url: string) => countSubdomains(url) > 3
  },
  {
    name: 'Menggunakan TLD berisiko tinggi',
    weight: 20,
    test: (url: string) => hasRiskyTld(url)
  },
  {
    name: 'Mengandung keyword mencurigakan (login, verify, secure, account, register)',
    weight: 15,
    test: (url: string) => {
      const keywords = [
        'login', 'signin', 'sign-in', 'log-in',
        'verify', 'verification', 'validate',
        'secure', 'security',
        'account', 'myaccount', 'my-account',
        'update', 'upgrade',
        'confirm', 'confirmation',
        'password', 'passwd', 'pwd',
        'banking', 'bank',
        'register', 'signup', 'sign-up',
        'recover', 'recovery', 'reset',
        'unlock', 'suspended', 'limited',
        'wallet', 'payment', 'invoice'
      ]
      const lowerUrl = url.toLowerCase()
      return keywords.some(kw => lowerUrl.includes(kw))
    }
  },
  {
    name: 'Mengandung karakter @ dalam URL',
    weight: 30,
    test: (url: string) => {
      try {
        const parsed = new URL(url)
        // Check if @ is in the path/query, not the auth part
        return parsed.pathname.includes('@') || parsed.search.includes('@')
      } catch {
        return url.includes('@')
      }
    }
  },
  {
    name: 'Terdeteksi impersonasi brand populer',
    weight: 40,
    test: (url: string) => checkBrandImpersonation(url) !== null
  },
  {
    name: 'Menggunakan karakter homoglyph (karakter mirip)',
    weight: 35,
    test: (url: string) => detectHomoglyphs(url)
  },
  {
    name: 'Panjang URL berlebihan (lebih dari 100 karakter)',
    weight: 10,
    test: (url: string) => url.length > 100
  },
  {
    name: 'Mengandung banyak angka di domain',
    weight: 15,
    test: (url: string) => {
      const domain = extractDomain(url)
      const digits = domain.replace(/[^0-9]/g, '')
      return digits.length > 4
    }
  },
  {
    name: 'Menggunakan HTTPS dengan sertifikat gratis (Let\'s Encrypt pattern)',
    weight: 5,
    test: (url: string) => {
      // URLs that look like they're trying too hard to appear secure
      const lowerUrl = url.toLowerCase()
      return lowerUrl.includes('secure-') || 
             lowerUrl.includes('ssl-') || 
             lowerUrl.includes('https-')
    }
  },
  {
    name: 'Mengandung double dash atau underscore berlebihan',
    weight: 10,
    test: (url: string) => {
      const domain = extractDomain(url)
      return domain.includes('--') || (domain.match(/_/g) || []).length > 2
    }
  }
]
