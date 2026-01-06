import { useState } from 'react'
import './App.css'

// API Base URL - ubah ke production URL saat deploy
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:4001'

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  
  // Advanced analysis states
  const [advancedResult, setAdvancedResult] = useState(null)
  const [advancedLoading, setAdvancedLoading] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)

  // Validate URL format
  const isValidUrl = (string) => {
    try {
      const url = new URL(string)
      return url.protocol === 'http:' || url.protocol === 'https:'
    } catch (_) {
      return false
    }
  }

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setResult(null)

    // Validate input
    if (!url.trim()) {
      setError('Mohon masukkan URL yang ingin diperiksa')
      return
    }

    if (!isValidUrl(url)) {
      setError('Format URL tidak valid. Pastikan URL dimulai dengan http:// atau https://')
      return
    }

    setLoading(true)

    try {
      // Call backend API
      const response = await fetch(`${API_BASE_URL}/api/check-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url.trim() }),
      })

      const data = await response.json()

      if (!response.ok) {
        // Handle error response from backend
        throw new Error(data.message || 'Terjadi kesalahan saat menganalisis URL')
      }

      // Set result from API response
      setResult(data)
      
    } catch (err) {
      console.error('API Error:', err)
      
      // Check if it's a network error
      if (err.name === 'TypeError' && err.message.includes('fetch')) {
        setError('Tidak dapat terhubung ke server. Pastikan backend sedang berjalan.')
      } else {
        setError(err.message || 'Terjadi kesalahan saat menganalisis URL. Silakan coba lagi.')
      }
    } finally {
      setLoading(false)
    }
  }

  // Copy result to clipboard
  const copyResult = () => {
    if (!result) return
    const text = `URL: ${url}\nStatus: ${result.status.toUpperCase()}\nSkor Risiko: ${result.score}/100\n\nIndikator:\n${result.indicators.map(i => `- ${i.text}`).join('\n')}`
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // Run advanced analysis (VirusTotal + AI)
  const runAdvancedAnalysis = async () => {
    if (!url.trim()) return
    
    setAdvancedLoading(true)
    setShowAdvanced(true)
    
    try {
      const response = await fetch(`${API_BASE_URL}/api/advanced-analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          url: url.trim(),
          includeAI: true  // Request AI analysis
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.message || 'Gagal melakukan analisis lanjutan')
      }

      setAdvancedResult(data)
      
    } catch (err) {
      console.error('Advanced Analysis Error:', err)
      setAdvancedResult({
        error: true,
        message: err.message || 'Terjadi kesalahan saat melakukan analisis lanjutan'
      })
    } finally {
      setAdvancedLoading(false)
    }
  }

  // Reset form
  const resetForm = () => {
    setUrl('')
    setResult(null)
    setError('')
    setAdvancedResult(null)
    setShowAdvanced(false)
  }

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div className="logo">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M12 16V12M12 8H12.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            <span>CekAsli</span>
          </div>
          <nav className="nav">
            <a href="#how-it-works">Cara Kerja</a>
            <a href="#education">Edukasi</a>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <main className="main">
        <section className="hero">
          <div className="hero-content">
            <div className="hero-badge">🛡️ Perlindungan dari Phishing</div>
            <h1>Periksa Keamanan Link Sebelum Diklik</h1>
            <p className="hero-description">
              Jangan jadi korban phishing! Analisis URL secara instan dan dapatkan 
              informasi lengkap tentang keamanan sebuah link.
            </p>

            {/* URL Input Form */}
            <form onSubmit={handleSubmit} className="url-form">
              <div className="input-wrapper">
                <svg className="input-icon" viewBox="0 0 24 24" fill="none">
                  <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="Masukkan URL yang ingin diperiksa..."
                  className={`url-input ${error ? 'error' : ''}`}
                  disabled={loading}
                />
                <button type="submit" className="check-button" disabled={loading}>
                  {loading ? (
                    <span className="loading-spinner"></span>
                  ) : (
                    <>
                      <svg viewBox="0 0 24 24" fill="none">
                        <path d="M21 21L15 15M17 10C17 13.866 13.866 17 10 17C6.13401 17 3 13.866 3 10C3 6.13401 6.13401 3 10 3C13.866 3 17 6.13401 17 10Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                      </svg>
                      Periksa
                    </>
                  )}
                </button>
              </div>
              {error && <p className="error-message">{error}</p>}
            </form>

            {/* Loading State */}
            {loading && (
              <div className="loading-state">
                <div className="loading-animation">
                  <div className="loading-ring"></div>
                  <svg className="loading-shield" viewBox="0 0 24 24" fill="none">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="2"/>
                  </svg>
                </div>
                <p>Menganalisis URL...</p>
                <div className="loading-steps">
                  <span className="step active">Validasi URL</span>
                  <span className="step active">Analisis Struktur</span>
                  <span className="step">Cek Reputasi</span>
                  <span className="step">Kalkulasi Skor</span>
                </div>
              </div>
            )}

            {/* Result Section */}
            {result && !loading && (
              <div className={`result-card ${result.status}`}>
                <div className="result-header">
                  <div className="result-icon">
                    {result.status === 'safe' && (
                      <svg viewBox="0 0 24 24" fill="none">
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                        <polyline points="22,4 12,14.01 9,11.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    )}
                    {result.status === 'suspicious' && (
                      <svg viewBox="0 0 24 24" fill="none">
                        <path d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    )}
                    {result.status === 'phishing' && (
                      <svg viewBox="0 0 24 24" fill="none">
                        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2"/>
                        <line x1="15" y1="9" x2="9" y2="15" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                        <line x1="9" y1="9" x2="15" y2="15" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                      </svg>
                    )}
                  </div>
                  <div className="result-status">
                    <span className="status-badge">{
                      result.status === 'safe' ? 'AMAN' : 
                      result.status === 'suspicious' ? 'MENCURIGAKAN' : 
                      'PHISHING'
                    }</span>
                    <p className="result-message">{result.message}</p>
                  </div>
                </div>

                <div className="result-url">
                  <span className="label">URL yang dianalisis:</span>
                  <span className="url-text">{url}</span>
                </div>

                <div className="risk-score">
                  <div className="score-header">
                    <span>Skor Risiko</span>
                    <span className="score-value">{result.score}/100</span>
                  </div>
                  <div className="score-bar">
                    <div 
                      className="score-fill" 
                      style={{ width: `${result.score}%` }}
                    ></div>
                  </div>
                  <div className="score-labels">
                    <span>Aman</span>
                    <span>Mencurigakan</span>
                    <span>Berbahaya</span>
                  </div>
                </div>

                <div className="indicators">
                  <h4>Indikator Analisis:</h4>
                  <ul className="indicator-list">
                    {result.indicators.map((indicator, index) => (
                      <li key={index} className={`indicator ${indicator.type}`}>
                        {indicator.type === 'positive' && (
                          <svg viewBox="0 0 24 24" fill="none">
                            <polyline points="20,6 9,17 4,12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                          </svg>
                        )}
                        {indicator.type === 'warning' && (
                          <svg viewBox="0 0 24 24" fill="none">
                            <path d="M12 9v4M12 17h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                          </svg>
                        )}
                        {indicator.type === 'danger' && (
                          <svg viewBox="0 0 24 24" fill="none">
                            <line x1="18" y1="6" x2="6" y2="18" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                            <line x1="6" y1="6" x2="18" y2="18" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                          </svg>
                        )}
                        <span>{indicator.text}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="result-actions">
                  <button className="action-btn copy" onClick={copyResult}>
                    <svg viewBox="0 0 24 24" fill="none">
                      <rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2"/>
                      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" strokeWidth="2"/>
                    </svg>
                    {copied ? 'Tersalin!' : 'Salin Hasil'}
                  </button>
                  <button className="action-btn report">
                    <svg viewBox="0 0 24 24" fill="none">
                      <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z" stroke="currentColor" strokeWidth="2"/>
                      <line x1="4" y1="22" x2="4" y2="15" stroke="currentColor" strokeWidth="2"/>
                    </svg>
                    Laporkan False Positive
                  </button>
                  <button className="action-btn new-check" onClick={resetForm}>
                    <svg viewBox="0 0 24 24" fill="none">
                      <polyline points="23,4 23,10 17,10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                    Periksa URL Lain
                  </button>
                </div>

                {/* Advanced Analysis Section */}
                {result.advancedAvailable && !showAdvanced && (
                  <div className="advanced-analysis-prompt">
                    <div className="advanced-info">
                      <svg viewBox="0 0 24 24" fill="none">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="2"/>
                        <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                      <div>
                        <h4>Analisis Lanjutan Tersedia</h4>
                        <p>Lakukan pemindaian mendalam dengan 70+ vendor keamanan melalui VirusTotal</p>
                      </div>
                    </div>
                    <button 
                      className="action-btn advanced" 
                      onClick={runAdvancedAnalysis}
                      disabled={advancedLoading}
                    >
                      <svg viewBox="0 0 24 24" fill="none">
                        <circle cx="11" cy="11" r="8" stroke="currentColor" strokeWidth="2"/>
                        <path d="M21 21l-4.35-4.35" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                        <path d="M11 8v6M8 11h6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                      </svg>
                      Analisis Lanjutan
                    </button>
                  </div>
                )}

                {/* Advanced Analysis Loading */}
                {advancedLoading && (
                  <div className="advanced-loading">
                    <div className="loading-spinner"></div>
                    <p>Memindai dengan VirusTotal...</p>
                    <span className="loading-note">Ini mungkin memakan waktu beberapa detik</span>
                  </div>
                )}

                {/* Advanced Analysis Result */}
                {showAdvanced && advancedResult && !advancedLoading && (
                  <div className={`advanced-result ${advancedResult.error ? 'error' : advancedResult.status}`}>
                    <div className="advanced-header">
                      <svg viewBox="0 0 24 24" fill="none">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="2"/>
                        {advancedResult.status === 'safe' && (
                          <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        )}
                      </svg>
                      <h4>Hasil Analisis Lanjutan (VirusTotal)</h4>
                    </div>
                    
                    {advancedResult.error ? (
                      <p className="advanced-error">{advancedResult.message}</p>
                    ) : (
                      <>
                        <p className="advanced-message">{advancedResult.message}</p>
                        
                        {advancedResult.virusTotal ? (
                          <div className="vt-stats">
                            <div className={`vt-stat ${advancedResult.virusTotal.malicious > 0 ? 'danger' : 'neutral'}`}>
                              <span className="vt-number">{advancedResult.virusTotal.malicious}</span>
                              <span className="vt-label">Malicious</span>
                            </div>
                            <div className={`vt-stat ${advancedResult.virusTotal.suspicious > 0 ? 'warning' : 'neutral'}`}>
                              <span className="vt-number">{advancedResult.virusTotal.suspicious}</span>
                              <span className="vt-label">Suspicious</span>
                            </div>
                            <div className={`vt-stat ${advancedResult.virusTotal.harmless > 0 ? 'safe' : 'neutral'}`}>
                              <span className="vt-number">{advancedResult.virusTotal.harmless}</span>
                              <span className="vt-label">Harmless</span>
                            </div>
                            <div className="vt-stat neutral">
                              <span className="vt-number">{advancedResult.virusTotal.undetected}</span>
                              <span className="vt-label">Undetected</span>
                            </div>
                          </div>
                        ) : (
                          <div className="vt-no-data">
                            <svg viewBox="0 0 24 24" fill="none" style={{width: '24px', height: '24px', margin: '0 auto 0.5rem', display: 'block', color: '#f59e0b'}}>
                              <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2"/>
                              <path d="M12 8v4M12 16h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                            </svg>
                            <p>URL sedang diproses oleh VirusTotal. Coba lagi dalam beberapa saat.</p>
                          </div>
                        )}

                        {advancedResult.indicators && advancedResult.indicators.length > 0 && (
                          <ul className="indicator-list">
                            {advancedResult.indicators.map((indicator, index) => (
                              <li key={index} className={`indicator ${indicator.type}`}>
                                {indicator.type === 'positive' && (
                                  <svg viewBox="0 0 24 24" fill="none">
                                    <polyline points="20,6 9,17 4,12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                                  </svg>
                                )}
                                {indicator.type === 'warning' && (
                                  <svg viewBox="0 0 24 24" fill="none">
                                    <path d="M12 9v4M12 17h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                                  </svg>
                                )}
                                {indicator.type === 'danger' && (
                                  <svg viewBox="0 0 24 24" fill="none">
                                    <line x1="18" y1="6" x2="6" y2="18" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                                    <line x1="6" y1="6" x2="18" y2="18" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                                  </svg>
                                )}
                                <span>{indicator.text}</span>
                              </li>
                            ))}
                          </ul>
                        )}

                        {/* AI Analysis Section */}
                        {advancedResult.aiAnalysis && (
                          <div className="ai-analysis-section">
                            <div className="ai-header">
                              <svg viewBox="0 0 24 24" fill="none">
                                <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                              </svg>
                              <h5>Analisis AI</h5>
                              <span className={`ai-risk-badge ${advancedResult.aiAnalysis.riskLevel}`}>
                                {advancedResult.aiAnalysis.riskLevel === 'critical' ? 'Risiko Kritis' :
                                 advancedResult.aiAnalysis.riskLevel === 'high' ? 'Risiko Tinggi' :
                                 advancedResult.aiAnalysis.riskLevel === 'medium' ? 'Risiko Sedang' : 'Risiko Rendah'}
                              </span>
                            </div>
                            
                            <div className="ai-confidence">
                              <span>Tingkat Keyakinan:</span>
                              <div className="confidence-bar">
                                <div 
                                  className="confidence-fill" 
                                  style={{ width: `${advancedResult.aiAnalysis.confidence}%` }}
                                ></div>
                              </div>
                              <span className="confidence-value">{advancedResult.aiAnalysis.confidence}%</span>
                            </div>
                            
                            <p className="ai-summary">{advancedResult.aiAnalysis.summary}</p>
                            
                            {advancedResult.aiAnalysis.recommendations && advancedResult.aiAnalysis.recommendations.length > 0 && (
                              <div className="ai-recommendations">
                                <h6>Rekomendasi:</h6>
                                <ul>
                                  {advancedResult.aiAnalysis.recommendations.map((rec, idx) => (
                                    <li key={idx}>{rec}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </section>

        {/* How It Works Section */}
        <section id="how-it-works" className="how-it-works">
          <h2>Bagaimana Cara Kerjanya?</h2>
          <div className="steps-grid">
            <div className="step-card">
              <div className="step-number">1</div>
              <div className="step-icon">
                <svg viewBox="0 0 24 24" fill="none">
                  <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                  <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                </svg>
              </div>
              <h3>Masukkan URL</h3>
              <p>Tempelkan link yang ingin Anda periksa ke dalam kolom input</p>
            </div>
            <div className="step-card">
              <div className="step-number">2</div>
              <div className="step-icon">
                <svg viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2"/>
                  <path d="M12 6v6l4 2" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                </svg>
              </div>
              <h3>Analisis Otomatis</h3>
              <p>Sistem menganalisis struktur URL, reputasi domain, dan threat intelligence</p>
            </div>
            <div className="step-card">
              <div className="step-number">3</div>
              <div className="step-icon">
                <svg viewBox="0 0 24 24" fill="none">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="2"/>
                </svg>
              </div>
              <h3>Lihat Hasil</h3>
              <p>Dapatkan laporan lengkap dengan skor risiko dan indikator keamanan</p>
            </div>
          </div>
        </section>

        {/* Education Section */}
        <section id="education" className="education">
          <h2>Pelajari Tentang Phishing</h2>
          <div className="education-grid">
            <div className="edu-card">
              <div className="edu-icon danger">
                <svg viewBox="0 0 24 24" fill="none">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke="currentColor" strokeWidth="2"/>
                </svg>
              </div>
              <h3>Apa itu Phishing?</h3>
              <p>Phishing adalah upaya penipuan untuk mendapatkan informasi sensitif seperti kata sandi dan data kartu kredit dengan menyamar sebagai entitas terpercaya.</p>
            </div>
            <div className="edu-card">
              <div className="edu-icon warning">
                <svg viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2"/>
                  <path d="M12 16v-4M12 8h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                </svg>
              </div>
              <h3>Tanda-tanda Phishing</h3>
              <ul>
                <li>URL yang mirip tapi tidak sama (contoh: paypa1.com)</li>
                <li>Domain dengan subdomain berlebihan</li>
                <li>Permintaan informasi sensitif mendadak</li>
                <li>Pesan yang menciptakan urgensi palsu</li>
              </ul>
            </div>
            <div className="edu-card">
              <div className="edu-icon safe">
                <svg viewBox="0 0 24 24" fill="none">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="2"/>
                  <polyline points="9,12 11,14 15,10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </div>
              <h3>Cara Melindungi Diri</h3>
              <ul>
                <li>Selalu periksa URL sebelum mengklik</li>
                <li>Jangan klik link dari sumber tidak dikenal</li>
                <li>Gunakan autentikasi dua faktor (2FA)</li>
                <li>Perbarui browser dan antivirus secara rutin</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Stats Section */}
        <section className="stats">
          <div className="stats-grid">
            <div className="stat-item">
              <span className="stat-number">1M+</span>
              <span className="stat-label">URL Dianalisis</span>
            </div>
            <div className="stat-item">
              <span className="stat-number">50K+</span>
              <span className="stat-label">Phishing Terdeteksi</span>
            </div>
            <div className="stat-item">
              <span className="stat-number">99.2%</span>
              <span className="stat-label">Tingkat Akurasi</span>
            </div>
            <div className="stat-item">
              <span className="stat-number">&lt;2s</span>
              <span className="stat-label">Waktu Analisis</span>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="footer">
        <div className="footer-content">
          <div className="footer-brand">
            <div className="logo">
              <svg viewBox="0 0 24 24" fill="none">
                <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="currentColor" strokeWidth="2"/>
                <path d="M12 16V12M12 8H12.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              </svg>
              <span>CekAsli</span>
            </div>
            <p>Melindungi Anda dari ancaman phishing dengan teknologi analisis canggih.</p>
          </div>
          <div className="footer-links">
            <div className="footer-column">
              <h4>Navigasi</h4>
              <a href="#how-it-works">Cara Kerja</a>
              <a href="#education">Edukasi</a>
            </div>
            <div className="footer-column">
              <h4>Legal</h4>
              <a href="#">Kebijakan Privasi</a>
              <a href="#">Syarat & Ketentuan</a>
            </div>
          </div>
        </div>
        <div className="footer-bottom">
          <p>&copy; 2026 CekAsli. Dibuat untuk keamanan digital Anda.</p>
        </div>
      </footer>
    </div>
  )
}

export default App
