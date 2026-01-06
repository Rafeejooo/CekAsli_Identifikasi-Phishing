# FINAL BACKEND FLOW – PHISHING LINK DETECTION

## 0️⃣ ENTRY POINT

- **Endpoint:** `POST /api/check-url`
- **Input:** `{ url: string }`
- **Output:** verdict + detail analisis

---

## 1️⃣ INPUT VALIDATION & SANITIZATION

**Validasi:**
- URL tidak kosong
- Format URL valid
- Scheme hanya `http` / `https`

**Reject:**
- Private IP
- Localhost
- `file://` / `ftp://` scheme

**Normalize:**
- Lowercase
- Decode URL encoding
- Remove tracking params
- Trim trailing slash

➡️ **Jika gagal → return error**

---

## 2️⃣ RATE LIMIT & ABUSE CHECK

- Limit per IP / session
- Block automated burst
- Optional captcha trigger

➡️ **Jika limit exceeded → stop**

---

## 3️⃣ DETECT URL SHORTENER

- Cocokkan domain dengan daftar shortener
- Jika match:
  - Tambahkan scam point
  - Flag `isShortened = true`

---

## 4️⃣ REDIRECT EXPANSION (CRITICAL STEP)

**Proses:**
- Gunakan HTTP HEAD
- Follow `Location` header
- Max redirect: 3–5 hop
- Timeout ketat
- Stop jika loop

**Output:**
- `redirect chain` (array)
- `final destination URL`

---

## 5️⃣ STATIC URL SCAM ANALYSIS (RULE ENGINE)

Analisis **original URL** + **redirect chain** + **final URL**

**Pola yang dicek:**
| Pattern | Description |
|---------|-------------|
| IP-based domain | Domain menggunakan IP langsung |
| Excessive subdomain | Terlalu banyak subdomain |
| Homoglyph | Karakter mirip (paypa1, g00gle) |
| Suspicious keyword | login, verify, secure, account, update |
| @ symbol | Karakter @ dalam URL |
| Risky TLD | TLD berisiko tinggi |

➡️ **Setiap match → tambah scam point**

---

## 6️⃣ DOMAIN INTELLIGENCE

**WHOIS Lookup (final domain):**
- Domain age
- Hidden registrant

**DNS / TLD Risk Analysis**

➡️ **Tambah scam point sesuai rule**

---

## 7️⃣ CORE THREAT INTEL CHECK (WAJIB)

### 7.1 Google Safe Browsing

- Check final URL
- Jika match:
  - `verdict = PHISHING`
  - Skip step lain
  - Return response

### 7.2 OpenPhish Lookup

- Check final URL ke local OpenPhish DB/feed
- Jika match:
  - `verdict = PHISHING`
  - Return response

---

## 8️⃣ INITIAL SCORING & VERDICT

**Hitung total scam point**

**Klasifikasi awal:**
| Score Range | Verdict |
|-------------|---------|
| 0-30 | SAFE |
| 31-60 | SUSPICIOUS |
| 61-100 | PHISHING |

➡️ **Simpan sebagai preliminary verdict**

---

## 9️⃣ CONDITIONAL ADVANCED VERIFICATION (OPTIONAL)

**Jalan HANYA JIKA:**
- `verdict = SUSPICIOUS`
- User unlock advanced scan (ads / premium)
- Admin / SOC mode

**Advanced Layer:**
- PhishTank lookup
- VirusTotal (selective)
- AI analysis (metadata only)

➡️ **Update skor & verdict**

---

## 🔟 FINAL DECISION LOGIC

| Source | Authority |
|--------|-----------|
| Google Safe Browsing / OpenPhish | Final authority |
| Advanced layer | Confidence booster |
| AI | Advisory (tidak override) |

---

## 1️⃣1️⃣ RESPONSE GENERATION

**Return JSON:**

```json
{
  "verdict": "SAFE | SUSPICIOUS | PHISHING",
  "riskScore": 0-100,
  "indicators": [
    {
      "type": "positive | warning | danger",
      "text": "Description of indicator"
    }
  ],
  "redirectChain": ["url1", "url2", "finalUrl"],
  "confidenceLevel": "low | medium | high",
  "analyzedUrl": "original input URL",
  "finalUrl": "final destination after redirects"
}
```

---

## 1️⃣2️⃣ LOGGING & CACHE

- Store result in DB
- Cache final verdict (TTL)
- Log suspicious & phishing URL

---

## FLOW DIAGRAM

```
┌─────────────────┐
│   POST /check   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 1. Validation   │──── Error ──→ Return 400
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 2. Rate Limit   │──── Exceeded ──→ Return 429
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 3. Shortener?   │──── Yes ──→ Add scam point
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 4. Expand Redir │──── Get final URL
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 5. Scam Rules   │──── Calculate points
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 6. Domain Intel │──── WHOIS, DNS check
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 7.1 Safe Browse │──── Match ──→ PHISHING
└────────┬────────┘
         │ No Match
         ▼
┌─────────────────┐
│ 7.2 OpenPhish   │──── Match ──→ PHISHING
└────────┬────────┘
         │ No Match
         ▼
┌─────────────────┐
│ 8. Score/Verdict│──── Calculate
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 9. Advanced?    │──── If SUSPICIOUS
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 10. Final Logic │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 11. Response    │──── Return JSON
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 12. Log & Cache │
└─────────────────┘
```

---

## FILE STRUCTURE

```
backend/
├── src/
│   ├── controllers/
│   │   └── checkUrl.controller.ts    # Entry point handler
│   ├── services/
│   │   ├── urlNormalizer.service.ts  # Step 1: Validation & Normalize
│   │   ├── redirect.service.ts       # Step 4: Redirect expansion
│   │   ├── scamAnalysis.service.ts   # Step 5: Rule engine
│   │   ├── safeBrowser.service.ts    # Step 7.1: Google Safe Browsing
│   │   └── openPhish.service.ts      # Step 7.2: OpenPhish lookup
│   ├── rules/
│   │   └── scamRules.ts              # Scam detection rules
│   ├── config/
│   │   ├── db.ts                     # Database connection
│   │   ├── redis.ts                  # Redis cache
│   │   └── env.ts                    # Environment variables
│   └── types/
│       └── index.ts                  # TypeScript interfaces
└── prisma/
    └── schema.prisma                 # Database schema
```
