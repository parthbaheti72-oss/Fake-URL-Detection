# URLGuard — Advanced Fake URL & Phishing Detection System

> A multi-layered cybersecurity tool that detects phishing URLs using heuristic analysis and VirusTotal API integration.

---

## Overview

URLGuard is an intelligent phishing URL detection system that goes beyond simple blacklist lookups. It uses a **13-check heuristic engine** combined with **VirusTotal's 70+ antivirus engines** to detect fake URLs — including brand-new ones not yet in any database.

### Key Highlights

- **13 detection algorithms** — typosquatting, leet speak, brand impersonation, keyword analysis, combo patterns
- **30 brands monitored** — Google, PayPal, Amazon, Facebook, Netflix, SBI, HDFC, and more
- **Dual scoring engine** — Heuristics (60%) + VirusTotal (40%) with adaptive weighting
- **Bulk Scanner** — scan up to 50 URLs at once with CSV report export
- **Zero false positives** — tested with 48 URLs (18 legit + 30 fake), 100% accuracy

---

## Features

### Single URL Scanner
- Real-time URL analysis with instant verdict
- Visual domain similarity comparison with animated bars
- Attack type identification (Leet Speak, Typosquatting, Brand Impersonation, etc.)
- Color-coded results: ✅ SAFE / ⚠️ SUSPICIOUS / 🚨 FAKE

### Bulk CSV Scanner
- Upload CSV or paste up to 50 URLs
- Summary dashboard (Safe / Suspicious / Malicious counts)
- Downloadable CSV report with full details
- Automatic deduplication and validation

---

## Tech Stack

| Component    | Technology                          |
|--------------|-------------------------------------|
| Backend      | Python 3.12+, Flask                 |
| Detection    | Custom heuristic engine (13 checks) |
| External API | VirusTotal API v3                   |
| Frontend     | HTML5, CSS3, Vanilla JavaScript     |
| Data Export  | CSV module                          |

---

## Project Structure

```
URLGuard/
├── app.py              # Flask backend — API routes, scoring engine, bulk scan
├── detector.py         # Core heuristic engine — 13 detection checks
├── api_checks.py       # VirusTotal API integration
├── index.html          # Frontend — tab navigation, forms, result templates
├── style.css           # Styling — responsive design, cards, tables
├── script.js           # Frontend logic — API calls, CSV export, rendering
├── .env                # API keys (not committed to git)
└── requirements.txt    # Python dependencies
```

---

## Installation

### Prerequisites
- Python 3.10+
- pip
- VirusTotal API key (free at [virustotal.com](https://www.virustotal.com))

### Setup

```bash
# 1. Install dependencies
pip install flask flask-cors requests python-dotenv

# 2. Create .env file
echo "VIRUSTOTAL_API_KEY=your_key_here" > .env

# 3. Start the server
python app.py

# 4. Open index.html in your browser
```

The backend runs on `http://localhost:5000`. Open `index.html` directly or via VS Code Live Server.

---

## Detection Algorithms

| ## | Check             | Score      | Description                                       |
|----|-------------------|------------|---------------------------------------------------|
| 01 | Typosquatting     | +25 to +50 | Levenshtein distance comparison against 30 brands |
| 02 | Leet Speak        | +25 to +50 | Decodes 0→o, 1→i, 3→e, 4→a, 5→s, etc.             |
| 03 | Brand in Domain   | +35        | Detects brand names in hyphenated segments        |
| 04 | Brand in Subdomain| +40        | Catches paypal.evil.com pattern                   |
| 05 | Suspicious TLD    | +20        | Flags .xyz, .tk, .ml, .ga, .cf, .club, etc.       |
| 06 | No HTTPS          | +10        | Missing encryption                                |
| 07 | IP Address        | +30        | Raw IP instead of domain name                     |
| 08 | Phishing Keywords | +10 to +25 | 25 keywords (login, verify, secure, etc.)         |
| 09 | Multiple Hyphens  | +10        | 2+ hyphens in domain                              |
| 10 | Long Domain       | +10        | Domain >30 characters                             |
| 11 | Digits in Domain  | +5         | Numbers in domain name                            |
| 12 | @ Symbol / Hex    | +10 to +20 | URL obfuscation techniques                        |
| 13 | Combo Patterns    | +10 to +15 | Brand + suspicious TLD = high threat              |

---

## Scoring System

```
If VirusTotal has data:
    Final Score = (Heuristic × 60%) + (VirusTotal × 40%)

If VirusTotal has no data:
    Final Score = Heuristic × 90%

If VirusTotal flags 2+ engines:
    Final Score = max(calculated, 75)
```

| Score | Verdict          |
|-------|------------------|
| 0–20  | SAFE             |
| 21–50 | SUSPICIOUS       |
| 51–100| FAKE / MALICIOUS |

---

## API Endpoints

| Method | Endpoint                | Description                |
|--------|-------------------------|----------------------------|
| `GET`  | `/`                     | Health check               |
| `POST` | `/analyze`              | Analyze single URL         |
| `GET`  | `/history`              | Last 10 scan results       |
| `GET`  | `/brands`               | List monitored brands      |
| `POST` | `/bulk-scan`            | Scan up to 50 URLs         |
| `POST` | `/bulk-scan/export-csv` | Scan + download CSV report |

---

## Test Results

Tested with 48 URLs (18 legitimate + 30 fake):

| URL                       | Score | Verdict       |
|---------------------------|-------|---------------|
| google.com                | 0     | ✅ SAFE       |
| g00gle-secure.xyz/login   | 100   | 🚨 FAKE       |
| paypal.secure-login.xyz   | 100   | 🚨 FAKE       |
| faceb00k-login.tk         | 100   | 🚨 FAKE       |
| netflix-account-verify.ml | 100   | 🚨 FAKE       |
| secure-sbi-netbanking.tk  | 100   | 🚨 FAKE       |
| arnazon.com               | 50    | ⚠️ SUSPICIOUS |
| paypal.com                | 0     | ✅ SAFE       |
| spotify.com               | 0     | ✅ SAFE       |

**Accuracy: 100% | False Positives: 0% | False Negatives: 0%**

---

## Future Scope

1. Machine Learning classifier trained on phishing datasets
2. Browser extension for real-time protection
3. QR Code URL scanner
4. Visual screenshot analysis for page similarity
5. Email link scanner
6. Dashboard analytics with charts

---

## License

This project is developed for academic purposes as part of the BCA program.

---

**Built with Python + Flask | Heuristic AI + VirusTotal Intelligence**
