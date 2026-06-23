# Backend Configuration

This folder contains the backend services for the intrusion detection system.

## Quick Configuration

### 1. Create `.env` file

```bash
cd backend
cp .env.example .env
```

### 2. Edit `backend/.env`

Add your VirusTotal API key (optional):

```env
VIRUSTOTAL_API_KEY=YOUR_API_KEY_HERE
```

### 3. Run

```bash
npm start  # or START.bat from project root
```

---

## Services

### Express Server (port 5003)
**File:** `server.js`

- Serves React dashboard
- Routes API calls
- Proxies VirusTotal API
- Manages PCAP uploads

### FastAPI ML Service (port 8787)
**File:** `inference_server.py`

- AutoEncoder model
- Isolation Forest model
- Random Forest model
- Ensemble voting

---

## Configuration Files

| File | Purpose |
|---|---|
| `.env.example` | Template (always keep this) |
| `.env` | Your actual configuration (create from example) |
| `ENV_SETUP.md` | Detailed setup guide |
| `README.md` | This file |

---

## Environment Variables

All variables are optional. System works with defaults.

```env
# DeepSeek API (optional)
DEEPSEEK_API_KEY=

# VirusTotal API (optional)
VIRUSTOTAL_API_KEY=YOUR_KEY_HERE
VIRUSTOTAL_MIN_INTERVAL_MS=15000

# Ports (change if already in use)
MNIDS_PORT=5003
ML_SERVER_PORT=8787
ML_SERVER_URL=http://127.0.0.1:8787

# Debugging
NODE_ENV=production
DEBUG=false
```

See `ENV_SETUP.md` for complete documentation.

---

## How Configuration Loads

1. Check `backend/.env` (priority)
2. Fall back to `root/.env`
3. Fall back to environment variables
4. Fall back to hardcoded defaults

---

## Getting VirusTotal API Key

Free: https://www.virustotal.com/
Paid: https://www.virustotal.com/pricing/

---

**See ENV_SETUP.md for detailed configuration guide**
