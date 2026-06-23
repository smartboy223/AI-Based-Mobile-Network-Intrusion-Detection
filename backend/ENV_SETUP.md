# Backend Environment Configuration Guide

**Location:** `backend/.env`  
**Status:** Optional (system works without it using defaults)

---

## Quick Setup

### Option A: Basic Setup (No API Key)
The system works out of the box with 41 hardcoded malicious IPs. You don't need to do anything.

### Option B: With VirusTotal API (Recommended)
Add IP reputation checking by configuring your VirusTotal API key.

---

## Step 1: Create .env File

1. Navigate to: `backend/` folder
2. Copy the template file:
   - From: `backend/.env.example`
   - To: `backend/.env`

Or create manually:

**Windows (PowerShell):**
```powershell
cd backend
Copy-Item .env.example .env
```

**Windows (Command Prompt):**
```cmd
cd backend
copy .env.example .env
```

**Mac/Linux:**
```bash
cd backend
cp .env.example .env
```

---

## Step 2: Add Your Configuration

Open `backend/.env` in a text editor and fill in the values:

### Example 1: Minimal (Default)
```env
VIRUSTOTAL_API_KEY=
VIRUSTOTAL_MIN_INTERVAL_MS=15000
```

### Example 2: With VirusTotal API
```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
VIRUSTOTAL_MIN_INTERVAL_MS=15000
```

### Example 3: Custom Ports
```env
VIRUSTOTAL_API_KEY=YOUR_KEY_HERE
VIRUSTOTAL_MIN_INTERVAL_MS=15000
MNIDS_PORT=8080
ML_SERVER_PORT=8788
ML_SERVER_URL=http://127.0.0.1:8788
```

---

## Configuration Options

### VIRUSTOTAL_API_KEY
- **Type:** String
- **Default:** (empty - uses hardcoded malicious IPs)
- **Required:** No
- **Get Key:** https://www.virustotal.com/
- **What It Does:** Enables IP reputation checking from VirusTotal
- **Free Tier:** ~4 requests per minute
- **Paid Tier:** Up to 500 requests per day

### VIRUSTOTAL_MIN_INTERVAL_MS
- **Type:** Number (milliseconds)
- **Default:** 15000 (15 seconds)
- **Minimum:** 1000 (1 second)
- **What It Does:** Rate limiting between VirusTotal API requests
- **Why:** Free tier allows ~4 requests/minute, so 15 seconds is safe
- **Note:** Increase if you hit rate limits; decrease if you have paid tier

### MNIDS_PORT
- **Type:** Number
- **Default:** 3000
- **What It Does:** Port for Express web server
- **When To Change:** If port 3000 is already in use
- **Example:** `MNIDS_PORT=8080`

### ML_SERVER_PORT
- **Type:** Number
- **Default:** 8787
- **What It Does:** Port for FastAPI ML service
- **Note:** START.bat hardcodes this, so this is informational
- **When To Change:** Only if running ML service on different port

### ML_SERVER_URL
- **Type:** URL String
- **Default:** http://127.0.0.1:8787
- **What It Does:** Backend URL for frontend to call ML service
- **When To Change:** If ML service runs on different machine/port
- **Example:** `ML_SERVER_URL=http://ml-server.example.com:8787`

### NODE_ENV
- **Type:** String (production | development)
- **Default:** production
- **What It Does:** Controls logging verbosity
- **production:** Quiet, optimized
- **development:** Verbose logging

### DEBUG
- **Type:** Boolean (true | false)
- **Default:** false
- **What It Does:** Enable detailed logging for debugging

---

## How the System Loads Configuration

### Priority Order (First Found Wins)

1. **backend/.env** ← Checked FIRST (your custom config)
2. **root/.env** ← Fallback (old location)
3. **Environment Variables** ← System variables
4. **Hardcoded Defaults** ← Built-in defaults

### Diagram

```
START.bat runs
     ↓
backend/server.js starts
     ↓
Check: backend/.env exists?
     ├─ YES → Load from backend/.env
     └─ NO → Check: root/.env exists?
               ├─ YES → Load from root/.env
               └─ NO → Use environment variables or defaults
```

---

## Getting a VirusTotal API Key

### Free Tier (Recommended for Testing)
1. Go to: https://www.virustotal.com/gui/home/upload
2. Click "Sign Up" (top right)
3. Create account with email
4. Go to: Settings → API Key (in sidebar)
5. Copy your API key
6. Paste into `backend/.env`

### Paid Tier (for Production)
- Contact: VirusTotal sales
- Higher rate limits
- Premium features
- Cost: Check VirusTotal pricing page

---

## Testing Configuration

### Without START.bat

If you want to test the backend directly:

```bash
cd backend
node server.js
```

The server will output:
```
[OK] Services running
Dashboard: http://localhost:3000/dashboard
```

If VirusTotal is configured, it shows:
```
[INFO] VirusTotal configured: yes
[INFO] Rate limit: 15 seconds
```

### With START.bat

Double-click `START.bat` from the project root. Everything loads automatically.

---

## Troubleshooting

### "VirusTotal not configured" error
- Check that `backend/.env` exists
- Check that `VIRUSTOTAL_API_KEY` is not empty
- Restart the server

### "API key invalid"
- Check that the key is correct (no spaces or typos)
- Visit https://www.virustotal.com/ and regenerate your key
- Update `backend/.env` and restart

### "Port 3000 already in use"
- Change `MNIDS_PORT` in `backend/.env` to different port (e.g., 8080)
- Restart START.bat

### Rate limit errors
- Increase `VIRUSTOTAL_MIN_INTERVAL_MS` (e.g., 20000 for 20 seconds)
- Or upgrade to paid VirusTotal tier

---

## Security Notes

### ✅ Best Practices
- ✅ Store secrets in `backend/.env` (not in code)
- ✅ Never commit `.env` to git
- ✅ Never share your `.env` file
- ✅ Use different keys for dev/production

### ⚠️ What NOT to Do
- ❌ Don't hardcode API keys in code
- ❌ Don't commit `.env` to version control
- ❌ Don't share `.env` in emails or forums
- ❌ Don't use same key across multiple projects

### Add to .gitignore

If you have git setup, add to `.gitignore`:

```
backend/.env
.env
.env.local
.env.*.local
```

---

## File Locations

| File | Location | Purpose |
|---|---|---|
| `.env.example` | `backend/.env.example` | Template (always keep this) |
| `.env` (your config) | `backend/.env` | Your actual secrets (create from example) |
| Old `.env` | `root/.env` | Legacy (still supported but backend/.env takes priority) |

---

## Example Scenarios

### Scenario 1: Local Development
```env
# backend/.env
VIRUSTOTAL_API_KEY=your_dev_api_key
VIRUSTOTAL_MIN_INTERVAL_MS=15000
NODE_ENV=development
DEBUG=true
```

### Scenario 2: Production
```env
# backend/.env
VIRUSTOTAL_API_KEY=your_prod_api_key
VIRUSTOTAL_MIN_INTERVAL_MS=15000
NODE_ENV=production
DEBUG=false
MNIDS_PORT=3000
```

### Scenario 3: No External APIs (Offline)
```env
# backend/.env
VIRUSTOTAL_API_KEY=
VIRUSTOTAL_MIN_INTERVAL_MS=15000
NODE_ENV=production
DEBUG=false
```

### Scenario 4: Custom Ports
```env
# backend/.env
VIRUSTOTAL_API_KEY=your_api_key
MNIDS_PORT=8080
ML_SERVER_PORT=8788
ML_SERVER_URL=http://localhost:8788
```

---

## What Gets Loaded?

When you run START.bat, the backend loads configuration in this order:

```javascript
// 1. Check backend/.env first
if (backend/.env exists) {
  load backend/.env
}
// 2. Fall back to root/.env
else if (root/.env exists) {
  load root/.env
}
// 3. Fall back to environment variables
else {
  use process.env.VARIABLE_NAME
}
// 4. Fall back to hardcoded defaults
else {
  VIRUSTOTAL_API_KEY = undefined (uses hardcoded IPs)
  MNIDS_PORT = 5003
  ML_SERVER_URL = http://127.0.0.1:8787
}
```

---

## Support

**Problem:** Not sure what to do?  
**Solution:** Press Enter at the startup key prompts. The system works with the bundled model and sample indicators.

**Problem:** Want to enable VirusTotal?  
**Solution:** Edit `backend/.env`, set `VIRUSTOTAL_API_KEY`, and restart `START.bat`.

**Problem:** Want to enable the AI assistant?  
**Solution:** Edit `backend/.env`, set `DEEPSEEK_API_KEY`, and restart `START.bat`.

---

**Version:** 1.0  
**Last Updated:** 2026-05-15
