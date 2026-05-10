# Email Analyzer Web

A free, public email security analysis tool.

## Features
- Header & routing analysis
- SPF / DKIM / DMARC authentication check
- Phishing detection (30+ patterns)
- IOC extraction (URLs, IPs, hashes, domains)
- Attachment analysis with hashing
- Threat scoring 0-100
- Export: JSON, CSV, TXT

## Deploy to Render.com (Free)

1. Push this folder to a GitHub repo
2. Go to render.com → New → Web Service
3. Connect your GitHub repo
4. Settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app --bind 0.0.0.0:$PORT`
5. Click Deploy

## Run Locally
```bash
pip install flask gunicorn
python app.py
# Open http://localhost:5000
```
