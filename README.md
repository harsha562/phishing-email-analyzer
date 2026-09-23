# Phishing Email Analyzer

A web tool that parses a raw email (.eml) and flags common phishing indicators:
display-name spoofing, Reply-To/Return-Path mismatches, failed SPF/DKIM/DMARC,
mismatched or suspicious links, and urgency-language patterns.

## Run locally
pip install -r requirements.txt
python app.py

Then open http://localhost:5000

## Test it
A sample phishing email is included at samples/sample_phishing.eml —
upload it on the homepage to see the tool flag it as "Likely Phishing".

## How it works
- analyzer.py — all detection logic (header analysis, link analysis, content analysis)
- app.py — Flask routes (upload page, analyze + results page)
- templates/ — HTML pages

## Next steps (stretch features, not built yet)
- Check extracted domains/IPs against AbuseIPDB or VirusTotal API
- Attachment hash scanning
- Save analysis history to a database
