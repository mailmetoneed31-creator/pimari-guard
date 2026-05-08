# pimari-guard
# PermiGuard-Advanced
Ethical OAuth Scope Auditor & App Risk Analyzer

## ⚠️ Legal Warning
Use ONLY on accounts you own or have written permission to audit.

## Features
- Fetch connected apps & granted permissions (Facebook)
- Risk scoring engine (Critical/Medium/Low)
- Deep scan: domain HTTPS check
- Markdown report generation
- Revoke permission support

## Quick Start (Termux)
1. `termux-setup-storage`
2. `bash setup.sh`
3. Get Facebook token from [Graph API Explorer](https://developers.facebook.com/tools/explorer/)
4. `echo "YOUR_TOKEN" > token.txt`
5. `python permi_guard.py --token-file token.txt --deep`

## Roadmap
- [ ] Google / LinkedIn support
- [ ] VirusTotal integration
- [ ] Historical diff engine
