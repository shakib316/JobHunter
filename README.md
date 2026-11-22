# JobHunter — CyberJobHunter

Automated discovery and ranking of Security Engineer, SIEM, SOAR, Detection Engineering and related roles.

## Automation
- GitHub Actions runs every Monday and Thursday at 03:30 UTC (09:00 IST).
- Use **Actions → CyberJobHunter scheduled search → Run workflow** for an immediate run.
- Up to 15 deduplicated roles are written to `docs/data/latest.json` and a dated JSON snapshot.
- GitHub Pages serves the dashboard from `docs/`.

## Profile focus
Google SecOps/Chronicle, Splunk, SIEM/SOAR, YARA-L, BindPlane, Cribl, detection engineering, cloud security and incident response. Search prioritises Hyderabad and Remote India, across cybersecurity vendors and Hyderabad GCCs.

## Local run
```bash
pip install -r requirements.txt
python cybersecurity_job_hunter.py
```

This is a discovery/ranking tool, not an auto-apply bot. Search providers can rate-limit or return stale results. Confirm every vacancy on the employer's official career site. No personal resume, credentials or tokens are stored in the generated website.
