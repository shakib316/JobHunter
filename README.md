# CyberJobHunter

Automated job intelligence for a 7-year Security Engineer profile focused on Google SecOps/Chronicle, Splunk, SIEM/SOAR, detection engineering, BindPlane, Cribl, YARA-L, cloud security and incident response.

## Website
**One-time Pages activation:** open [Repository Settings → Pages](https://github.com/shakib316/JobHunter/settings/pages), set **Build and deployment → Source** to **GitHub Actions**, and save. GitHub requires this publishing source to be enabled for the repository before the deployment workflow can publish. The repository and published dashboard are public.

After activation, the dashboard is at:
https://shakib316.github.io/JobHunter/

The dashboard reads `docs/data/latest.json` and provides search, location filtering, match scores, role summaries, skill matches, fit reasons and vacancy links. Downloadable CSV and raw JSON are also published.

## Automated schedule
- Monday and Thursday, 03:30 UTC (09:00 India Standard Time).
- A push to the search script, requirements, dashboard or workflow also triggers a run.
- Manual run: **Actions → CyberJobHunter scheduled search → Run workflow**.
- Up to 15 ranked and deduplicated opportunities.
- Every run writes `docs/data/latest.json`, `docs/data/latest.csv` and a dated JSON snapshot under `docs/data/archive/`.

## Search coverage
- 50 cybersecurity vendors.
- Named existing and potential Hyderabad GCC employers.
- Broad discovery queries for newly announced Hyderabad GCCs and India remote security roles.
- Hyderabad is prioritised, followed by Remote India and other Indian technology hubs.

## Run locally
```bash
pip install -r requirements.txt
python cybersecurity_job_hunter.py
```

## Important limitations
Search-engine discovery is not exhaustive and can return stale or duplicate vacancies. Page enrichment is best-effort; salary, experience, employment type and location are shown as not specified when they cannot be reliably extracted. Verify each role on the employer's official careers site. This project does not auto-apply, solve CAPTCHAs, bypass MFA or submit personal data.
