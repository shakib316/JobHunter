#!/usr/bin/env python3
"""Automated CyberJobHunter: discover, filter, rank and publish up to 15 roles."""
import json, os, re, html
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from ddgs import DDGS

OUT = Path("docs/data")
COMPANIES = ["Palo Alto Networks","CrowdStrike","Microsoft Security","Google Cloud Security","SentinelOne","Darktrace","Fortinet","Cisco Security","Check Point Software","IBM Security","Zscaler","Vectra AI","CyberArk","Okta","Cloudflare","Proofpoint","Trellix","Sophos","Rapid7","Elastic","Arctic Wolf","ReliaQuest","Exabeam","Securonix","Abnormal Security","Recorded Future","Tenable","Qualys","Wiz","Akamai","Bitdefender","Trend Micro","BlackBerry Cylance","Cybereason","eSentire","Huntress","Expel","Dropzone AI","Torq","Simbian","Prophet Security","Radiant Security","Stellar Cyber","Lakera","Protect AI","HiddenLayer","Mindgard","Robust Intelligence","Netskope","SparkCognition"]
GCCS = ["Deutsche Börse Group","Vanguard","Charles Schwab","UBS","HSBC","Voya Financial","T-Mobile","DoorDash","Billtrust","Sanofi","JLL","Acumatica","Blackbaud","Micron","Mattel","S&P Global","State Street","Wells Fargo","Synchrony","Salesforce","Microsoft","Google","Amazon"]
ROLE = re.compile(r"security|siem|soar|detection|threat|incident|soc|cyber|cloud security|security platform", re.I)
BAD = re.compile(r"documentation|docs\.|product overview|pricing|course|certification|salary guide|interview questions|what is |definition", re.I)
SKILLS = ["google secops","chronicle","splunk","soar","siem","yara-l","bindplane","cribl","sentinel","crowdstrike","detection engineering","incident response","log ingestion","aws","azure","kql"]
LOC = re.compile(r"hyderabad|remote|india|telangana", re.I)

def score(row):
    title, body, url = row["title"], row["snippet"], row["url"]
    if not ROLE.search(title) or BAD.search(title+" "+url): return -1
    host = urlparse(url).netloc.lower()
    if "linkedin.com" in host and re.search(r"/in/", url): return -1
    if any(x in host for x in ["docs.","support.","training.","youtube.com"]): return -1
    s = min(35, 15 + (15 if re.search(r"senior|lead|staff|principal|engineer", title, re.I) else 0) + (5 if re.search(r"security|siem|soar|detection", title, re.I) else 0))
    text = (title+" "+body).lower()
    s += min(35, sum(5 for k in SKILLS if k in text))
    s += 15 if LOC.search(text) else 0
    s += 5 if any(x in host for x in ["myworkdayjobs","greenhouse.io","lever.co","ashbyhq.com","smartrecruiters.com","workday.com","careers"]) else 0
    if re.search(r"intern|junior|graduate|entry.level", title, re.I): s -= 20
    return max(0, min(100, s))

def main():
    now = datetime.now(timezone.utc)
    queries = []
    for c in COMPANIES:
        queries.append(f'"{c}" (security engineer OR SIEM OR SOAR OR detection engineer) (Hyderabad OR India OR remote) jobs')
    for c in GCCS:
        queries.append(f'"{c}" (security engineer OR SIEM OR SOAR OR SOC OR detection) (Hyderabad OR India OR remote) careers')
    queries += ['Hyderabad security engineer SIEM SOAR detection engineer jobs India remote',
                'India remote security platform engineer cloud security jobs']
    found = {}
    with DDGS() as ddgs:
        for q in queries:
            try:
                for r in ddgs.text(q, max_results=8):
                    url = r.get("href") or r.get("url") or ""
                    title = (r.get("title") or "").strip()
                    snippet = (r.get("body") or r.get("snippet") or "").strip()
                    if not url or not title: continue
                    key = url.split("?")[0].rstrip("/").lower()
                    row = {"title":title,"snippet":snippet,"url":url,"query":q}
                    points = score(row)
                    if points < 0: continue
                    row["score"] = points
                    if key not in found or points > found[key]["score"]: found[key] = row
            except Exception as e:
                print(f"Search skipped: {q[:70]}: {e}")
    rows = sorted(found.values(), key=lambda x:(x["score"], x["title"]), reverse=True)[:15]
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {"generated_at":stamp,"count":len(rows),"results":rows,
               "notes":"Discovery/ranking only. Verify role status and details on the employer's official careers page."}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/"latest.json").write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
    (OUT/f"{now:%Y-%m-%d}.json").write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
    print(f"Published {len(rows)} roles at {stamp}")

if __name__ == "__main__": main()
