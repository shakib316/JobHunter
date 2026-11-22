#!/usr/bin/env python3
"""CyberJobHunter: scheduled discovery, enrichment, scoring and JSON/CSV publishing."""
from __future__ import annotations
import csv, json, re, time, hashlib, html
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from ddgs import DDGS

ROOT=Path(__file__).resolve().parent
DOCS=ROOT/"docs"; DATA=DOCS/"data"; ARCHIVE=DATA/"archive"
MAX_RESULTS=15
HEADERS={"User-Agent":"Mozilla/5.0 (compatible; CyberJobHunter/2.0; +https://github.com/shakib316/JobHunter)"}
VENDORS=["Palo Alto Networks","CrowdStrike","Microsoft Security","Google Cloud Security","SentinelOne","Darktrace","Fortinet","Cisco Security","Check Point Software","IBM Security","Zscaler","Vectra AI","CyberArk","Okta","Cloudflare","Proofpoint","Trellix","Sophos","Rapid7","Elastic","Arctic Wolf","ReliaQuest","Exabeam","Securonix","Abnormal Security","Recorded Future","Tenable","Qualys","Wiz","Akamai","Bitdefender","Trend Micro","BlackBerry Cylance","Cybereason","eSentire","Huntress","Expel","Dropzone AI","Torq","Simbian","Prophet Security","Radiant Security","Stellar Cyber","Lakera","Protect AI","HiddenLayer","Mindgard","Robust Intelligence","Netskope","SparkCognition"]
GCCS=["Deutsche Börse Group","Vanguard","Charles Schwab","UBS","HSBC","Voya Financial","T-Mobile","DoorDash","Billtrust","Sanofi","JLL","Acumatica","Blackbaud","Regeneron","Amgen","Eli Lilly","Citizens Financial Group","Nationwide","HCA Healthcare","Western Union","Costco","Marriott","DAZN","Agilent","McDonald's","Micron","Mattel","S&P Global","State Street","Wells Fargo","Synchrony","Salesforce","Google","Amazon","Microsoft"]
ROLES=["security engineer","cybersecurity engineer","cyber security engineer","siem engineer","soar engineer","detection engineer","security platform engineer","security operations engineer","security analyst","soc engineer","security architect","cloud security engineer","incident response","threat detection","security consultant","security lead","cyber security lead"]
SKILLS=["Google SecOps","Chronicle","Splunk","Splunk ES","SOAR","SIEM","YARA-L","BindPlane","Cribl","Microsoft Sentinel","CrowdStrike","NG SIEM","detection engineering","incident response","log ingestion","log parsing","normalization","AWS","Azure","GCP","KQL","Python","EDR","XDR"]
LOCATIONS=["Hyderabad","Remote India","Remote","Bengaluru","Pune","Gurugram","Chennai","Mumbai","Noida","India"]
BAD=re.compile(r"documentation|product overview|pricing|course|certification|interview questions|salary guide|what is |definition|linkedin\.com/(in|company)/",re.I)
def clean(s): return re.sub(r"\s+"," ",str(s or "")).strip()
def search_queries():
    qs=[]
    role=' OR '.join('"'+r+'"' for r in ROLES[:9])
    for c in VENDORS: qs.append((f'"{c}"',f'"{c}" ({role}) (Hyderabad OR India OR remote) jobs'))
    for c in GCCS: qs.append((f'"{c}"',f'"{c}" (security OR SIEM OR SOAR OR detection OR SOC) (Hyderabad OR India OR remote) careers jobs'))
    qs += [("New Hyderabad GCCs",'new GCC Hyderabad 2026 cybersecurity security engineer SIEM SOAR jobs'),
           ("New Hyderabad GCCs",'Hyderabad global capability centre expansion information security careers 2026'),
           ("India discovery",'India remote security engineer SIEM SOAR detection engineer jobs'),
           ("Hyderabad discovery",'Hyderabad security engineer cloud security SIEM SOAR jobs')]
    return qs
def discover():
    rows={}
    with DDGS() as ddgs:
        for employer,q in search_queries():
            try:
                for hit in ddgs.text(q,max_results=8):
                    url=clean(hit.get("href") or hit.get("url")); title=clean(hit.get("title")); snippet=clean(hit.get("body") or hit.get("snippet"))
                    if not url or not title or BAD.search(title+" "+url): continue
                    if not re.search(r"security|siem|soar|detection|threat|incident|soc|cyber",title,re.I): continue
                    if "linkedin.com" in urlparse(url).netloc and re.search(r"/(in|company)/",url): continue
                    key=url.split("?")[0].rstrip("/").lower()
                    rows.setdefault(key,{"title":title,"url":url,"snippet":snippet,"target_employer":employer,"search_query":q})
            except Exception as e: print("Search error:",str(e)[:180])
            time.sleep(.25)
    return list(rows.values())
def find_jobposting(obj):
    if isinstance(obj,dict):
        kind=obj.get("@type",[])
        if isinstance(kind,str): kind=[kind]
        if any("JobPosting" in str(k) for k in kind): return obj
        for value in obj.values():
            found=find_jobposting(value)
            if found: return found
    elif isinstance(obj,list):
        for value in obj:
            found=find_jobposting(value)
            if found: return found
    return None
def enrich(row):
    result={**row,"company":row["target_employer"],"location":"Not specified","description":row["snippet"],"responsibilities":[],"requirements":[],"skills":[],"salary":"Not disclosed","employment_type":"Not specified","experience":"Not specified","date_posted":"Not specified","valid_through":"Not specified","responsibilities":[],"requirements":[],"apply_url":row["url"],"source_domain":urlparse(row["url"]).netloc,"page_status":"Search result only"}
    try:
        r=requests.get(row["url"],headers=HEADERS,timeout=12,allow_redirects=True)
        result["page_status"]=f"Fetched (HTTP {r.status_code})"
        if r.ok and "text/html" in r.headers.get("content-type",""):
            soup=BeautifulSoup(r.text[:1_500_000],"html.parser")
            job=None
            for node in soup.select('script[type="application/ld+json"]'):
                try:
                    job=find_jobposting(json.loads(node.string or node.get_text()))
                    if job: break
                except Exception: pass
            if job:
                org=job.get("hiringOrganization",{})
                if isinstance(org,dict) and org.get("name"): result["company"]=clean(org["name"])
                result["date_posted"]=clean(job.get("datePosted") or "Not specified")
                result["valid_through"]=clean(job.get("validThrough") or "Not specified")
                result["employment_type"]=clean(job.get("employmentType") or "Not specified")
                exp=job.get("experienceRequirements")
                if exp: result["experience"]=clean(exp if isinstance(exp,str) else json.dumps(exp))
                sal=job.get("baseSalary")
                if sal: result["salary"]=clean(json.dumps(sal,ensure_ascii=False))
                desc=job.get("description")
                if desc: result["description"]=clean(BeautifulSoup(str(desc),"html.parser").get_text(" ",strip=True))[:2400]
            for tag in soup(["script","style","noscript","svg"]): tag.decompose()
            text=clean(soup.get_text(" ",strip=True))
            for sel,field in [('meta[name="description"]','description'),('meta[property="og:description"]','description')]:
                tag=soup.select_one(sel)
                if tag and tag.get("content") and len(tag["content"])>len(result[field]): result[field]=clean(tag["content"])
            title=soup.title.string if soup.title and soup.title.string else ""
            if title and len(title)>len(result["title"]) and re.search(r"security|siem|soar|detection|cyber",title,re.I): result["title"]=clean(title)[:180]
            m=re.search(r"(Hyderabad|Bengaluru|Bangalore|Pune|Gurugram|Gurgaon|Chennai|Mumbai|Noida|India|Remote)",text,re.I)
            if m: result["location"]=m.group(1)
            sal=re.search(r"(?:₹|INR|USD|\$)\s?[\d,.]+\s?(?:LPA|LPA|per annum|/year|to\s+(?:₹|INR|USD|\$)?\s?[\d,.]+)?",text,re.I)
            if sal: result["salary"]=sal.group(0)
            for s in SKILLS:
                if re.search(re.escape(s),text,re.I): result["skills"].append(s)
            result["description"]=result["description"] if len(result["description"])>180 else text[:1800]
            if re.search(r"remote|work from home",text,re.I): result["location"]="Remote / "+result["location"]
    except Exception as e: result["fetch_error"]=str(e)[:180]
    return result
def rank(x):
    t=x["title"].lower(); blob=(t+" "+x["description"]+" "+" ".join(x["skills"])).lower()
    title= min(35, 10+sum(5 for k in ["security engineer","siem","soar","detection","security platform","security lead"] if k in t))
    skill=min(35,sum(4 for k in ["google secops","chronicle","splunk","soar","siem","yara-l","bindplane","cribl","sentinel","crowdstrike","detection engineering","incident response"] if k in blob))
    loc=x["location"].lower()
    location=15 if "hyderabad" in loc else 12 if "remote" in loc and ("india" in loc or "not specified" not in loc) else 8 if "india" in loc else 3
    seniority=5 if re.search(r"senior|lead|staff|principal|manager",t) else 2
    employer=5 if x["target_employer"] not in ("New Hyderabad GCCs","India discovery","Hyderabad discovery") else 0
    penalties=15 if re.search(r"intern|junior|graduate|entry.level",t) else 0
    x["score"]=max(0,min(100,title+skill+location+seniority+employer-penalties))
    x["fit_reasons"]=[]
    if any(k in blob for k in ["google secops","chronicle","splunk","soar","siem"]): x["fit_reasons"].append("Direct SIEM/SOAR platform alignment")
    if any(k in blob for k in ["yara-l","detection engineering","threat detection"]): x["fit_reasons"].append("Detection engineering alignment")
    if "hyderabad" in loc: x["fit_reasons"].append("Preferred Hyderabad location")
    if "remote" in loc: x["fit_reasons"].append("Remote opportunity indicated")
    if not x["fit_reasons"]: x["fit_reasons"].append("Relevant security role; validate detailed requirements")
    x["profile_alignment"]="7-year Security Engineer profile: SIEM/SOAR, Google SecOps, Splunk, detection engineering and cloud security"
    x["verification_note"]="Discovery result only; confirm the role is active and apply on the employer's official careers site."
    return x
def rough_score(x):
    title=x["title"].lower(); blob=(title+" "+x["snippet"]).lower()
    return min(35,10+sum(5 for k in ["security engineer","siem","soar","detection","security platform","security lead"] if k in title))+min(35,sum(4 for k in ["google secops","chronicle","splunk","soar","siem","yara-l","bindplane","cribl","sentinel","crowdstrike","detection engineering"] if k in blob))+ (15 if "hyderabad" in blob else 10 if "remote india" in blob else 5 if "india" in blob else 0)
def main():
    now=datetime.now(timezone.utc); print("Searching target vendors, GCCs and wider India market…")
    raw=discover(); print(f"Discovered {len(raw)} candidate links")
    # Enrich only the strongest 60 leads to keep scheduled runs predictable.
    raw=sorted(raw,key=rough_score,reverse=True)[:60]
    enriched=[rank(enrich(x)) for x in raw]
    enriched.sort(key=lambda x:(x["score"],"hyderabad" in x["location"].lower(),"remote" in x["location"].lower()),reverse=True)
    # Deduplicate on canonical URL and similar role+company.
    chosen=[]; seen=set()
    for x in enriched:
        k=(re.sub(r"[^a-z0-9]","",x["title"].lower()),x["company"].lower())
        if k in seen: continue
        seen.add(k); chosen.append(x)
        if len(chosen)>=MAX_RESULTS: break
    stamp=now.strftime("%Y-%m-%d %H:%M UTC")
    payload={"project":"CyberJobHunter","generated_at":stamp,"generated_at_iso":now.isoformat(),"total_candidates":len(raw),"count":len(chosen),"profile":{"title":"Security Engineer","experience_years":7,"focus":["Google SecOps","Chronicle","Splunk","SIEM","SOAR","YARA-L","BindPlane","Cribl","Detection Engineering","Cloud Security"]},"search_coverage":{"cybersecurity_vendors":len(VENDORS),"named_gccs":len(GCCS),"broad_discovery_queries":5,"locations_priority":LOCATIONS},"results":chosen,"disclaimer":"Search-engine discovery can miss vacancies or surface stale listings. Confirm status, location, eligibility and details on the employer's official careers page."}
    DATA.mkdir(parents=True,exist_ok=True); ARCHIVE.mkdir(parents=True,exist_ok=True)
    (DATA/"latest.json").write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
    dated=now.strftime("%Y-%m-%d")
    (ARCHIVE/f"{dated}.json").write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
    fields=["score","title","company","location","salary","employment_type","experience","date_posted","valid_through","url","apply_url","description","skills","fit_reasons","page_status"]
    with (DATA/"latest.csv").open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore"); w.writeheader()
        for x in chosen: w.writerow({**x,"skills":"; ".join(x["skills"]),"fit_reasons":"; ".join(x["fit_reasons"])})
    print(f"Published {len(chosen)} ranked jobs to docs/data at {stamp}")
if __name__=="__main__": main()
