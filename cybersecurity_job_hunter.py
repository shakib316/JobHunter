#!/usr/bin/env python3
"""CyberJobHunter: scheduled discovery, enrichment, scoring and JSON/CSV publishing."""
from __future__ import annotations
import csv, json, re, time, hashlib, html
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlencode
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
def api_row(title, company, location, url, description="", salary="Not disclosed", source="API"):
    title=clean(title); url=clean(url); location=clean(location)
    if not title or not url or BAD.search(title+" "+url): return None
    # Match the job title itself, not incidental security words buried in an unrelated description.
    if not re.search(r"security|cyber|siem|soar|detection|threat|incident|soc|devsecops",title,re.I): return None
    # This dashboard prioritises India. Accept explicitly India-based roles and truly worldwide remote roles;
    # do not label US/Europe-only vacancies as "Remote India".
    loc=location.lower()
    india=bool(re.search(r"india|hyderabad|bengaluru|bangalore|pune|gurugram|gurgaon|chennai|mumbai|noida",loc))
    worldwide=bool(re.search(r"worldwide|anywhere|global|all countries|open to all",loc))
    if not (india or worldwide): return None
    return {"title":title,"url":url,"snippet":clean(description)[:1800],"target_employer":clean(company) or "API discovery","search_query":source,"api_company":clean(company),"api_location":location or "Not specified","api_salary":clean(salary) or "Not disclosed","discovery_source":source}

def discover():
    rows={}; health={}
    def add(row):
        if not row: return
        key=row["url"].split("?")[0].rstrip("/").lower()
        rows.setdefault(key,row)
    # Public job feeds; each source is isolated so one outage cannot stop discovery.
    feeds=[
      ("RemoteOK","https://remoteok.com/api",lambda j: api_row(j.get("position"),j.get("company"),j.get("location") or "Remote",j.get("url"),j.get("description") or " ".join(j.get("tags") or []),j.get("salary") or "Not disclosed","RemoteOK")),
      ("Arbeitnow","https://www.arbeitnow.com/api/job-board-api?page=1",lambda j: api_row(j.get("title"),j.get("company_name"),j.get("location") or ("Remote" if j.get("remote") else ""),j.get("url"),j.get("description") or "", "Not disclosed","Arbeitnow")),
      ("Jobicy","https://jobicy.com/api/v2/remote-jobs?count=50&tag=security",lambda j: api_row(j.get("jobTitle"),j.get("companyName"),j.get("candidateRequiredLocation") or j.get("jobGeo") or "",j.get("url"),j.get("jobDescription") or "",j.get("annualSalaryTo") or "Not disclosed","Jobicy")),
      ("Remotive","https://remotive.com/api/remote-jobs?search=security&limit=50",lambda j: api_row(j.get("title"),j.get("company_name"),j.get("candidate_required_location") or "Remote",j.get("url"),j.get("description") or "",j.get("salary") or "Not disclosed","Remotive"))
    ]
    session=requests.Session(); session.headers.update(HEADERS)
    for name,url,mapper in feeds:
        try:
            response=session.get(url,timeout=18); response.raise_for_status(); body=response.json()
            items=body if isinstance(body,list) else body.get("data",body.get("jobs",[]))
            count=0
            for item in items:
                row=mapper(item)
                if row: add(row); count+=1
            health[name]={"status":"ok","matching_jobs":count}
        except Exception as e:
            health[name]={"status":"error","error":str(e)[:220]}
            print(f"Source {name} failed: {str(e)[:180]}")
    # Himalayas public remote-jobs API: India-filtered search; keep its application link unchanged.
    try:
        queries_h=["security engineer","security operations","SIEM","SOAR","detection engineer","incident response"]
        hcount=0
        for term in queries_h:
            params=urlencode({"q":term,"country":"IN","sort":"recent","page":1})
            response=session.get("https://himalayas.app/jobs/api/search?"+params,timeout=18)
            response.raise_for_status()
            body=response.json()
            items=body.get("jobs",body.get("results",[])) if isinstance(body,dict) else []
            for item in items:
                title=clean(item.get("title")); company=clean(item.get("companyName"))
                desc=BeautifulSoup(str(item.get("description") or item.get("excerpt") or ""),"html.parser").get_text(" ",strip=True)
                restrictions=item.get("locationRestrictions") or []
                location="Remote India" if restrictions else "Remote India (worldwide eligible)"
                guid=clean(item.get("guid"))
                source_url=guid if guid.startswith("http") else ("https://himalayas.app"+(guid if guid.startswith("/") else "/"+guid) if guid else "")
                apply_link=clean(item.get("applicationLink"))
                if not source_url or not apply_link: continue
                expiry=item.get("expiryDate")
                if expiry:
                    try:
                        if float(expiry)<time.time(): continue
                    except (TypeError,ValueError): pass
                salary="Not disclosed"
                if item.get("minSalary") is not None or item.get("maxSalary") is not None:
                    currency=clean(item.get("currency") or "")
                    lo=item.get("minSalary"); hi=item.get("maxSalary")
                    amount=(str(lo) if lo is not None else "")+("–"+str(hi) if hi is not None and hi!=lo else "")
                    salary=clean(currency+" "+amount+" / "+clean(item.get("salaryPeriod") or "annual"))
                row=api_row(title,company,location,source_url,desc,salary,"Himalayas")
                if not row: continue
                row.update({"apply_url":apply_link,"source_url":source_url,"source_name":"Himalayas","api_employment_type":item.get("employmentType") or "Not specified","api_date_posted":item.get("pubDate"),"api_valid_through":expiry})
                add(row); hcount+=1
        health["Himalayas"]={"status":"ok","matching_jobs":hcount,"note":"India-filtered remote listings; Apply uses the provider-supplied applicationLink."}
    except Exception as e:
        health["Himalayas"]={"status":"error","error":str(e)[:220]}
        print("Source Himalayas failed:",str(e)[:180])
    # Search engine is supplementary. Rotate a small batch each run to avoid rate limits.
    try:
        with DDGS() as ddgs:
            all_queries=search_queries()
            run_slot=(datetime.now(timezone.utc).isocalendar().week*2 + (1 if datetime.now(timezone.utc).weekday() >= 3 else 0))*6
            start=run_slot % len(all_queries)
            queries=[all_queries[(start+i) % len(all_queries)] for i in range(min(6,len(all_queries)))]
            for employer,q in queries:
                try:
                    for hit in ddgs.text(q,max_results=6):
                        url=clean(hit.get("href") or hit.get("url")); title=clean(hit.get("title")); snippet=clean(hit.get("body") or hit.get("snippet"))
                        if not url or not title or BAD.search(title+" "+url): continue
                        if not re.search(r"security|cyber|siem|soar|detection|threat|incident|soc|devsecops",title,re.I): continue
                        if not re.search(r"India|Hyderabad|Bengaluru|Bangalore|Pune|Gurugram|Chennai|Mumbai|Noida|worldwide|anywhere|global",snippet+" "+title,re.I): continue
                        add({"title":title,"url":url,"snippet":snippet,"target_employer":employer,"search_query":q,"api_location":"India/remote eligibility to verify","search_query_location":"India priority","discovery_source":"DuckDuckGo"})
                except Exception as e:
                    print("Search query failed:",str(e)[:160])
                time.sleep(.7)
        health["DuckDuckGo"]={"status":"ok" if any(x.get("discovery_source")=="DuckDuckGo" for x in rows.values()) else "degraded","matching_jobs":sum(x.get("discovery_source")=="DuckDuckGo" for x in rows.values())}
    except Exception as e:
        health["DuckDuckGo"]={"status":"error","error":str(e)[:220]}
        print("DuckDuckGo unavailable:",str(e)[:180])
    print("Source health:",json.dumps(health,ensure_ascii=False))
    return list(rows.values()),health
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
    result={**row,"company":row.get("api_company") or "Employer not verified","location":row.get("api_location") or "Not specified","description":row["snippet"],"responsibilities":[],"requirements":[],"skills":[],"salary":row.get("api_salary") or "Not disclosed","employment_type":row.get("api_employment_type") or "Not specified","experience":"Not specified","date_posted":datetime.fromtimestamp(row["api_date_posted"],timezone.utc).strftime("%Y-%m-%d") if row.get("api_date_posted") else "Not specified","valid_through":datetime.fromtimestamp(row["api_valid_through"],timezone.utc).strftime("%Y-%m-%d") if row.get("api_valid_through") else "Not specified","apply_url":row.get("apply_url") or row["url"],"source_url":row.get("source_url") or row["url"],"source_name":row.get("source_name") or row.get("discovery_source","Job source"),"source_domain":urlparse(row["url"]).netloc,"page_status":"Search result only","discovery_source":row.get("discovery_source","DuckDuckGo")}
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
                jl=job.get("jobLocation")
                if jl:
                    locs=jl if isinstance(jl,list) else [jl]
                    bits=[]
                    for loc in locs:
                        addr=loc.get("address",{}) if isinstance(loc,dict) else {}
                        if isinstance(addr,dict):
                            bits += [clean(addr.get(k)) for k in ["addressLocality","addressRegion","addressCountry"] if addr.get(k)]
                    if bits: result["location"]=", ".join(dict.fromkeys(bits))
                resp=job.get("responsibilities")
                quals=job.get("qualifications") or job.get("skills")
                if resp: result["responsibilities"]=[clean(resp if isinstance(resp,str) else json.dumps(resp))[:1200]]
                if quals: result["requirements"]=[clean(quals if isinstance(quals,str) else json.dumps(quals))[:1200]]
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
            target=clean(row["target_employer"])
            if result["company"]=="Employer not verified" and target not in ["New Hyderabad GCCs","India discovery","Hyderabad discovery","API discovery"] and target.lower() in (row["title"]+" "+row["snippet"]+" "+urlparse(row["url"]).netloc).lower():
                result["company"]=target
            m=re.search(r"(Hyderabad|Bengaluru|Bangalore|Pune|Gurugram|Gurgaon|Chennai|Mumbai|Noida|India)",text,re.I)
            if m and result["location"] in ["Not specified","Remote"]: result["location"]=m.group(1)
            sal=re.search(r"(?:₹|INR|USD|US\$|\$)\s?[\d,.]+\s?(?:k|K|LPA|lakh|lakhs|per annum|/year|/yr|annually)",text,re.I)
            if sal and not re.search(r"\$\s?0(?:\.0+)?\b",sal.group(0)): result["salary"]=sal.group(0)
            for s in SKILLS:
                if re.search(re.escape(s),text,re.I): result["skills"].append(s)
            result["description"]=result["description"] if len(result["description"])>180 else text[:1800]
            if re.search(r"remote|work from home",text,re.I) and result["location"] in ["Remote","Worldwide","Not specified"]:
                result["location"]="Remote (worldwide eligibility not confirmed)" if result["location"]=="Not specified" else "Remote ("+result["location"]+")"
    except Exception as e: result["fetch_error"]=str(e)[:180]
    return result
def rank(x):
    t=x["title"].lower(); blob=(t+" "+x["description"]+" "+" ".join(x["skills"])).lower()
    title= min(35, 10+sum(5 for k in ["security engineer","siem","soar","detection","security platform","security lead"] if k in t))
    skill=min(35,sum(4 for k in ["google secops","chronicle","splunk","soar","siem","yara-l","bindplane","cribl","sentinel","crowdstrike","detection engineering","incident response"] if k in blob))
    loc=x["location"].lower()
    location=15 if "hyderabad" in loc else 12 if "remote" in loc and ("india" in loc or "not specified" not in loc) else 8 if "india" in loc else 3
    seniority=5 if re.search(r"senior|lead|staff|principal|manager",t) else 2
    employer=5 if x["company"]!="Employer not verified" else 0
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
    raw,source_health=discover(); print(f"Discovered {len(raw)} candidate links")
    if not raw:
        raise SystemExit("No job candidates returned by any source; preserving the last published dataset.")
    # Enrich only the strongest 60 leads to keep scheduled runs predictable.
    raw=sorted(raw,key=rough_score,reverse=True)[:60]
    enriched=[rank(enrich(x)) for x in raw]
    enriched=[x for x in enriched if x["score"]>=50]
    if not enriched:
        print("No candidates met the minimum 50/100 relevance threshold; preserving the last published snapshot.")
        return
    enriched.sort(key=lambda x:(x["score"],"hyderabad" in x["location"].lower(),"remote" in x["location"].lower()),reverse=True)
    # Deduplicate on canonical URL and similar role+company.
    chosen=[]; seen=set()
    for x in enriched:
        k=(re.sub(r"[^a-z0-9]","",x["title"].lower()),x["company"].lower())
        if k in seen: continue
        seen.add(k); chosen.append(x)
        if len(chosen)>=MAX_RESULTS: break
    stamp=now.strftime("%Y-%m-%d %H:%M UTC")
    payload={"project":"CyberJobHunter","generated_at":stamp,"generated_at_iso":now.isoformat(),"total_candidates":len(raw),"count":len(chosen),"profile":{"title":"Security Engineer","experience_years":7,"focus":["Google SecOps","Chronicle","Splunk","SIEM","SOAR","YARA-L","BindPlane","Cribl","Detection Engineering","Cloud Security"]},"search_coverage":{"cybersecurity_vendors":len(VENDORS),"named_gccs":len(GCCS),"broad_discovery_queries":4,"locations_priority":LOCATIONS},"source_health":source_health,"results":chosen,"disclaimer":"Search-engine discovery can miss vacancies or surface stale listings. Confirm status, location, eligibility and details on the employer's official careers page."}
    DATA.mkdir(parents=True,exist_ok=True); ARCHIVE.mkdir(parents=True,exist_ok=True)
    (DATA/"latest.json").write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
    dated=now.strftime("%Y-%m-%d")
    (ARCHIVE/f"{dated}.json").write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
    archive_dates=sorted([p.stem for p in ARCHIVE.glob("*.json") if p.name!="index.json"],reverse=True)
    (ARCHIVE/"index.json").write_text(json.dumps({"dates":archive_dates},indent=2),encoding="utf-8")
    fields=["score","title","company","location","salary","employment_type","experience","date_posted","valid_through","url","apply_url","source_url","source_name","description","skills","fit_reasons","page_status"]
    with (DATA/"latest.csv").open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore"); w.writeheader()
        for x in chosen: w.writerow({**x,"skills":"; ".join(x["skills"]),"fit_reasons":"; ".join(x["fit_reasons"])})
    print(f"Published {len(chosen)} ranked jobs to docs/data at {stamp}")
if __name__=="__main__": main()
