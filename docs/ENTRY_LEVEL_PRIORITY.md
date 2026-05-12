# RECALIBRATED: Projects For Entry-Level Job Seeker
## Tailored to Goutham's Resume - What Actually Gets You Hired RIGHT NOW

---

## HONEST ASSESSMENT OF YOUR RESUME

### Strengths (Unusual for Entry-Level)
- **OSEP + CRTE** - Most entry-level candidates have Security+ at best. You have advanced offensive certs. This is your superpower.
- **AWS Security Specialty** - Proves cloud depth beyond just "I used EC2 once"
- **Real IR experience** - You neutralized live cryptojacking at SportsExcitement. That's not a lab exercise.
- **Python automation** - You already script real workflows (SOC triage, log analysis, forensics)
- **Teaching experience** - Guided 60+ students in DFIR. Shows communication skills.

### What's Working Against You
- **Short tenure at each role** - 3 months at DreamStudio, ~5 months at SportsExcitement. Hiring managers will notice.
- **Small/unknown companies** - SportsExcitement and DreamStudio don't carry brand recognition
- **Only 2 projects on resume** - Both are academic/lab exercises, not tools other people use
- **No GitHub portfolio** - Your resume lists skills but has no proof anyone can click and verify
- **No open-source contributions** - No social proof in the security community
- **Title inflation risk** - "Head Security Engineer" at a small company after 6 months post-graduation may raise eyebrows

### What Entry-Level Roles Actually Want
For **SOC Analyst / Junior Security Engineer / Junior Pentester / Cloud Security Analyst**:
1. Can you triage alerts and investigate incidents? (SIEM skills)
2. Can you write detection rules? (Sigma, Splunk SPL, KQL)
3. Can you do basic pentesting and write a clear report? (methodology)
4. Can you automate repetitive security tasks? (Python scripting)
5. Can you work with cloud security tools? (GuardDuty, Security Hub, CloudTrail)
6. Do you understand network fundamentals? (CCNA helps here)

**Your certs say you can. Your projects need to PROVE it.**

---

## THE RIGHT 10 PROJECTS FOR YOU (Ranked)

These are **scoped down to be completable in 1-3 weeks each**, use **Python** (your strongest language), and directly demonstrate the skills hiring managers test for.

---

### 1. ThreatHunt-Assist (Project #45) - Threat Hunting Query Generator
**Why #1 for you:** You built 25+ SIEM correlation rules at Phoenix Global. This project productizes that exact skill. Every SOC hiring manager will understand this instantly.

**Scoped for entry-level:**
- Python CLI tool (not a full SaaS platform)
- Input: MITRE ATT&CK technique ID (e.g., T1059.001)
- Output: Ready-to-paste queries for Splunk SPL, Elastic KQL, and Microsoft Sentinel
- Includes a library of 50+ pre-built hunting queries you wrote
- Maps every query to ATT&CK technique + data source required
- Generates a hunting report template (Markdown/PDF)

**What it proves:** "I don't just run queries - I build the tools that generate them. Here are 50 detection queries I wrote, mapped to MITRE ATT&CK, across 3 SIEM platforms."

**Tech:** Python, MITRE ATT&CK STIX data, Jinja2 templates, Click CLI, JSON/YAML
**Time to build:** ~2 weeks
**Repo name:** `threat-hunt-queries`

---

### 2. CloudMisconfig-Hunter (Project #28) - AWS Security Auditor
**Why #2:** Your resume says you audited IAM/S3 across 50+ AWS assets. This tool is proof.

**Scoped for entry-level:**
- Python CLI tool focused on **AWS only** (not multi-cloud yet)
- Checks for the top 30 most critical AWS misconfigurations:
  - S3 public access, unencrypted buckets
  - IAM users without MFA, overly permissive policies, unused credentials
  - Security groups with 0.0.0.0/0 on sensitive ports
  - CloudTrail not enabled, GuardDuty not enabled
  - Unencrypted EBS volumes, public RDS instances
  - Root account usage, no password policy
- Output: JSON report + terminal summary + HTML report with severity ratings
- Maps each check to CIS AWS Benchmark ID + NIST 800-53 control

**What it proves:** "I automated the exact AWS audit I did manually at Phoenix Global and DreamStudio. Here's the tool - run it against your own account."

**Tech:** Python, boto3, Click CLI, Jinja2 (HTML reports), JSON
**Time to build:** ~2-3 weeks
**Repo name:** `aws-security-auditor`

---

### 3. ForensicTimeline (Project #47) - DFIR Timeline Builder
**Why #3:** You taught DFIR to 60+ grad students and did forensic analysis at SportsExcitement. This productizes your teaching.

**Scoped for entry-level:**
- Python CLI tool that ingests common forensic artifacts:
  - Windows Event Logs (.evtx)
  - Syslog files
  - AWS CloudTrail JSON logs
  - CSV/JSON generic log files
- Normalizes all timestamps to UTC
- Merges into a single sorted timeline
- Tags events with MITRE ATT&CK techniques where applicable
- Outputs: unified CSV timeline + Markdown investigation report + terminal summary
- Includes 2-3 sample case files with walkthrough

**What it proves:** "I built the tool I wished I had when teaching DFIR at Maryland. Here's an example investigation using it."

**Tech:** Python, python-evtx, pandas, Click CLI, Jinja2
**Time to build:** ~2 weeks
**Repo name:** `forensic-timeline`

---

### 4. PrivEsc-Detector (Project #25) - AD Privilege Escalation Path Finder
**Why #4:** CRTE is your crown jewel cert. This tool proves you didn't just pass the exam - you understand AD attack paths deeply enough to automate finding them.

**Scoped for entry-level:**
- Python tool that analyzes Active Directory for privilege escalation paths:
  - Kerberoastable accounts
  - AS-REP roastable accounts
  - Unconstrained/constrained delegation misconfigs
  - Users with DCSync rights
  - Nested group membership leading to Domain Admin
  - Stale admin accounts (password age > 90 days)
  - Service accounts with excessive privileges
- Works via LDAP queries (no BloodHound dependency, though can export to BloodHound format)
- Output: Risk-scored findings + remediation recommendations + JSON/CSV export
- Includes a lab setup guide (Docker-based AD lab) for testing

**What it proves:** "My CRTE isn't just a cert - I automated the exact AD attack path analysis I perform during engagements."

**Tech:** Python, ldap3, impacket, Click CLI, JSON
**Time to build:** ~2-3 weeks
**Repo name:** `ad-escalation-audit`

---

### 5. GitLeaks-Pro (Project #11) - Secret Detection Scanner
**Why #5:** Proven category (Gitleaks = 25K stars). Yours adds ML context analysis. Every company has this problem.

**Scoped for entry-level:**
- Python CLI tool that scans Git repos for secrets:
  - AWS keys, Azure tokens, GCP service account keys
  - API keys (Stripe, Twilio, SendGrid, etc.)
  - Database connection strings
  - Private keys (SSH, PGP, TLS)
  - High-entropy strings with context analysis
- Scans full Git history (not just current files)
- Pre-commit hook mode (block commits with secrets)
- Low false-positive rate by checking if secrets are in test/example files
- Output: JSON/SARIF + terminal summary with file:line references

**What it proves:** "I understand the secret exposure problem and built a scanner with smart context analysis to reduce false positives."

**Tech:** Python, GitPython, regex, entropy calculation, Click CLI
**Time to build:** ~2 weeks
**Repo name:** `secret-scanner`

---

### 6. PhishNet (Project #46) - Phishing Email Analyzer
**Why #6:** 91% of breaches start with phishing. Every SOC analyst triages phishing emails daily.

**Scoped for entry-level:**
- Python CLI tool that analyzes suspicious emails (.eml/.msg files):
  - Header analysis (SPF, DKIM, DMARC validation)
  - Sender reputation check
  - URL extraction and VirusTotal/URLhaus lookup
  - Attachment hash check against known malware databases
  - Suspicious keyword/pattern detection
  - Verdict: CLEAN / SUSPICIOUS / MALICIOUS with confidence score
- Batch mode: analyze a folder of emails
- Output: JSON report + terminal summary + investigation notes template

**What it proves:** "I automated SOC email triage - the exact task junior analysts spend 60% of their day doing."

**Tech:** Python, email/mailparser libraries, requests (VT API), Click CLI
**Time to build:** ~1.5 weeks
**Repo name:** `phish-analyzer`

---

### 7. AlertFusion (Project #43) - Alert Triage Automation
**Why #7:** You already automated alert triage at Phoenix Global (saved 15+ hours/week). Scale that up.

**Scoped for entry-level:**
- Python tool that reads alert exports (CSV/JSON from Splunk, Elastic, or generic SIEM):
  - Deduplicates similar alerts
  - Enriches with threat intel (IP reputation, domain age, hash lookup)
  - Scores priority based on: severity + asset value + threat intel match
  - Groups related alerts into potential incidents
  - Generates a triage report (high/medium/low buckets)
- Includes sample alert datasets for demo purposes
- Output: Prioritized CSV + Markdown triage report + statistics

**What it proves:** "This is the Python automation that saved my SOC team 15 hours per week at Phoenix Global - now anyone can use it."

**Tech:** Python, pandas, requests (threat intel APIs), Click CLI
**Time to build:** ~2 weeks
**Repo name:** `alert-triage`

---

### 8. DepShield (Project #8) - Dependency Security Scanner
**Why #8:** Supply chain attacks doubled. Simple to build, useful to everyone, shows DevSecOps awareness.

**Scoped for entry-level:**
- Python CLI tool that scans project dependencies for risks:
  - Check pip/npm/gem packages against OSV vulnerability database
  - Detect typosquatting (Levenshtein distance against top 1000 packages)
  - Flag packages with suspicious install scripts
  - Check for recently changed maintainers
  - Flag packages with no source repo or <10 stars
- GitHub Actions integration (YAML workflow file included)
- Output: JSON/SARIF + terminal summary with severity

**What it proves:** "I understand supply chain risk and built a scanner that catches malicious dependencies before they hit production."

**Tech:** Python, pip API, npm registry API, OSV API, Click CLI
**Time to build:** ~2 weeks
**Repo name:** `dep-shield`

---

### 9. PatchPulse (Project #12) - Vulnerability Prioritizer
**Why #9:** Shows you understand risk management, not just finding vulns. Business acumen.

**Scoped for entry-level:**
- Python CLI tool that takes vulnerability scan output (Nessus CSV, Qualys CSV, or generic CVE list):
  - Enriches each CVE with EPSS score (exploit prediction)
  - Checks CISA KEV (Known Exploited Vulnerabilities) catalog
  - Cross-references with CVSS score
  - Calculates composite risk score: EPSS + KEV + CVSS + asset context
  - Outputs prioritized patch list (focus on the 5% that matter)
- Output: Prioritized CSV + executive summary + "patch this week" shortlist

**What it proves:** "I don't dump 5,000 CVEs on the engineering team - I tell them which 50 to fix this week and why."

**Tech:** Python, NVD API, EPSS API, CISA KEV, pandas, Click CLI
**Time to build:** ~1.5 weeks
**Repo name:** `vuln-priority`

---

### 10. PromptArmor (Project #14) - Prompt Injection Detector
**Why #10:** Still important for differentiation, but scoped way down.

**Scoped for entry-level:**
- Python library/CLI that detects prompt injection attempts in text:
  - Pattern-based detection (known injection patterns)
  - Instruction override detection ("ignore previous instructions")
  - Role hijacking detection ("you are now...")
  - Encoding bypass detection (base64, unicode tricks)
  - Confidence scoring per input
- Usable as: CLI tool, Python library (`pip install`), or FastAPI microservice
- Includes a test suite of 200+ injection payloads from public datasets
- Output: CLEAN/SUSPICIOUS/INJECTION verdict + matched patterns + confidence

**What it proves:** "I understand the emerging AI threat landscape - not just traditional security."

**Tech:** Python, regex, FastAPI (optional), pytest
**Time to build:** ~2 weeks
**Repo name:** `prompt-armor`

---

## REVISED BUILD ORDER & TIMELINE

```
MONTH 1 (Weeks 1-4): Get 3 projects DONE and on GitHub
├── Week 1-2: threat-hunt-queries (leverages your strongest skill)
├── Week 2-3: aws-security-auditor (leverages your AWS cert + experience)
└── Week 3-4: phish-analyzer (quick win, every SOC needs this)

MONTH 2 (Weeks 5-8): Add 3 more, start applying
├── Week 5-6: forensic-timeline (your DFIR teaching → product)
├── Week 6-7: ad-escalation-audit (your CRTE → product)
├── Week 7-8: alert-triage (your Phoenix Global automation → product)
└── START APPLYING TO JOBS with 6 projects live

MONTH 3 (Weeks 9-12): Polish + differentiation
├── Week 9-10: secret-scanner (proven category, easy adoption)
├── Week 10-11: dep-shield (supply chain, DevSecOps signal)
├── Week 11-12: vuln-priority (business acumen signal)
└── prompt-armor (AI security differentiator, if time)
```

---

## HOW THESE MAP TO YOUR RESUME

| Resume Claim | Project That Proves It |
|-------------|----------------------|
| "Developed 25+ custom SIEM correlation rules" | **threat-hunt-queries** - here are 50+ queries I wrote |
| "Audited IAM and security configurations across 50+ AWS assets" | **aws-security-auditor** - here's the tool I use |
| "Engineered Python scripts to automate SOC alert triage" | **alert-triage** - here's the actual automation |
| "Guided 60+ grad students in DFIR" | **forensic-timeline** - here's the tool I built for teaching |
| "Neutralized live cryptojacking and data exfiltration" | **forensic-timeline** - here's how I reconstruct incidents |
| "AV/EDR evasion, AD exploitation (OSEP, CRTE)" | **ad-escalation-audit** - I find the paths I would exploit |
| "AWS IAM, S3, EC2, Lambda, VPC (AWS Specialty)" | **aws-security-auditor** - automated cloud audit |
| "Python, Bash, PowerShell automation" | **Every single project** - all Python CLI tools |

---

## GITHUB PIN ORDER (Once Built)

Pin these 4-6 on your GitHub profile:
1. **aws-security-auditor** - Cloud security (matches AWS cert)
2. **threat-hunt-queries** - Detection engineering (matches SIEM experience)
3. **ad-escalation-audit** - Offensive security (matches OSEP/CRTE)
4. **forensic-timeline** - DFIR (matches teaching + IR experience)
5. **alert-triage** - SOC automation (matches Phoenix Global work)
6. **prompt-armor** - Forward-looking (AI security differentiator)

---

## WHAT EACH PROJECT README NEEDS (Entry-Level Version)

Keep it simple. No Docusaurus sites. No ONNX runtimes. Just:

```markdown
# project-name

One line: what it does.

## The Problem
2-3 sentences with a real stat.

## Installation
pip install project-name
# or
git clone ... && pip install -e .

## Usage
# 3-5 copy-paste examples showing real output

## Example Output
[Screenshot or terminal output]

## How It Works
[Simple diagram or bullet list]

## Detection Coverage / Checks Performed
[Table mapping to MITRE ATT&CK / CIS Benchmarks / OWASP]

## License
MIT
```

**No over-engineering.** A clean Python CLI with good output and clear README beats a half-finished Go microservice with a React dashboard every time.

---

## BOTTOM LINE

**You don't need 50 projects. You need 6-8 FINISHED ones that back up every line on your resume.**

Your certs are already way above entry-level average. What's missing is proof-of-work that a hiring manager can click on, run, and see results in 30 seconds. Every project above is designed to be:

1. **Completable** in 1-3 weeks (not months)
2. **Runnable** with one command
3. **Directly tied** to a resume bullet point
4. **Python-based** (your strongest language)
5. **Useful** to real security teams (not just academic)

The 50 projects file is still your long-term backlog. But **these 10 are what get you hired.**
