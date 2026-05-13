# STRATEGIC PROJECT PRIORITY ROADMAP
## Build Order Optimized for Career Impact & Getting Hired

> Prioritized based on: your OSEP/CRTE/AWS profile, hiring manager research,
> open-source success patterns, skills gap data, and salary impact analysis.

---

## PRIORITIZATION FRAMEWORK

Each project scored on 5 dimensions (1-5 scale):

- **Profile Alignment** - Does it use your OSEP/CRTE/AWS/DFIR strengths?
- **Skills Gap Match** - Does it address what employers can't find (AI, cloud, zero trust, DFIR)?
- **Portfolio Differentiation** - Will it make you stand out vs other candidates?
- **Open-Source Traction Potential** - Could this get stars and real users?
- **Career Velocity** - Does it unlock higher-paying roles?

---

## TIER 1: FLAGSHIP PROJECTS (Build First - Your GitHub Pins)
> These 5 projects become your portfolio. Build them production-grade.
> Together they tell the story: "I build real security tools that solve real problems."

### FLAGSHIP 1: PromptArmor (Project #14) - LLM Prompt Injection Firewall
**Priority Score: 25/25** (5+5+5+5+5)
**Why Build First:**
- AI/ML Security has the **#1 skills shortage** (34% critical) - this instantly fills your biggest gap
- AI Red Teamer roles pay $160K-$225K and are exploding
- Prompt injection is **OWASP LLM #1** - the hottest problem in security right now
- No dominant open-source solution exists yet - **greenfield opportunity**
- Directly parallels how Nuclei dominated vuln scanning: template-based, community-driven
- Shows you're not just a pentester - you understand where the field is moving

**Upgraded Architecture:**
```
promptarmor/
├── cmd/                      # CLI entry points (Go)
│   └── promptarmor/main.go   # Single binary
├── pkg/
│   ├── engine/               # Core detection engine
│   │   ├── pattern.go        # Regex/pattern-based detection
│   │   ├── semantic.go       # Embedding-based semantic analysis
│   │   ├── boundary.go       # Instruction hierarchy enforcement
│   │   └── classifier.go     # ML classifier (ONNX runtime)
│   ├── proxy/                # HTTP reverse proxy for LLM APIs
│   ├── rules/                # YAML rule definitions (Nuclei-style)
│   ├── reporter/             # Output: JSON, SARIF, CEF, webhook
│   └── api/                  # gRPC + REST API
├── rules/                    # Community-contributed detection rules
│   ├── direct-injection/
│   ├── indirect-injection/
│   ├── jailbreak/
│   └── data-exfil/
├── sdk/
│   ├── python/               # pip install promptarmor
│   └── javascript/           # npm install promptarmor
├── dashboard/                # React monitoring UI
├── tests/
│   ├── unit/
│   ├── integration/
│   └── benchmarks/           # Against known injection datasets
├── docs/                     # Docusaurus site
├── .github/workflows/        # CI/CD, release automation
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
└── Dockerfile
```

**Key Decisions:**
- **Go** for core (single binary, fast proxy, cross-platform)
- **YAML rules** for extensibility (community contributes without touching Go code)
- **ONNX Runtime** for ML inference (no Python dependency in production)
- SDKs in Python + JS for developers to integrate in 3 lines of code
- Benchmark against published prompt injection datasets (report detection rate + latency)

**Career Signal:** "I identified the #1 emerging threat in AI security and built a production-grade defense before most companies even had a plan."

---

### FLAGSHIP 2: CloudMisconfig-Hunter (Project #28) - Multi-Cloud Security Scanner
**Priority Score: 24/25** (5+5+4+5+5)
**Why Build Second:**
- Cloud security is **#2 skills shortage** (30%) - your AWS Specialty + this tool = unstoppable
- Prowler (13.5K stars, $12.5M raised) proves this exact category creates careers and companies
- You already have deep AWS hands-on from your work at SportsExcitement and Phoenix Global
- Directly demonstrates the skills for $160K-$200K+ cloud security roles
- Multi-cloud (AWS + Azure + GCP) is what enterprises desperately need

**Upgraded Architecture:**
```
cloudmisconfig-hunter/
├── cmd/
│   └── cmh/main.go              # Single binary CLI
├── pkg/
│   ├── providers/
│   │   ├── aws/                  # AWS checks (IAM, S3, EC2, Lambda, VPC, KMS)
│   │   ├── azure/                # Azure checks (RBAC, Storage, VNet, KeyVault)
│   │   └── gcp/                  # GCP checks (IAM, GCS, VPC, KMS)
│   ├── checks/                   # Check definitions (YAML - CIS Benchmark mapped)
│   │   ├── aws/
│   │   ├── azure/
│   │   └── gcp/
│   ├── engine/                   # Check execution engine (parallel, rate-limited)
│   ├── reporter/                 # JSON, CSV, SARIF, HTML, ASFF (Security Hub)
│   ├── compliance/               # CIS, SOC2, PCI-DSS, HIPAA, NIST 800-53 mapping
│   ├── remediation/              # Auto-fix with approval workflow
│   └── api/                      # gRPC + REST
├── dashboard/                    # React compliance dashboard
├── policies/                     # OPA/Rego policy definitions
├── tests/
│   ├── unit/
│   ├── integration/              # Against LocalStack / test accounts
│   └── compliance_validation/    # Verify CIS benchmark accuracy
├── docs/
├── .github/workflows/
├── SECURITY.md
└── Dockerfile
```

**Key Decisions:**
- **Go** (matches Prowler's competitor Trivy, single binary distribution)
- **YAML check definitions** with CIS Benchmark IDs embedded
- **OPA/Rego** for custom policy-as-code
- **ASFF output** for native AWS Security Hub integration
- Auto-remediation with **dry-run mode** and approval workflow (critical for enterprise trust)
- Compliance mapping built-in (one scan covers CIS + SOC2 + PCI-DSS + HIPAA + NIST)

**Career Signal:** "I built a cloud security scanner that covers all three major clouds, maps to 5 compliance frameworks, and provides auto-remediation - exactly what my current employer needed but couldn't find commercially."

---

### FLAGSHIP 3: AlertFusion (Project #43) - ML-Powered Alert Correlation Engine
**Priority Score: 23/25** (4+5+5+4+5)
**Why Build Third:**
- SOC alert fatigue is the **#1 operational problem** - 3,000+ alerts/day, 30% missed
- Shows your DFIR/blue team depth alongside your red team skills = **purple team proof**
- Custom SIEM correlation was literally your job at Phoenix Global (25+ rules, 30% FP reduction)
- Demonstrates ML/data engineering skills that unlock Staff/Principal roles
- Every security team on Earth needs this - massive adoption potential

**Upgraded Architecture:**
```
alertfusion/
├── cmd/
│   └── alertfusion/main.go
├── pkg/
│   ├── ingest/                  # Multi-source ingestion
│   │   ├── syslog.go            # Syslog receiver (UDP/TCP/TLS)
│   │   ├── webhook.go           # Generic webhook receiver
│   │   ├── kafka.go             # Kafka consumer
│   │   └── adapters/            # SIEM-specific adapters
│   │       ├── splunk.go
│   │       ├── elastic.go
│   │       └── sentinel.go
│   ├── normalize/               # Event normalization to common schema
│   ├── correlate/
│   │   ├── dedup.go             # Deduplication engine
│   │   ├── cluster.go           # HDBSCAN alert clustering
│   │   ├── graph.go             # Graph-based correlation (attack chain detection)
│   │   └── temporal.go          # Time-window correlation
│   ├── enrich/                  # Threat intel, GeoIP, asset context
│   ├── score/                   # Priority scoring (ML + heuristic)
│   ├── reporter/                # Output: Jira, PagerDuty, Slack, webhook
│   └── api/
├── ml/
│   ├── training/                # Python training pipeline
│   ├── models/                  # Serialized models (ONNX)
│   └── evaluation/              # Benchmarks against BETH dataset
├── dashboard/                   # React SOC analyst workbench
├── tests/
├── docs/
└── docker-compose.yml           # Full stack deployment
```

**Key Decisions:**
- **Go** for the ingestion/correlation pipeline (performance critical - thousands of events/sec)
- **Python** for ML training, **ONNX** for production inference
- **HDBSCAN** for clustering (handles variable-density alert patterns)
- **Graph correlation** to detect multi-stage attack chains (not just individual alerts)
- Benchmark: measure noise reduction ratio (goal: 3000 alerts -> <50 incidents)
- SOC analyst workbench with MTTA/MTTR metrics

**Career Signal:** "I built a tool that reduces 3,000 daily alerts to 50 actionable incidents using ML correlation - something I wished I had when I was building SIEM rules at Phoenix Global."

---

### FLAGSHIP 4: FilelessHunter (Project #5) - Memory-Only Malware Detection
**Priority Score: 23/25** (5+4+5+4+5)
**Why Build Fourth:**
- Directly showcases your **OSEP + red team expertise** on the defensive side
- You know exactly how AV/EDR evasion works (your core skill) - now build the detector
- Memory forensics aligns with your DFIR teaching experience at UMD
- Shows you can think like an attacker AND a defender simultaneously
- No good open-source real-time memory scanner exists - **blue ocean**

**Upgraded Architecture:**
```
fileless-hunter/
├── cmd/
│   ├── fh-agent/main.go        # Endpoint agent (lightweight daemon)
│   └── fh-analyze/main.go      # Offline forensic analyzer
├── pkg/
│   ├── scanner/
│   │   ├── memory.go            # Process memory scanning
│   │   ├── shellcode.go         # Shellcode pattern detection
│   │   ├── injection.go         # DLL injection / process hollowing detection
│   │   ├── hollowing.go         # Process hollowing (PEB mismatch)
│   │   └── lolbin.go            # LOLBin abuse chain detection
│   ├── hooks/
│   │   ├── etw_windows.go       # Windows ETW provider
│   │   └── ebpf_linux.go        # Linux eBPF hooks
│   ├── signatures/              # YARA + custom Sigma rules
│   │   ├── cobalt_strike.yar
│   │   ├── sliver.yar
│   │   ├── meterpreter.yar
│   │   └── custom/
│   ├── reporter/
│   └── api/
├── signatures/                  # Community-contributed detection rules
├── tests/
│   ├── unit/
│   └── detection/               # Test against Cobalt Strike, Sliver, Meterpreter artifacts
├── docs/
└── Dockerfile
```

**Key Decisions:**
- **Go + CGo** for core (memory access, OS-level APIs)
- Dual-mode: **real-time agent** (daemon) + **offline forensic analyzer** (CLI)
- Detection rules for **Cobalt Strike, Sliver, Meterpreter, Brute Ratel** (the C2s you know)
- YARA integration for community extensibility
- Benchmark: detection rate against C2 frameworks in sandboxed environment

**Career Signal:** "I used my offensive security expertise (OSEP, Cobalt Strike, Sliver) to build a defense tool that catches the exact techniques I use during red team engagements. I wrote YARA signatures for C2 frameworks I've operated."

---

### FLAGSHIP 5: DepShield (Project #8) - Supply Chain Attack Detection Pipeline
**Priority Score: 22/25** (4+4+5+5+4)
**Why Build Fifth:**
- Supply chain attacks doubled in 2025 ($60B losses) - massive problem, massive attention
- Gitleaks (25.8K stars) and TruffleHog (25.6K, $40M raised) prove this category creates careers
- Directly integrates into every developer's workflow (CI/CD) = viral adoption potential
- Shows software engineering maturity (CI/CD, AST parsing, package ecosystems)
- Complements your cloud security story (supply chain -> cloud deployment -> runtime)

**Upgraded Architecture:**
```
depshield/
├── cmd/
│   └── depshield/main.go
├── pkg/
│   ├── registries/              # Package registry clients
│   │   ├── npm.go
│   │   ├── pypi.go
│   │   ├── rubygems.go
│   │   └── crates.go
│   ├── analyzers/
│   │   ├── typosquat.go         # Levenshtein + phonetic matching
│   │   ├── scripts.go           # Post-install script analysis
│   │   ├── maintainer.go        # Maintainer change detection
│   │   ├── obfuscation.go       # Code obfuscation detection
│   │   └── behavioral.go        # Historical baseline comparison
│   ├── policy/                  # OPA policy engine
│   ├── reporter/                # JSON, SARIF, GitHub PR comments
│   └── api/
├── integrations/
│   ├── github-action/           # GitHub Actions integration
│   ├── gitlab-ci/               # GitLab CI template
│   └── pre-commit/              # Pre-commit hook
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/                # Known-malicious package samples
├── docs/
└── Dockerfile
```

**Career Signal:** "I built the tool that catches the next Shai-Hulud before it enters your build pipeline."

---

## TIER 2: HIGH-VALUE PROJECTS (Build Months 3-6)
> These deepen your expertise in high-demand areas.

| Priority | # | Project | Why Now | Aligns With |
|----------|---|---------|---------|-------------|
| 6 | 14 | PromptArmor *(already Tier 1)* | - | - |
| 7 | 25 | **PrivEsc-Detector** | Your CRTE + BloodHound expertise - build the automated scanner | Red team |
| 8 | 22 | **TokenShield** | Token theft = 31% of M365 breaches - hot identity problem | Cloud + DFIR |
| 9 | 12 | **PatchPulse** | Vuln prioritization is what every CISO wants - shows business acumen | Risk management |
| 10 | 20 | **LLM-Vuln-Scanner** | "The Burp Suite for LLM apps" - pairs perfectly with PromptArmor | AI security |
| 11 | 34 | **OT-Sentinel** | OT security is massive gap - rare skill set commands premium | DFIR + detection |
| 12 | 11 | **GitLeaks-Pro** | Proven category (Gitleaks=25K stars) - your ML twist differentiates | Supply chain |
| 13 | 47 | **ForensicTimeline** | Leverages your DFIR teaching experience directly | DFIR |
| 14 | 29 | **K8s-SecOps** | K8s is everywhere, eBPF runtime security is hot | Cloud + detection |
| 15 | 3 | **MalwareGenome** | Malware analysis platform - pairs with your DFIR background | DFIR |

---

## TIER 3: SPECIALIZATION PROJECTS (Build Months 6-12)
> These target specific niches and build domain depth.

| Priority | # | Project | Strategic Value |
|----------|---|---------|----------------|
| 16 | 16 | DeepFakeDetect | AI security portfolio depth |
| 17 | 18 | RAG-Shield | Enterprise AI security - hot market |
| 18 | 30 | API-Sentinel | Pairs with cloud security story |
| 19 | 45 | ThreatHunt-Assist | Shows your hunting methodology as a product |
| 20 | 23 | CredBreach-Monitor | Identity security depth |
| 21 | 46 | PhishNet | AI + social engineering defense |
| 22 | 10 | ContainerLock | Container supply chain |
| 23 | 9 | SBOM-Sentinel | Compliance + supply chain |
| 24 | 31 | InfraAsCode-Sec | DevSecOps shift-left |
| 25 | 44 | IRPlaybook-Engine | DFIR automation |
| 26 | 19 | AIAgent-Firewall | Frontier AI-agent security |
| 27 | 1 | RansomShield | Complex endpoint agent - high reward |
| 28 | 39 | ComplianceOS | Compliance automation |
| 29 | 24 | MFA-Fortress | Identity hardening |
| 30 | 48 | QuantumReady | Future-proofing |

---

## TIER 4: DEPTH & BREADTH (Build Months 12+)
> Remaining projects for portfolio completeness.

| Priority | # | Project | Strategic Value |
|----------|---|---------|----------------|
| 31 | 17 | ModelGuard | ML security testing |
| 32 | 15 | ShadowAI-Detect | Enterprise AI governance |
| 33 | 21 | DataLeakAI | AI-aware DLP |
| 34 | 27 | IAM-Hygiene | Identity attack surface |
| 35 | 26 | ZeroTrust-Audit | Zero trust assessment |
| 36 | 33 | ServerlessGuard | Serverless security |
| 37 | 32 | CloudForensics | Cloud IR toolkit |
| 38 | 13 | ThirdPartyRisk | Vendor risk management |
| 39 | 37 | OT-AssetDiscovery | OT asset visibility |
| 40 | 35 | SCADA-Hardener | SCADA hardening |
| 41 | 2 | BackupGuard | Backup integrity |
| 42 | 7 | DecryptorForge | Ransomware recovery |
| 43 | 4 | CryptoTracer | Blockchain forensics |
| 44 | 6 | RaaS-Intel | Threat intelligence |
| 45 | 40 | IncidentReport-SEC | SEC compliance |
| 46 | 41 | PrivacyGuard | Privacy DPIA |
| 47 | 42 | PolicyBot | Policy generation |
| 48 | 38 | IT-OT-Bridge | IT/OT gateway |
| 49 | 36 | GridShield | Grid simulation |
| 50 | 49 | IoT-Fortress | IoT security |
| - | 50 | MobileThreat-Shield | Mobile (requires app store) |

---

## GITHUB PROFILE STRATEGY

### Pin These 5 Repos (In Order)
1. **promptarmor** - "LLM Prompt Injection Firewall" (AI security)
2. **cloudmisconfig-hunter** - "Multi-Cloud Security Scanner" (cloud security)
3. **alertfusion** - "ML-Powered Alert Correlation Engine" (detection engineering)
4. **fileless-hunter** - "Memory-Only Malware Detection Engine" (offensive → defensive)
5. **depshield** - "Supply Chain Attack Detection" (DevSecOps)

### The Story These Tell
Together, these 5 projects say:
> "I'm a security engineer who can secure AI systems, cloud infrastructure, SOC operations,
> detect advanced persistent threats in memory, and protect the software supply chain.
> I build production-grade tools in Go with plugin architectures, ML integration,
> SIEM output, and enterprise-ready documentation."

That's the **trilingual hybrid**: cybersecurity + software engineering + AI/ML.

### Naming Convention
Use kebab-case, descriptive names:
- `promptarmor` (not `project14` or `PA`)
- `cloudmisconfig-hunter` (not `cloud_scanner`)
- `fileless-hunter` (not `fh`)
- `alertfusion` (not `alert_tool`)
- `depshield` (not `dependency-checker`)

### README Template for Every Project
```markdown
<p align="center">
  <img src="docs/logo.svg" width="200">
  <h1 align="center">ProjectName</h1>
  <p align="center">One-line description of what it does</p>
</p>

<p align="center">
  <a href="..."><img src="https://img.shields.io/github/actions/workflow/status/..."></a>
  <a href="..."><img src="https://img.shields.io/codecov/c/github/..."></a>
  <a href="..."><img src="https://img.shields.io/github/license/..."></a>
  <a href="..."><img src="https://img.shields.io/docker/pulls/..."></a>
  <a href="..."><img src="https://img.shields.io/github/v/release/..."></a>
</p>

<!-- Terminal demo GIF here -->

## The Problem
[2-3 sentences with real stats]

## How It Works
[Architecture diagram]

## Quick Start
\`\`\`bash
# One-command install
go install github.com/yourusername/project@latest

# Or Docker
docker run --rm yourusername/project scan --target ...

# Basic usage
project scan --config config.yaml
\`\`\`

## Features
- Feature 1 with MITRE ATT&CK / OWASP mapping
- Feature 2
- Feature 3

## Detection Coverage
[Table mapping to MITRE ATT&CK or OWASP]

## Output Formats
JSON | SARIF | CEF | CSV | HTML | Webhook

## Benchmarks
[Detection rate, false positive rate, performance]

## Documentation
[Link to docs site]

## Contributing
[Link to CONTRIBUTING.md]

## Security
[Link to SECURITY.md]

## License
MIT / Apache 2.0
```

---

## WEEKLY CADENCE

### Sustainable Build Pace
| Day | Activity |
|-----|----------|
| Mon-Fri | 1-2 hours focused development on current flagship project |
| Saturday | Documentation, testing, polish |
| Sunday | Research, planning, community engagement (Twitter/X, blog) |

### Milestones Per Project
| Week | Target |
|------|--------|
| Week 1 | Research complete, architecture designed, repo initialized |
| Week 2-3 | Core engine working, basic CLI functional |
| Week 4 | Testing, CI/CD pipeline, multiple output formats |
| Week 5 | Dashboard/UI, documentation site |
| Week 6 | Polish, demo GIF, benchmarks, release v1.0.0 |

**6 weeks per flagship project = 5 flagships in ~7 months** (with overlapping research phases).

---

*Remember: 5 excellent projects > 50 mediocre ones. Build each one like it's going to be reviewed
by the hiring manager at your dream company - because it will be.*
