# Cloud Security Posture Checker

> **AWS IAM & S3 Policy Misconfiguration Analyzer**  
> A Gradio-powered security tool that audits AWS JSON policy files against industry-standard security controls — surfacing critical misconfigurations before they become breaches.

---

## Overview

The **Cloud Security Posture Checker** is a portfolio-grade application designed to demonstrate practical cloud security expertise. It accepts AWS IAM policies, S3 bucket policies, and AWS config JSON files, then runs them through a suite of automated security checks aligned with AWS best practices and the principle of least privilege.

Built for security practitioners who understand that misconfigured policies — not zero-days — are the leading cause of cloud data breaches.

---

## Features

| Capability | Detail |
|---|---|
| **7 Security Checks** | CRITICAL through LOW severity across IAM and S3 controls |
| **Risk Scoring** | Weighted aggregate score (0–100) with risk classification |
| **3-Tab Report** | Summary · Detailed Findings · Remediation Steps |
| **Sample Configs** | 4 built-in demo policies (clean and misconfigured) |
| **AWS Docs Links** | Direct remediation references for every finding |
| **File or Paste** | Upload `.json` or paste content directly |

---

## Security Checks

| ID | Check | Severity |
|---|---|---|
| IAM-001 | Wildcard Action (`Action: *`) | 🔴 CRITICAL |
| IAM-002 | Wildcard Resource with Sensitive Actions | 🟠 HIGH |
| IAM-003 | Sensitive Actions Missing MFA Condition | 🟠 HIGH |
| IAM-004 | Allow Statements Without Conditions | 🟡 MEDIUM |
| IAM-005 | Outdated Policy Language Version | 🟢 LOW |
| S3-001 | Public Principal (`Principal: *`) | 🔴 CRITICAL |
| S3-002 | Public S3 Write Access | 🔴 CRITICAL |

---

## Demo

### Misconfigured Policy Input
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Principal": "*"
    }
  ]
}
```

### Output
- **Risk Score:** 100 — CRITICAL RISK  
- **Findings:** IAM-001 (CRITICAL), S3-001 (CRITICAL), S3-002 (CRITICAL), IAM-002 (HIGH), IAM-003 (HIGH), IAM-004 (MEDIUM), IAM-005 (LOW)  
- **Remediation:** Step-by-step fixes with direct AWS documentation links

---

## Project Structure

```
cloud-posture-checker/
├── app/
│   ├── __init__.py
│   ├── main.py          # Gradio UI and entry point
│   ├── checks.py        # Security check engine (7 checks)
│   └── report.py        # HTML report generator
├── sample_configs/
│   ├── misconfigured_iam.json
│   ├── open_s3_bucket.json
│   └── secure_policy.json
├── tests/
│   └── test_checks.py   # 18 unit tests (pytest)
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Getting Started

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/kobiawilliams/cloud-posture-checker.git
cd cloud-posture-checker

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Run the App

```bash
python -m app.main
```

Open your browser at `http://localhost:7860`

### Run Tests

```bash
pytest tests/ -v
```

---

## Usage

1. **Upload** a `.json` AWS policy file **or** paste JSON content directly into the editor
2. Optionally select a **Sample Config** from the dropdown and click **Load** to explore demo scenarios
3. Click **🔍 Analyze Config**
4. Review results across three tabs:
   - **Summary** — Risk score, severity breakdown, pass/fail list
   - **Findings** — Per-check description and affected statements
   - **Remediation** — Prioritized fix instructions with AWS documentation links

---

## Technical Design

**Separation of concerns:**
- `checks.py` — Pure functions, each returning a typed `Finding` dataclass. Zero UI coupling.
- `report.py` — Converts findings into styled HTML. Independently testable.
- `main.py` — Gradio wiring only. Loads UI, binds events, delegates all logic.

This architecture makes adding new checks straightforward: define a function in `checks.py`, register it in `run_all_checks()`, and the report generation handles the rest automatically.

---

## Roadmap

- [ ] YAML config file support (AWS Config Rules, CloudFormation)
- [ ] Additional checks: KMS key policies, VPC security groups, CloudTrail logging
- [ ] Export report as PDF
- [ ] AWS Organizations / multi-account scanning
- [ ] CVE enrichment integration (see companion project: `cve-lookup-tool`)

---

## About

Built by **Kobia Williams** — Network Security Administrator transitioning into Cloud Security Engineering.

With a decade of network engineering experience (CCNA, CEH, ISO/IEC 27001) and deep expertise in infrastructure security, I build tools that bridge traditional security fundamentals with modern cloud environments.

- 🔗 [LinkedIn](https://linkedin.com/in/kobiawilliams)
- 🐙 [GitHub](https://github.com/kobiawilliams)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
