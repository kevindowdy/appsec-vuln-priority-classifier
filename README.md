# appsec-vuln-priority-classifier

This script processes large application security vulnerability datasets — up to 800k+ rows — to produce a prioritized, leader-attributed vulnerability report. It ingests open vulnerability exports and a trusted app inventory, excludes vulnerabilities already being actively managed in a WAR Room (tracked via a composite hash of app ID, version, and instance ID), and classifies remaining vulnerabilities into two priority tiers based on severity: P1 (Critical & High) and P2 (Medium & Low). The output is a clean CSV ready for pivot table analysis or executive reporting in seconds.

---

## Priority Definitions

| Priority | Severities | Condition |
|----------|-----------|-----------|
| P1 | Critical, High | Not in WAR Room |
| P2 | Medium, Low | Not in WAR Room |

WAR Room vulnerabilities are those actively being tracked in escalated priority groups (1e, 7a, 7b) and are excluded from this report.

---

## Prerequisites

- Python 3.8+
- pandas

Install dependencies:
```bash
pip install pandas
```

### Required Input Files

| File | Description |
|------|-------------|
| `APPLICATION - Insight Export - ... - Priority - 1e OWASP Top 10.csv` | WAR Room group 1e vulnerabilities |
| `APPLICATION - Insight Export - ... - Priority - 7a OWASP Top 10 - Tier 1.csv` | WAR Room group 7a vulnerabilities |
| `APPLICATION - Insight Export - ... - Priority - 7b OWASP Top 10 - Tier 2.csv` | WAR Room group 7b vulnerabilities |
| `FIG Open Vulnerabilities_[date].xlsx` | Open Critical, High, and Medium vulnerabilities |
| `FIG Open Vulnerabilities_Low_[date].xlsx` | Open Low vulnerabilities (separate export) |
| `App Inventory_Enriched 1.xlsx` | Trusted app inventory used to resolve accurate ownership (MC-2) |

**Note:** Low severity vulnerabilities are exported separately and merged during processing. Ensure both vulnerability files are present before running.

---

## Instructions

1. Clone this repository
```bash
git clone https://github.com/your-username/appsec-vuln-priority-classifier.git
cd appsec-vuln-priority-classifier
```

2. Place all required input files in your `Downloads` folder or update `base_path` in the script to match your file location

3. Open `main.py` and set your Windows username at the top of `main()`:
```python
username = "your-username"
```

4. Run the script:
```bash
python main.py
```

5. The output file `Vulnerabilities-excluding-war-room.csv` will be written to your `base_path` directory

---

## Output

The output CSV contains all open vulnerabilities excluding WAR Room entries, enriched with:
- **Priority tier** (P1 or P2) based on severity
- **MC-2 ownership** sourced from the trusted enriched app inventory rather than the CMDB, which may reflect stale or in-flight org changes

Load the output into Excel and use a pivot table to slice by leader, priority, severity, or business division.

---

## Notes

- Deduplication between the WAR Room and open vulnerability datasets is performed using a composite hash of `App ID + Release Version + Instance ID`
- CMDB-sourced ownership data may be unreliable during organizational transitions; the enriched app inventory is used as the trusted source for MC-2 attribution
- This script was built to handle datasets that exceed Excel's practical row limit for in-memory processing
- Vulnerability data ingestion from source system still presents a challenge due to the large size of the data sets which requires chunking of the vulnerabilities by severity and other attributes prior to running the script.