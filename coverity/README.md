# Coverity Issue Toolkit

Utilities for normalising Coverity CSV exports, enriching them with helpful links, and discovering related CERT-C rules.

## What lives here
- `coverity.py` – converts raw Coverity exports, loads individual findings, and builds GitHub/Coverity/CWE links.
- `scrape_cwe.py` – fetches CWE → CERT-C mappings and persists them in `cwe_mappings.json`.
- `coverity_issues_raw.csv` – sample export downloaded from Coverity Scan (checked in for local experiments).
- `coverity_issues.csv` – trimmed dataset generated from the raw export.
- `cwe_mappings.json` – Cache of scraped mappings.

## Requirements
- Python 3.9 or newer.
- Install dependencies from the project root: `pip install -r requirements.txt` (requires `pandas`, `requests`, and `beautifulsoup4`).
- Outbound HTTPS access to `scan.coverity.com` and `cwe.mitre.org` when refreshing data.

## Prepare a trimmed CSV
1. Download the project’s findings from Coverity Scan as CSV and save it to `coverity/coverity_issues_raw.csv`.
2. Run the converter to keep just the evaluator-facing columns:

```bash
python -m coverity.coverity
```

The script writes `coverity_issues.csv` in the same directory. Point the Streamlit app at this file to populate the issue selector.

## Load issues programmatically

```python
from coverity import load_coverity_issue, get_coverity_issue_cids

cids = get_coverity_issue_cids()
issue = load_coverity_issue(cids[0])
print(issue["github_link"], issue["cwe_link"])
```

Each `CoverityIssue` record includes convenience links for GitHub, Coverity Scan, and the CWE reference.

## Build CWE → CERT-C mappings
Generate or refresh the optional `cwe_mappings.json` file (requires network access):

```bash
python -m coverity.scrape_cwe
```

The script enumerates unique CWEs from `coverity_issues.csv`, scrapes each CWE page, and stores the related CERT-C rule IDs. You can then query the mappings in code via `get_related_certc_cids`.
