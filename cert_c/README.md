# CERT-C Rule Dataset

Tools for collecting the SEI CERT C Coding Standard and packaging it for the evaluator UI.

## What lives here
- `scrape.py` – crawls the public wiki and materializes rules, examples, and risk assessment data.
- `load_rules.py` – lightweight helpers for reading the JSON dataset at runtime.
- `certc_rules.json` / `certc_rules.jsonl` – cached outputs checked into the repo for convenience.

## Requirements
- Python 3.9 or newer.
- Install dependencies from the repository root: `pip install -r requirements.txt`.
- Outbound HTTPS access to `wiki.sei.cmu.edu` when running the scraper.

## Generate the dataset
Run the crawler from the project root to refresh both JSON artifacts:

```bash
python -m cert_c.scrape \
  --base-page "https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard" \
  --domain "wiki.sei.cmu.edu" \
  --timeout 15 \
  --sleep 0.2 \
  --out-json cert_c/certc_rules.json \
  --out-jsonl cert_c/certc_rules.jsonl
```

The default arguments match the command above, so a simple `python -m cert_c.scrape` is usually sufficient. Expect the crawl to take several minutes and be respectful of the public wiki (increase `--sleep` if you see throttling).

## Using the data
Load CERT-C definitions directly in Python:

```python
from cert_c import load_rules, load_rule_by_id

rules = load_rules()
api_rule = load_rule_by_id("API00-C")
```

Each rule dictionary contains structured fields for the description, paired compliant/noncompliant examples, and the risk assessment block with metrics.

## Tips
- The crawler retries transient HTTP errors and will skip pages that consistently fail; rerun later if necessary.
- Regenerate the dataset periodically to keep pace with upstream CERT-C updates.
