# CERT-Evaluator AI Prototype

Streamlit tooling for inspecting Coverity findings, running an OpenAI agent to propose fixes, and scoring those fixes against the CERT-C rubric.

## Project layout
- `main.py` – Streamlit UI tying together data selection, the fix agent, and rubric evaluation.
- `coverity/` – Coverity CSV normalisation and CWE mapping helpers ([README](coverity/README.md)).
- `cert_c/` – Scraper and loaders for the CERT-C rule dataset ([README](cert_c/README.md)).
- `fix_agent/` – OpenAI agent that drafts fixes for a Coverity finding ([README](fix_agent/README.md)).
- `evaluator/` – Gemini-based rubric evaluator used to score the agent output ([README](evaluator/README.md)).
- `requirements.txt` – single dependency set shared by all components.

## Requirements
- Python 3.9 or newer.
- Access to the managed services used by the tooling:
  - Google Generative AI (Gemini 2.5 Flash) – for rubric evaluation.
  - OpenAI API + GitHub MCP server – for the fix agent.
  - Optional: Coverity Scan export and internet access to refresh datasets.

## Setup
1. Create and activate a Python virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Define credentials in `.env` (loaded automatically by `python-dotenv`):
   ```env
   # Required for rubric evaluation
   GOOGLE_API_KEY=your_gemini_key

   # Required for the mcp fix agent
   OPENAI_API_KEY=sk-...
   NO_PRIVILGE_GITHUB_PERSONAL_ACCESS_TOKEN=ghp_public_read_only
   ```
4. Ensure the data files referenced by the app are present:
   - `cert_c/certc_rules.json` – run the scraper if you need to refresh it.
   - `coverity/coverity_issues.csv` – convert your Coverity export via `python -m coverity.coverity`.

## Run the Streamlit app
Launch the end-to-end UI from the repository root:

```bash
streamlit run main.py
```

The sidebar lets you choose a CERT-C rule and relatd Coverity CID. You can then:
- Trigger the **Fix agent** to call OpenAI via MCP and cache the result.
- Run the **Rubric evaluation** to score the agent output with Gemini.

## Useful CLI entry points
- Refresh CERT-C rule data: `python -m cert_c.scrape`
- Convert Coverity CSV exports: `python -m coverity.coverity`
- Scrape CWE → CERT-C mappings: `python -m coverity.scrape_cwe`
- Run the fix agent sample: `python -m fix_agent.fix_agent`
- Execute a rubric-only evaluation: `python -m evaluator.evaluator`

For deeper instructions and troubleshooting tips, refer to the README inside each sub-directory.
