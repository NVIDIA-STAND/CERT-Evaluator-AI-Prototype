# Fix Agent

Automates a Coverity remediation workflow using the OpenAI Agents SDK and the GitHub MCP server. Given a Coverity finding, the agent inspects the repository at a pinned commit, explains the issue, and proposes a patch.

## What lives here
- `fix_agent.py` – orchestrates the agent run, caching, and environment configuration.
- `fix_cache.json` – optional cache of previous runs (populated automatically).
- `__init__.py` – re-exports the public API (`fix_issue`, `AgentFixResult`, and constants).

## Requirements
- Python 3.9 or newer.
- Install dependencies from the project root: `pip install -r requirements.txt` (notably `openai`, `openai-agents`, `mcp`, and `python-dotenv`).
- Outbound HTTPS access to GitHub and the configured MCP endpoint.
- Environment variables:
  - `OPENAI_API_KEY` – used for the underlying model (`gpt-4.1-mini`).
  - `NO_PRIVILGE_GITHUB_PERSONAL_ACCESS_TOKEN` – classic GitHub PAT with **no scopes** for anonymous, read-only access (required by the MCP server).
  - Optional overrides:
    - `GITHUB_MCP_URL` (default: `https://api.githubcopilot.com/mcp/`)
    - `EVAL_CACHE_PATH` (defaults to `./fix_agent/fix_cache.json`)
    - `FORCE_REGENERATE` (set to `1`/`true` to bypass the cache)

## Configure credentials
Store the values in `.env` at the project root so `python-dotenv` loads them on import:

```env
OPENAI_API_KEY=sk-...
NO_PRIVILGE_GITHUB_PERSONAL_ACCESS_TOKEN=ghp_your_pat
GITHUB_MCP_URL=https://api.githubcopilot.com/mcp/
```

## Run the agent
Trigger a fix for a specific Coverity CID (uses the repo snapshot defined in `coverity/coverity.py`):

```bash
python -m fix_agent.fix_agent
```

The script loads the sample Coverity issue `473947`, invokes the agent, prints the structured response, and caches the result. Programmatically you can call `fix_issue(issue)` to reuse the logic from other modules or the Streamlit UI.

## Output shape
`fix_issue` returns an `AgentFixResult` dictionary containing:
- `identified_severity`
- `identified_priority`
- `explanation`
- `fix_description`
- `patch` (unified diff)

The Streamlit app displays this data in the “Agent generated fix” panel.
