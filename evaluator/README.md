# Rubric Evaluator

LLM-backed scoring for agent-produced fixes. Given a Coverity finding, the AI-generated fix analysis, and optional CERT-C rule context, this module fills out the rubric used in the Streamlit UI.

## What lives here
- `evaluator.py` – core logic that loads the rubric, builds the Gemini prompt, and normalises the JSON response.
- `rubric.json` – default rubric consumed by the evaluator and the UI.
- `__init__.py` – convenience exports for use elsewhere in the repo.

## Requirements
- Python 3.9 or newer.
- Install dependencies from the repository root: `pip install -r requirements.txt` (notably `langchain`, `langchain-google-genai`, and `python-dotenv`).
- A Google Generative AI API key (`GOOGLE_API_KEY`) with access to Gemini 2.5 Flash.
- Optional: generated data from `cert_c/` and issue metadata from `coverity/` when running standalone examples.

## Configure credentials
Create (or update) the project-level `.env` file so `python-dotenv` can pick up the key:

```env
GOOGLE_API_KEY=your_gemini_key
```

## Run an evaluation
Provide a Coverity issue, the agent’s fix output, and (optionally) a CERT-C rule:

```python
from evaluator import load_rubric, evaluate_example
from coverity import load_coverity_issue
from fix_agent import fix_issue
import asyncio

rubric = load_rubric()
issue = load_coverity_issue("473951")
agent_fix = asyncio.run(fix_issue(issue))
result = evaluate_example(rubric, agent_fix, issue)
```

When executed as `python -m evaluator.evaluator`, the module performs the same flow using the sample data shipped with the repository and prints the resulting rubric completion.

## Integration in the UI
The Streamlit app (`main.py`) imports `evaluate_example` to populate the “Rubric-Based LLM Evaluation” panel. Ensure the API key is configured before launching the UI so the table renders populated scores.
