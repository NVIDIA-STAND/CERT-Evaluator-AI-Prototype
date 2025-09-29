# CERT-C Evaluator & Tooling

This repository is a small toolkit for evaluating LLM suggested fixes of CERT-C non-compliant code :

- `evaluator/` – a Streamlit app that scores AI-generated analyses and fixes against CERT-C guidance.
- `cert-c/` – scripts for scraping the SEI CERT C Coding Standard into JSON.
- `coverity/` – sample input payloads for the evaluator.

The sections below focus on getting the evaluator running; see `cert-c/README.md` for scraper details.

## Prerequisites

- Python 3.9+ 
- Optional: a virtual environment (recommended).
- Google API Key for Gemini LLM (for rubric-based evaluation)

## Installation

```bash
conda activate mqp    
pip install -r requirements.txt
```

## Environment Setup

Create a `.env` file in the project root with your Google API key:

```bash
# Get your API key from: https://makersuite.google.com/app/apikey
GOOGLE_API_KEY=your_google_api_key_here
```

## Required data files

The evaluator uses a set of JSON files alongside the app:

- `certc_rules.json` – structured CERT-C rule data. You can supply your own file or generate one via the scraper under `cert-c/`.
- `example_inputs.json` – optional example payloads that pre-fill the UI. The `coverity/` folder contains sample files.
- `evaluator/rubric.json` – rubric used to summarise evaluation metrics. A default version ships with the repo.

---

## Running the evaluator

```bash
# From the repository root
streamlit run evaluator/ui.py
```

## Features

The evaluator provides two types of analysis:

1. **Rubric-Based LLM Evaluation**: Uses Google's Gemini LLM to evaluate AI analysis against Coverity output using a comprehensive rubric. This provides detailed scoring and reasoning for each metric.

2. **Detailed Technical Evaluation**: Traditional similarity-based evaluation using BERTScore, SentenceTransformers, and TF-IDF for comparing AI outputs against CERT-C standards.

The rubric evaluation appears first and provides a comprehensive assessment, while the technical evaluation provides detailed similarity metrics and analysis.  


## Rubric  
| Metric                                              | Description                                                                                                | Evaluation Method                                                                                                                                                                                                                                                                                                    | Weight         |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| **Compilation Check**                               | Suggested fix must compile.                                                                                | `compile(ai.fix_code) == pass`                                                                                                                                                                                                                                                                                       | Hard 0 if fail |
| **Tests Check**                                     | All unit/regression/security tests (if provided) must pass.                                                | `tests(ai.fix_code) == pass`                                                                                                                                                                                                                                                                                         | Hard 0 if fail |
| **Static Analyzer Regression Check**                | No new issues; original finding resolved when applicable.                                                  | `coverity(ai.fix_code).new_issues == 0 AND (gold.violation == false OR coverity(ai.fix_code).resolves(rule_id=gold.rule_id) == true)`                                                                                                                                                                                | Hard 0 if fail |
| **False Positive Handling**                         | If the original finding is a false positive, the model must mark it compliant.                             | `(gold.violation == false) => (ai.violation == false)`                                                                                                                                                                                                                                                               | Hard 0 if fail |
| **Severity Alignment with CERT-C**                  | Predicted severity aligns with the rule’s gold severity.                                                   | `Score = {0->1.0, 1->0.7, 2->0.3, >=3 or unknown->0.0} where bucket = OrdinalDistance(ai.severity, gold.severity)`                                                                                                                                                                                                   | 10             |
| **Priority Alignment with CERT-C**                  | Predicted priority matches the rule’s gold priority (P1..P18).                                             | `lower(ai.priority) == lower(gold.priority)`                                                                                                                                                                                                                                                                         | 15             |
| **Issue Understanding**                             | Issue explanation matches the rule’s noncompliant rationale and examples (the AI understood what’s wrong). | `max( SimText(ai.issue_text, gold.noncompliant_blob), SimText(ai.issue_text, gold.rule_intro), CodeSim(ai.issue_code, gold.noncompliant_codes) )`                                                                                                                                                                    | 15             |
| **Fix Explanation Alignment**                       | Fix explanation aligns with compliant rationale, risk explanation, and rule description.                   | `good = max( SimText(ai.fix_text, gold.compliant_blob), SimText(ai.fix_text, gold.risk_expl), SimText(ai.fix_text, gold.rule_intro) ); bad = SimText(ai.fix_text, gold.noncompliant_blob); gap = good - bad; Score buckets: OK if (good>=0.65 and gap>=0.20), Partial if (good>=0.40 and gap>=0.10), else Misguided` | 20             |
| **Fix Code Similarity to Compliant Examples**       | Fix code resembles official compliant examples.                                                            | `CodeSim(ai.fix_code, gold.compliant_codes)`                                                                                                                                                                                                                                                                         | 20             |
| **Fix Code Dissimilarity to Noncompliant Examples** | Fix code avoids resembling official noncompliant examples.                                                 | `1 - CodeSim(ai.fix_code, gold.noncompliant_codes)`                                                                                                                                                                                                                                                                  | 20             |
| **Efficiency Gain**                                 | Measures reduction in developer effort/time compared to manual fixing.                                     | `time_manual_fix / time_ai_fix`                                                                                                                                                                                                                                                                                      | 10             |
| **Threshold Compliance**                            | AI fix passes correctness threshold required for enabling the checker in CI.                               | `score(ai.fix) >= threshold`                                                                                                                                                                                                                                                                                         | Hard 0 if fail |
| **Developer Readability**                           | Explanations are clear, concise, and actionable for developers.                                            | `ReadabilityScore(ai.fix_text) >= threshold`                                                                                                                                                                                                                                                                         | 10             |

