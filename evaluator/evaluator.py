"""Evaluator that returns a completed rubric in strict JSON (RubricEvaluation)."""
from __future__ import annotations

import os
import json
from typing import Any, Dict, List, Optional, TypedDict, Union, cast, NotRequired

from dotenv import load_dotenv
from langchain.chat_models import init_chat_model
from langchain_core.prompts import ChatPromptTemplate

from coverity import CoverityIssue
from cert_c import CertCRule
from fix_agent import AgentFixResult

load_dotenv()

GOOGLE_API_KEY: Optional[str] = os.getenv("GOOGLE_API_KEY")
RUBRIC_PATH = "evaluator/rubric.json"

RubricWeight = Union[int, float, str]

class RubricMetric(TypedDict, total=True):
    metric: str
    description: NotRequired[str]
    evaluation_method: NotRequired[str]
    weight: NotRequired[RubricWeight]


class Rubric(TypedDict, total=True):
    metrics: List[RubricMetric]
    notes: NotRequired[Dict[str, Any]]


class MetricEvaluation(TypedDict, total=True):
    metric: RubricMetric
    comparison: str
    status: str
    reasoning: str


class RubricEvaluation(TypedDict, total=True):
    metricEvaluations: List[MetricEvaluation]


def _as_rubric_metric(raw: Any) -> Optional[RubricMetric]:
    if not isinstance(raw, dict):
        return None

    name = str(raw.get("metric", "") or "").strip()
    if not name:
        return None

    metric: RubricMetric = {"metric": name}

    description = raw.get("description")
    if isinstance(description, str) and description.strip():
        metric["description"] = description.strip()

    evaluation_method = raw.get("evaluation_method")
    if isinstance(evaluation_method, str) and evaluation_method.strip():
        metric["evaluation_method"] = evaluation_method.strip()

    weight = raw.get("weight")
    if isinstance(weight, (int, float, str)) and (not isinstance(weight, str) or weight.strip()):
        metric["weight"] = cast(RubricWeight, weight)

    return metric


def load_rubric(path: str = RUBRIC_PATH) -> Rubric:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Rubric JSON must contain a top-level object.")

    raw_metrics = data.get("metrics", [])
    metrics: List[RubricMetric] = []
    if isinstance(raw_metrics, list):
        for raw in raw_metrics:
            metric = _as_rubric_metric(raw)
            if metric:
                metrics.append(metric)

    notes_raw = data.get("notes")
    rubric: Rubric = {"metrics": metrics}
    if isinstance(notes_raw, dict):
        rubric["notes"] = {str(k): str(v) for k, v in notes_raw.items()}

    return rubric

def _trunc(x: Any, n: int = 900) -> str:
    s = "" if x is None else str(x)
    return s if len(s) <= n else s[:n] + "..."

def _coverity_summary(issue: CoverityIssue) -> Dict[str, str]:
    return {
        "severity": str(issue.get("Severity", "") or ""),
        "issue_description": _trunc(
            " ".join(
                p for p in [
                    str(issue.get("Type", "") or ""),
                    str(issue.get("Category", "") or ""),
                    f"Checker={issue.get('Checker','') or ''}",
                    f"CWE={issue.get('CWE','') or ''}",
                    f"Impact={issue.get('Impact','') or ''}",
                ] if p
            )
        ),
        "issue_code": _trunc(
            "\n".join(
                p for p in [
                    f"// File: {issue.get('File','') or ''}" if issue.get("File") else "",
                    f"// Function: {issue.get('Function','') or ''}" if issue.get("Function") else "",
                    f"// Line: {issue.get('Line_Number','') or ''}" if issue.get("Line_Number") else "",
                    "// (source snippet unavailable)",
                ] if p
            )
        ),
    }

def _ai_summary(ai: AgentFixResult) -> Dict[str, str]:
    return {
        "identified_severity": str(ai.get("identified_severity", "") or ""),
        "identified_priority": str(ai.get("identified_priority", "") or ""),
        "explanation": _trunc(ai.get("explanation", "")),
        "fix_description": _trunc(ai.get("fix_description", "")),
        "patch": _trunc(ai.get("patch", "")),
    }

def _rule_context(rule: Optional[CertCRule]) -> Dict[str, str]:
    if not rule:
        return {"rule_id": "Unknown", "title": "Unknown", "description": "", "risk_explanation": ""}
    risk_assessment = rule.get("risk_assessment")
    explanation = ""
    if isinstance(risk_assessment, dict):
        explanation = str(risk_assessment.get("explanation", "") or "")
    return {
        "rule_id": rule.get("rule_id", "Unknown") or "Unknown",
        "title": rule.get("title", "Unknown") or "Unknown",
        "description": _trunc(rule.get("description", "") or "", 500),
        "risk_explanation": _trunc(explanation, 300),
    }

def _rubric_lines(rubric: Rubric) -> str:
    lines: List[str] = []
    for i, m in enumerate(rubric.get("metrics", []), 1):
        metric_name = m.get("metric", "Unknown")
        description = m.get("description", "") or ""
        lines.append(f"{i}. {metric_name}: {description}")
    return "\n".join(lines)

def _eval_response_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "metricEvaluations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "metric": {
                            "type": "object",
                            "properties": {
                                "metric": {"type": "string"},
                                "description": {"type": "string"},
                                "evaluation_method": {"type": "string"},
                                "weight": {"type": ["string", "number"]},
                            },
                            "required": ["metric"],
                        },
                        "comparison": {"type": "string"},
                        "status": {"type": "string"},
                        "reasoning": {"type": "string"},
                    },
                    "required": ["metric", "comparison", "status", "reasoning"],
                },
            }
        },
        "required": ["metricEvaluations"],
    }

def _metric_name_from_payload(payload: Any) -> Optional[str]:
    if isinstance(payload, str):
        name = payload.strip()
        return name or None

    if isinstance(payload, dict):
        for key in ("metric", "name"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    return None


def _normalize_and_complete(raw: Dict[str, Any], rubric: Rubric) -> RubricEvaluation:
    metrics = rubric.get("metrics", [])
    canonical_by_name = {m["metric"]: m for m in metrics if m.get("metric")}

    provided: Dict[str, MetricEvaluation] = {}
    items = raw.get("metricEvaluations")
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue

            metric_name = _metric_name_from_payload(item.get("metric"))
            if not metric_name or metric_name not in canonical_by_name:
                continue
            if metric_name in provided:
                continue

            provided[metric_name] = {
                "metric": canonical_by_name[metric_name],
                "comparison": str(item.get("comparison", "") or ""),
                "status": str(item.get("status", "") or ""),
                "reasoning": str(item.get("reasoning", "") or ""),
            }

    metric_evaluations: List[MetricEvaluation] = []
    for metric in metrics:
        metric_name = metric["metric"]
        metric_evaluations.append(
            provided.get(
                metric_name,
                {
                    "metric": metric,
                    "comparison": "",
                    "status": "",
                    "reasoning": "",
                },
            )
        )

    return {"metricEvaluations": metric_evaluations}


def evaluate_example(
    rubric: Optional[Rubric],
    ai_analysis: AgentFixResult,
    coverity_issue: CoverityIssue,
    rule: Optional[CertCRule] = None,
    google_api_key: Optional[str] = GOOGLE_API_KEY,
) -> RubricEvaluation:
    if rubric is None:
        try:
            rubric = load_rubric()
        except Exception:
            print("Failed to load rubric; skipping evaluation.")
            return {"metricEvaluations": []}
    if not google_api_key:
        print("No GOOGLE_API_KEY configured; skipping evaluation.")
        return {"metricEvaluations": []}

    schema = _eval_response_schema()

    try:
        llm = init_chat_model(
            "google_genai:gemini-2.5-flash",
            google_api_key=google_api_key,
            temperature=0,
            timeout=45,
            response_mime_type="application/json",
            response_schema=schema,
        )
    except Exception:
        return {"metricEvaluations": []}

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """You are an expert code analysis evaluator.

You MUST return ONLY valid JSON that conforms exactly to this JSON schema:

{json_schema}

The JSON must represent a completed evaluation of the rubric (one entry per rubric metric):

Rubric (names + descriptions):
{rubric_text}

Rule Context:
- ID: {rule_id}
- Title: {rule_title}
- Description: {rule_description}
- Risk: {rule_risk}

Coverity Summary:
{coverity_summary}

AI Analysis Summary:
{ai_summary}

For each rubric metric:
- Write a brief 'comparison' of AI vs Coverity.
- Fill 'status' with PASS/FAIL or a numeric score when appropriate.
- Keep 'reasoning' under 50 words.
""",
            ),
            ("human", "Return ONLY the JSON. No markdown, no prose."),
        ]
    )

    rule_context = _rule_context(rule)
    rubric_text = _rubric_lines(rubric)
    coverity_summary_json = json.dumps(_coverity_summary(coverity_issue), indent=2)
    ai_summary_json = json.dumps(_ai_summary(ai_analysis), indent=2)
    schema_json = json.dumps(schema, indent=2)

    text = llm.invoke(
        prompt.format_messages(
            json_schema=schema_json,
            rubric_text=rubric_text,
            rule_id=rule_context["rule_id"],
            rule_title=rule_context["title"],
            rule_description=rule_context["description"],
            rule_risk=rule_context["risk_explanation"],
            coverity_summary=coverity_summary_json,
            ai_summary=ai_summary_json,
        )
    ).content

    try:
        raw = json.loads(str(text))
        if not isinstance(raw, dict):
            raise ValueError("LLM did not return a JSON object")
    except Exception:
        return _normalize_and_complete({"metricEvaluations": []}, rubric)

    result =  _normalize_and_complete(raw, rubric)
    print("Evaluation result:", json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    from cert_c import load_rule_by_id
    from coverity import load_coverity_issue
    from fix_agent import fix_issue
    import asyncio

    rubric = load_rubric()
    issue = load_coverity_issue("473951")
    agent_fix = asyncio.run(fix_issue(issue))
    rule = load_rule_by_id("MEM00-C")
    evaluation = evaluate_example(rubric, agent_fix, issue, rule)

    print(json.dumps(evaluation, indent=2))
