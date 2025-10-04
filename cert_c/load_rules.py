import json
from typing import Dict, List, Optional, TypedDict, NotRequired, cast

CERT_C_RULES_PATH = "cert_c/certc_rules.json"

class ExampleSection(TypedDict, total=True):
    heading: NotRequired[str]
    pre_code_commentary: NotRequired[str]
    code: NotRequired[str]
    explanation_after: NotRequired[Optional[str]]

class RuleExample(TypedDict, total=True):
    noncompliant: NotRequired[ExampleSection]
    compliant: NotRequired[ExampleSection]

class RiskAssessmentMetrics(TypedDict, total=True):
    severity: NotRequired[str]
    likelihood: NotRequired[str]
    detectable: NotRequired[str]
    repairable: NotRequired[str]
    priority: NotRequired[str]
    level: NotRequired[str]

class RiskAssessment(TypedDict, total=True):
    explanation: NotRequired[str]
    metrics: NotRequired[RiskAssessmentMetrics]

class CertCRule(TypedDict, total=True):
    rule_id: str
    title: str
    url: NotRequired[str]
    description: NotRequired[str]
    examples: NotRequired[List[RuleExample]]
    risk_assessment: NotRequired[RiskAssessment]

def load_rules(path: str = CERT_C_RULES_PATH) -> List[CertCRule]:
    """Load CERT-C rule definitions from disk."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, dict):
        data = [data]

    filtered = [it for it in data if isinstance(it, dict) and it.get("rule_id") and it.get("title")]
    return cast(List[CertCRule], filtered)

def get_rules_ids(path: str = CERT_C_RULES_PATH) -> List[str]:
    rules = load_rules(path)
    return [r["rule_id"] for r in rules if r.get("rule_id")]

def rule_index_by_id(rules: List[CertCRule]) -> Dict[str, CertCRule]:
    return {r["rule_id"]: r for r in rules if r.get("rule_id")}

def load_rule_by_id(rule_id: str, path: str = CERT_C_RULES_PATH) -> Optional[CertCRule]:
    rules = load_rules(path)
    for r in rules:
        if r["rule_id"] == rule_id:
            return r
    return None
