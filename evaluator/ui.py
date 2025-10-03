from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple
import json
import os

import streamlit as st

from analysis import verification
from utilities import (
    CERT_C_RULES_PATH,
    COVERITY_EXAMPLES_PATH,
    PRIORITY_OPTIONS,
    RUBRIC_PATH,
    SEVERITY_ORDER,
    join_nonempty,
    load_examples,
    load_rubric,
    load_rules,
    rule_index_by_id,
)

__all__ = ["main"]

def _apply_example_to_state(example: Dict[str, Any]) -> None:
    coverity = (example.get("coverity") or {}) if isinstance(example, dict) else {}
    ai = (example.get("ai") or {}) if isinstance(example, dict) else {}

    st.session_state.sel_rule_id = coverity.get("rule_id", None) 
    st.session_state.coverity_sev = coverity.get("severity", st.session_state.get("coverity_sev", "Medium"))
    st.session_state.coverity_pri = coverity.get("priority", st.session_state.get("coverity_pri", "P1"))
    st.session_state.issue_text = coverity.get("message", "")
    st.session_state.issue_code = coverity.get("code", "")

    st.session_state.ai_sev = ai.get("identified_severity", "")
    st.session_state.ai_pri = ai.get("identified_priority", "")
    st.session_state.ai_expl = ai.get("explanation", "")
    st.session_state.ai_fix_text = ai.get("fix_narrative", "")
    st.session_state.ai_fix_code = ai.get("patch", "")


def _escape_table_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|")


def _rubric_metrics_table(metrics: Iterable[Dict[str, Any]]) -> str:
    columns: List[str] = ["Metric", "Description", "Evaluation Method", "Weight"]
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for metric in metrics:
        entries = [
            _escape_table_cell(metric.get("metric")),
            _escape_table_cell(metric.get("description")),
            _escape_table_cell(metric.get("evaluation_method")),
            _escape_table_cell(metric.get("weight")),
        ]
        lines.append("| " + " | ".join(entries) + " |")
    return "\n".join(lines)


def _ensure_data_loaded() -> None:
    if "rules" not in st.session_state:
        try:
            rules = load_rules(CERT_C_RULES_PATH)
            st.session_state.rules = rules
            st.session_state.rules_by_id = rule_index_by_id(rules)
            st.session_state.rules_error = None
        except Exception as exc:  # noqa: BLE001
            st.session_state.rules = []
            st.session_state.rules_by_id = {}
            st.session_state.rules_error = str(exc)

    # Legacy examples.json is deprecated. We keep graceful handling in case it exists.
    if "examples" not in st.session_state:
        try:
            if os.path.exists(COVERITY_EXAMPLES_PATH):
                st.session_state.examples = load_examples(COVERITY_EXAMPLES_PATH)
                st.session_state.examples_error = None
            else:
                st.session_state.examples = []
                st.session_state.examples_error = None
        except Exception as exc:  # noqa: BLE001
            st.session_state.examples = []
            st.session_state.examples_error = str(exc)

    if "rubric" not in st.session_state:
        try:
            st.session_state.rubric = load_rubric(RUBRIC_PATH)
            st.session_state.rubric_error = None
        except Exception as exc:  # noqa: BLE001
            st.session_state.rubric = None
            st.session_state.rubric_error = str(exc)


def _safe_decode_uploaded(file_obj: Any) -> str:
    if not file_obj:
        return ""
    try:
        content = file_obj.read()
        if isinstance(content, bytes):
            return content.decode("utf-8", errors="replace")
        return str(content)
    except Exception:  # noqa: BLE001
        return ""


def _find_key_recursive(obj: Any, key: str) -> Optional[Any]:
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for value in obj.values():
            found = _find_key_recursive(value, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_key_recursive(item, key)
            if found is not None:
                return found
    return None


def _extract_coverity_values(
    defectdetails_text: str,
    defecttriage_text: str,
    source_text: str,
) -> Dict[str, Any]:
    """Parse three Coverity JSON payloads and extract useful fields.

    Expected fields (best-effort, tolerant to schema variations):
    - checkerName from defectdetails
    - severity and classification from defecttriage
    - impact from source
    - message/description and code snippet when available
    """
    def parse_json(text: str) -> Any:
        try:
            return json.loads(text) if text and text.strip() else {}
        except Exception:  # noqa: BLE001
            return {}

    defectdetails = parse_json(defectdetails_text)
    defecttriage = parse_json(defecttriage_text)
    source = parse_json(source_text)

    checker_name = _find_key_recursive(defectdetails, "checkerName") or _find_key_recursive(defectdetails, "checker")
    severity = _find_key_recursive(defecttriage, "severity") or _find_key_recursive(defecttriage, "impact")
    classification = _find_key_recursive(defecttriage, "classification") or _find_key_recursive(defecttriage, "classificationName")
    impact = _find_key_recursive(source, "impact") or _find_key_recursive(defectdetails, "impact")

    # Best-effort messages and code
    issue_message = _find_key_recursive(defectdetails, "message") or _find_key_recursive(defectdetails, "description")
    code_snippet = _find_key_recursive(source, "code") or _find_key_recursive(source, "contents") or _find_key_recursive(source, "snippet")

    # Attempt to map severity into known buckets
    sev_norm = str(severity or "").strip().title()
    if sev_norm and sev_norm not in SEVERITY_ORDER:
        # Basic normalization: map e.g. "critical"/"CRITICAL" to title case
        candidates = {s.lower(): s for s in SEVERITY_ORDER}
        sev_norm = candidates.get(sev_norm.lower(), "")

    # Attempt to coerce classification to priority if it looks like P#
    pri_norm = None
    if isinstance(classification, str) and classification.upper().startswith("P"):
        upper = classification.upper()
        if upper in PRIORITY_OPTIONS:
            pri_norm = upper

    return {
        "checker_name": checker_name or "",
        "severity": sev_norm or "",
        "classification": classification or "",
        "priority_from_classification": pri_norm or "",
        "impact": impact or "",
        "issue_message": (issue_message or "").strip(),
        "code_snippet": (code_snippet or "").strip(),
    }


def _render_coverity_json_inputs() -> Tuple[str, str, str]:
    with st.expander("Coverity Finding (Raw JSON)", expanded=False):
        st.markdown("**Input Coverity JSON Data:**")
        st.markdown("**Option 1: Upload Files**")

        col_u1, col_u2, col_u3 = st.columns(3)
        with col_u1:
            file_defectdetails = st.file_uploader("Upload defectdetails.json", type=["json"], key="file_defectdetails")
        with col_u2:
            file_defecttriage = st.file_uploader("Upload defecttriage.json", type=["json"], key="file_defecttriage")
        with col_u3:
            file_source = st.file_uploader("Upload source.json (for Impact)", type=["json"], key="file_source")

        st.markdown("**Option 2: Paste JSON Content**")
        defectdetails_text = st.text_area("defectdetails.json content:", height=160, key="defectdetails_text")
        defecttriage_text = st.text_area("defecttriage.json content:", height=160, key="defecttriage_text")
        source_text = st.text_area("source.json content (Required - for Impact):", height=160, key="source_text")

        col_b1, col_b2, col_b3 = st.columns(3)
        with col_b1:
            if st.button("📝 Provide defectdetails.json content", key="btn_fill_defectdetails") and file_defectdetails:
                st.session_state.defectdetails_text = _safe_decode_uploaded(file_defectdetails)
        with col_b2:
            if st.button("📝 Provide defecttriage.json content", key="btn_fill_defecttriage") and file_defecttriage:
                st.session_state.defecttriage_text = _safe_decode_uploaded(file_defecttriage)
        with col_b3:
            if st.button("📝 Provide source.json content", key="btn_fill_source") and file_source:
                st.session_state.source_text = _safe_decode_uploaded(file_source)

        # Quick status note
        if not (st.session_state.get("defectdetails_text") and st.session_state.get("defecttriage_text") and st.session_state.get("source_text")):
            st.warning("⏳ Waiting for required files: Please upload all three files (defectdetails.json, defecttriage.json, and source.json) to begin parsing.")

    return (
        st.session_state.get("defectdetails_text", defectdetails_text),
        st.session_state.get("defecttriage_text", defecttriage_text),
        st.session_state.get("source_text", source_text),
    )


def _render_rubric_panel(rubric: Optional[Dict[str, Any]], rubric_error: Optional[str]) -> None:
    with st.expander("Evaluation rubric", expanded=False):
        if isinstance(rubric, dict) and rubric:
            metrics = rubric.get("metrics") or []
            if metrics:
                st.markdown(_rubric_metrics_table(metrics))
            else:
                st.info("Rubric does not define any metrics.")
            notes = rubric.get("notes") or {}
            if notes:
                st.markdown("**Notes**")
                for key, value in notes.items():
                    st.markdown(f"- **{key}**: {value}")
        elif rubric_error:
            st.error(f"Failed to load rubric from `{RUBRIC_PATH}`.\n\n{rubric_error}")
        else:
            st.info("No rubric available.")


def _render_example_selector(
    examples: List[Dict[str, Any]],
    examples_error: Optional[str],
    container: Any,
) -> bool:
    if examples:
        options = ["(none)"] + [f"example{i + 1}" for i in range(len(examples))]
        loaded_label = st.session_state.get("loaded_example_label")
        default_label = loaded_label if loaded_label in options else "(none)"
        selection = container.selectbox(
            "Choose example",
            options=options,
            index=options.index(default_label),
            key="example_selector",
        )
        if selection == "(none)":
            st.session_state.loaded_example_label = None
        elif selection != loaded_label:
            example_idx = options.index(selection) - 1
            _apply_example_to_state(examples[example_idx])
            st.session_state.example_idx = example_idx
            st.session_state.loaded_example_label = selection
        if st.session_state.get("loaded_example_label"):
            container.caption(f"Loaded {st.session_state['loaded_example_label']}")
        else:
            container.caption(f"{len(examples)} examples available")
    elif examples_error:
        container.error(f"Failed to load examples from `{COVERITY_EXAMPLES_PATH}`.\n\n{examples_error}")
    else:
        container.info("No examples available.")

    return container.button("Calculate evaluation", key="calculate_evaluation")


def _load_example_triplet(base_dir: str) -> Tuple[str, str, str]:
    def read(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as h:
                return h.read()
        except Exception:  # noqa: BLE001
            return ""

    return (
        read(os.path.join(base_dir, "defectdetails.json")),
        read(os.path.join(base_dir, "defecttriage.json")),
        read(os.path.join(base_dir, "source.json")),
    )


def _render_sidebar_controls(examples: List[Dict[str, Any]], examples_error: Optional[str]) -> bool:
    sidebar = st.sidebar
    sidebar.markdown("### ZLIB Examples")
    col_e1, col_e2, col_e3 = sidebar.columns(3)
    example_base = os.getenv("COVERITY_EXAMPLES_BASE", "coverity/examples")
    loaded_label = None
    with col_e1:
        if sidebar.button("Example 1", key="ex1"):
            dd, dt, src = _load_example_triplet(os.path.join(example_base, "example1"))
            st.session_state.defectdetails_text = dd
            st.session_state.defecttriage_text = dt
            st.session_state.source_text = src
            loaded_label = "Example 1"
    with col_e2:
        if sidebar.button("Example 2", key="ex2"):
            dd, dt, src = _load_example_triplet(os.path.join(example_base, "example2"))
            st.session_state.defectdetails_text = dd
            st.session_state.defecttriage_text = dt
            st.session_state.source_text = src
            loaded_label = "Example 2"
    with col_e3:
        if sidebar.button("Example 3", key="ex3"):
            dd, dt, src = _load_example_triplet(os.path.join(example_base, "example3"))
            st.session_state.defectdetails_text = dd
            st.session_state.defecttriage_text = dt
            st.session_state.source_text = src
            loaded_label = "Example 3"

    with sidebar.expander("Example Data", expanded=False):
        if loaded_label:
            st.caption(f"Loaded {loaded_label}")
        st.caption(f"Base: {example_base}")

    controls = sidebar.expander("Evaluator Controls", expanded=False)
    return _render_example_selector(examples, examples_error, controls)


def _render_coverity_inputs(
    rules: List[Dict[str, Any]],
    rule_labels: List[str],
    default_index: int,
) -> Tuple[Dict[str, Any], str, str, str, str]:
    with st.expander("Coverity finding", expanded=False):
        selected_idx = st.selectbox(
            "Select CERT-C rule",
            options=range(len(rules)),
            format_func=lambda idx: rule_labels[idx],
            index=default_index,
            key="rule_selector",
        )
        rule = rules[selected_idx]
        st.session_state.sel_rule_id = rule.get("rule_id")

        coverity_sev = st.selectbox("Reported severity", options=SEVERITY_ORDER, key="coverity_sev")
        coverity_pri = st.selectbox("Reported priority", options=PRIORITY_OPTIONS, key="coverity_pri")
        issue_text = st.text_area("Finding description", height=190, key="issue_text")
        issue_code = st.text_area("Finding source code", height=220, key="issue_code")

    return rule, coverity_sev, coverity_pri, issue_text, issue_code


def _render_example_with_code(label: str, section: Dict[str, Any]) -> None:
    body = join_nonempty(
        [
            section.get("heading"),
            section.get("pre_code_commentary"),
            section.get("explanation_after"),
        ]
    )
    if body:
        st.markdown(f"**{label}**")
        st.write(body)
    code = section.get("code")
    if code:
        st.code(code, language="c")


def _render_rule_details(rule: Dict[str, Any]) -> None:
    with st.expander("CERT-C Rule Details", expanded=False):
        rule_id = rule.get("rule_id")
        rule_title = rule.get("title")
        rule_url = rule.get("url")
        if rule_id and rule_title and rule_url:
            st.markdown(f"[**{rule_id} — {rule_title}**]({rule_url})")
        else:
            st.markdown(f"**{rule_id or '—'} — {rule_title or '—'}**")

        risk_assessment = rule.get("risk_assessment") or {}
        metrics = risk_assessment.get("metrics") or {}
        with st.expander("Description", expanded=False):
            st.write(rule.get("description") or "—")

        with st.expander("Risk Assessment", expanded=False):
            st.markdown("**Explanation**")
            st.write((risk_assessment.get("explanation") or "").strip() or "—")
            st.markdown("**Metrics**")
            st.json(metrics or {})

        with st.expander("Examples", expanded=False):
            examples = rule.get("examples") or []
            if not examples:
                st.text("—")
            for idx, example in enumerate(examples, 1):
                st.markdown(f"**Example {idx}**")
                noncompliant = example.get("noncompliant") or {}
                compliant = example.get("compliant") or {}
                if noncompliant:
                    _render_example_with_code("Noncompliant", noncompliant)
                if compliant:
                    _render_example_with_code("Compliant", compliant)


def _render_ai_inputs() -> Tuple[str, str, str, str, str]:
    with st.expander("AI Analysis & Proposed Fix", expanded=False):
        ai_sev = st.selectbox("Identified severity", options=[""] + SEVERITY_ORDER, key="ai_sev")
        ai_pri = st.selectbox("Identified priority", options=[""] + PRIORITY_OPTIONS, key="ai_pri")
        ai_expl = st.text_area("Explanation (Why or why not this is a problem)", height=140, key="ai_expl")
        ai_fix_text = st.text_area("Fix description", height=120, key="ai_fix_text")
        ai_fix_code = st.text_area("Fix source code", height=220, key="ai_fix_code")
    return ai_sev, ai_pri, ai_expl, ai_fix_text, ai_fix_code


def _render_rubric_evaluation(
    trigger: bool,
    rubric: Dict[str, Any],
    rule: Dict[str, Any],
    coverity_sev: str,
    coverity_pri: str,
    issue_text: str,
    issue_code: str,
    ai_sev: str,
    ai_pri: str,
    ai_expl: str,
    ai_fix_text: str,
    ai_fix_code: str,
) -> None:
    """Render the rubric-based evaluation using LLM."""
    if not trigger:
        return
    if not isinstance(rubric, dict):
        st.error(f"Rubric must be a dict, got {type(rubric).__name__}")
        return
    if not isinstance(rule, dict):
        st.error(f"Rule must be a dict, got {type(rule).__name__}")
        return

    with st.expander("Rubric-Based LLM Evaluation", expanded=True):
        st.markdown("### Comprehensive Rubric Evaluation")

        # Check if API key is available
        import os
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            st.error("⚠️ Google API Key not found!")
            st.info(
                "Please create a `.env` file in the project root with your Google API key:\n\n"
                "```\nGOOGLE_API_KEY=your_key_here\n```\n\n"
                "Or, on Streamlit Cloud, add it to Secrets."
            )
            return

        # Prepare Coverity analysis data
        coverity_analysis = {
            "rule_id": rule.get("rule_id", ""),
            "rule_title": rule.get("title", ""),
            "severity": coverity_sev,
            "priority": coverity_pri,
            "issue_description": issue_text,
            "issue_code": issue_code,
            "rule_description": rule.get("description", ""),
            "risk_assessment": (rule.get("risk_assessment") or {}).get("explanation", ""),
            "examples": rule.get("examples", []),
        }

        # Prepare AI analysis data
        ai_analysis = {
            "identified_severity": ai_sev,
            "identified_priority": ai_pri,
            "explanation": ai_expl,
            "fix_description": ai_fix_text,
            "fix_code": ai_fix_code,
        }

        # Show loading spinner while LLM processes
        with st.spinner("🤖 Evaluating with LLM using rubric..."):
            try:
                evaluation_result = verification(rubric, ai_analysis, coverity_analysis)

                # Display the LLM evaluation result
                st.markdown("**LLM Evaluation Results:**")

                # Check if the result is an error message
                if isinstance(evaluation_result, str) and evaluation_result.startswith("Error:"):
                    st.error(evaluation_result)
                else:
                    st.markdown(evaluation_result)
            except Exception as e:  # noqa: BLE001
                st.error(f"Unexpected error during rubric evaluation: {str(e)}")
                st.info("Please check your internet connection and API key configuration.")


def main() -> None:
    """Render the evaluator UI."""
    st.set_page_config(page_title="CERT-C Guided Evaluator", layout="wide")
    _ensure_data_loaded()

    st.title("Evaluation of Coverity Findings & AI Fixes")

    # --- Hoist all state here ---
    rules = st.session_state.get("rules", [])
    rules_error = st.session_state.get("rules_error")
    rubric = st.session_state.get("rubric")
    rubric_error = st.session_state.get("rubric_error")
    examples = st.session_state.get("examples", [])
    examples_error = st.session_state.get("examples_error")

    # --- Pass state + error into components ---
    _render_rubric_panel(rubric, rubric_error)

    if not rules:
        if rules_error:
            st.error(f"Failed to load rules from `{CERT_C_RULES_PATH}`.\n\n{rules_error}")
        else:
            st.info("No CERT-C rules available.")
        st.stop()

    run_eval = _render_sidebar_controls(examples, examples_error)

    # New raw JSON section for Coverity triplet
    defectdetails_text, defecttriage_text, source_text = _render_coverity_json_inputs()

    # If all three present, auto-fill left-hand Coverity fields from parsed values
    parsed = None
    if defectdetails_text and defecttriage_text and source_text:
        parsed = _extract_coverity_values(defectdetails_text, defecttriage_text, source_text)
        if parsed:
            if not st.session_state.get("issue_text") and parsed.get("issue_message"):
                st.session_state.issue_text = parsed.get("issue_message")
            if not st.session_state.get("issue_code") and parsed.get("code_snippet"):
                st.session_state.issue_code = parsed.get("code_snippet")
            if parsed.get("severity") and parsed.get("severity") in SEVERITY_ORDER:
                st.session_state.coverity_sev = parsed.get("severity")
            if parsed.get("priority_from_classification") in PRIORITY_OPTIONS:
                st.session_state.coverity_pri = parsed.get("priority_from_classification")
    elif run_eval:
        st.warning("Please provide all three Coverity JSON files before running evaluation.")
        run_eval = False

    col_left, col_right = st.columns(2)

    with col_left:
        rule_labels = [f"{r.get('rule_id', '—')} — {r.get('title', '—')}" for r in rules]
        default_index = 0
        if st.session_state.get("sel_rule_id"):
            matching = [idx for idx, itm in enumerate(rules) if itm.get("rule_id") == st.session_state.sel_rule_id]
            if matching:
                default_index = matching[0]

        rule, coverity_sev, coverity_pri, issue_text, issue_code = _render_coverity_inputs(
            rules,
            rule_labels,
            default_index,
        )
        _render_rule_details(rule)

    with col_right:
        ai_sev, ai_pri, ai_expl, ai_fix_text, ai_fix_code = _render_ai_inputs()

    _render_rubric_evaluation(
        trigger=run_eval,
        rubric=rubric,
        rule=rule,
        coverity_sev=coverity_sev,
        coverity_pri=coverity_pri,
        issue_text=issue_text,
        issue_code=issue_code,
        ai_sev=ai_sev,
        ai_pri=ai_pri,
        ai_expl=ai_expl,
        ai_fix_text=ai_fix_text,
        ai_fix_code=ai_fix_code,
    )


if __name__ == "__main__":
    main()
