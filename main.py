from __future__ import annotations

import asyncio
import os
from typing import Dict, Optional, List, Tuple, cast
import streamlit as st

from cert_c import (
    CertCRule,
    load_rule_by_id,
)

from coverity import (
    CoverityIssue,
    get_coverity_issue_cids,
    load_coverity_issue,
    get_related_certc_cids,
    REPO_URL,
    COMMIT_URL,
)

from fix_agent import (
    AgentFixResult,
    fix_issue,
    GITHUB_MCP_URL,
)

from evaluator import (
    Rubric,
    RubricEvaluation,
    evaluate_example,
    load_rubric,
)

def app_state_defaults() -> None:
    st.session_state.setdefault("coverity_issue_cids", get_coverity_issue_cids())

    st.session_state.setdefault("selected_coverity_issue_cid", None)
    
    st.session_state.setdefault("related_certc_ids", []) 
    st.session_state.setdefault("selected_cert_rule_id", None)

    # Loaded detail objects
    st.session_state.setdefault("certCRule", None)            
    st.session_state.setdefault("coverity_issue", None)       # CoverityIssue
    st.session_state.setdefault("agent_fix_result", None)     # AgentFixResult

    # Rubric + last evaluation
    st.session_state.setdefault("rubric", load_rubric())      # Rubric
    st.session_state.setdefault("rubric_evaluation", None)    # RubricEvaluation


def update_app_state(
    selected_cert_rule_id: Optional[str] = None,
    selected_coverity_issue_cid: Optional[str] = None,
) -> None:
    # If user explicitly changes CERT-C rule, load it
    if selected_cert_rule_id is not None:
        st.session_state.selected_cert_rule_id = selected_cert_rule_id or None
        st.session_state.certCRule = (
            load_rule_by_id(selected_cert_rule_id) if selected_cert_rule_id else None
        )
        st.session_state.rubric_evaluation = None

    # If Coverity CID changes, load issue, compute related CERT-Cs, and auto-select first
    if selected_coverity_issue_cid is not None:
        st.session_state.selected_coverity_issue_cid = selected_coverity_issue_cid or None
        
        coverity_issue = load_coverity_issue(selected_coverity_issue_cid) 
        st.session_state.coverity_issue = coverity_issue
        
        cwe = coverity_issue.get('CWE', "") if coverity_issue else ""
        print("CWE of selected issue:", cwe)

        related_certc_ids = get_related_certc_cids(cwe) or []
        st.session_state.related_certc_ids = related_certc_ids
        
        print("Related CERT-C IDs:", related_certc_ids)

        auto_rule = related_certc_ids[0] if related_certc_ids else None
        st.session_state.selected_cert_rule_id = auto_rule
        st.session_state.certCRule = load_rule_by_id(auto_rule) if auto_rule else None

        st.session_state.agent_fix_result = None
        st.session_state.rubric_evaluation = None




def render_rubric(rubric: Rubric) -> None:
    with st.expander("Evaluation rubric", expanded=False):
        metrics = rubric["metrics"]
        cols = ["Metric", "Description", "Evaluation Method", "Weight"]
        lines = [
            "| " + " | ".join(cols) + " |",
            "| " + " | ".join(["---"] * len(cols)) + " |",
        ]
        for m in metrics:
            entries = [
                m["metric"],
                m.get("description", ""),
                m.get("evaluation_method", ""),
                str(m.get("weight", "")),
            ]
            esc = [e.replace("|", "\\|") for e in entries]
            lines.append("| " + " | ".join(esc) + " |")
        st.markdown("\n".join(lines))


def render_sidebar_controls(
    selected_cert_rule_id: str,
    selected_coverity_issue_cid: str,
    related_certc_rule_ids: List[str],
    coverity_issue_cids: List[str],
    rule_loaded: bool,
    issue_loaded: bool,
) -> Tuple[bool, bool, str, str]:
    with st.sidebar:
        st.markdown("### Select Inputs")

        cid_options = ["(none)"] + coverity_issue_cids
        cid_index = 0
        if selected_coverity_issue_cid and selected_coverity_issue_cid in coverity_issue_cids:
            cid_index = coverity_issue_cids.index(selected_coverity_issue_cid) + 1
        cid_choice = st.selectbox(
            "Coverity Issue CID",
            options=cid_options,
            index=cid_index,
            key="ui_cid_choice",
        )
        new_cid = "" if cid_choice == "(none)" else cid_choice
        
        rule_options = ["(none)"] + related_certc_rule_ids
        rule_index = 0
        if selected_cert_rule_id and selected_cert_rule_id in related_certc_rule_ids:
            rule_index = related_certc_rule_ids.index(selected_cert_rule_id) + 1
        rule_choice = st.selectbox(
            "Related CERT-C Rule ID",
            options=rule_options,
            index=rule_index,
            key="ui_rule_choice",
        )
        new_rule_id = "" if rule_choice == "(none)" else rule_choice

        st.divider()

        run_fix_agent = st.button(
            "Run fix agent",
            width="stretch",
            disabled=not new_cid,
            key="sidebar_run_fix_agent",
        )

        run_rubric_eval = st.button(
            "Evaluate with rubric",
            width="stretch",
            disabled=not (rule_loaded and issue_loaded),
            key="sidebar_run_rubric_eval",
        )

        st.divider()
        st.caption(f"Repo: {REPO_URL}")
        st.caption(f"Commit: {COMMIT_URL}")
        st.caption(f"GitHub MCP: {GITHUB_MCP_URL}")

    return run_fix_agent, run_rubric_eval, new_rule_id, new_cid


def render_rule_details(rule: CertCRule) -> None:
    with st.expander("CERT-C Rule Details", expanded=False):
        rule_id = rule.get("rule_id")
        rule_title = rule.get("title")
        rule_url = rule.get("url")
        if rule_id and rule_title and rule_url:
            st.markdown(f"[**{rule_id} — {rule_title}**]({rule_url})")
        else:
            st.markdown(f"**{rule_id or '—'} — {rule_title or '—'}**")

        with st.expander("Description", expanded=False):
            st.write(rule.get("description") or "—")

        risk_assessment = rule.get("risk_assessment") or {}
        metrics = risk_assessment.get("metrics") or {}
        with st.expander("Risk Assessment", expanded=False):
            st.markdown("**Explanation**")
            st.write((risk_assessment.get("explanation") or "").strip() or "—")
            metric_row = {
                "Severity": metrics.get("severity", "—"),
                "Likelihood": metrics.get("likelihood", "—"),
                "Detectable": metrics.get("detectable", "—"),
                "Repairable": metrics.get("repairable", "—"),
                "Priority": metrics.get("priority", "—"),
                "Level": metrics.get("level", "—"),
            }
            st.dataframe([metric_row], width="stretch", hide_index=True)

        with st.expander("Examples", expanded=False):
            examples = rule.get("examples") or []
            if not examples:
                st.text("—")
            for idx, example in enumerate(examples, 1):
                st.markdown(f"**Example {idx}**")
                for label in ("noncompliant", "compliant"):
                    section = example.get(label) or {}
                    if any(section.get(key) for key in ("heading", "pre_code_commentary", "explanation_after")):
                        st.markdown(f"**{label.capitalize()}**")
                        for key in ("heading", "pre_code_commentary", "explanation_after"):
                            value = section.get(key)
                            if value:
                                st.write(value)
                    code = section.get("code")
                    if code:
                        st.code(code, language="c")


def render_coverity_details(issue: CoverityIssue) -> None:
    title_cid = issue.get("CID", "") if isinstance(issue, dict) else ""
    with st.expander(f"Coverity Finding {title_cid}", expanded=False):
        st.write(f"**GitHub link:** {issue.get('github_link','—')}")
        st.write(f"**Coverity link:** {issue.get('coverity_link','—')}")
        st.write(f"**CWE link:** {issue.get('cwe_link','—')}")
        left, right = st.columns(2)
        with left:
            st.write(f"**Type:** {issue.get('Type','—')}")
            st.write(f"**Category:** {issue.get('Category','—')}")
            st.write(f"**Checker:** {issue.get('Checker','—')}")
            st.write(f"**CWE:** {issue.get('CWE','—')}")
            st.write(f"**Impact:** {issue.get('Impact','—')}")
            st.write(f"**Severity:** {issue.get('Severity','—')}")

        with right:
            st.write(f"**File:** {issue.get('File','—')}")
            st.write(f"**Function:** {issue.get('Function','—')}")
            st.write(f"**Line Number:** {issue.get('Line_Number','—')}")
            st.write(f"**Language:** {issue.get('Language','—')}")
            st.write(
                f"**First Snapshot:** {issue.get('First_Snapshot_Date','—')} — "
                f"{issue.get('First_Snapshot_Version','—')} / "
                f"{issue.get('First_Snapshot_Stream','—')}"
            )
            st.write(
                f"**Last Snapshot:** {issue.get('Last_Snapshot_Date','—')} — "
                f"{issue.get('Last_Snapshot_Version','—')} / "
                f"{issue.get('Last_Snapshot_Stream','—')}"
            )


def render_agent_fix(selected_coverity_issue_cid: str, agent_fix_result: Optional[AgentFixResult]) -> None:
    with st.expander("Agent generated fix", expanded=True):
       

        if not selected_coverity_issue_cid:
            st.info("Select a Coverity Issue CID in the sidebar, then run the fix agent to populate this section.")
        elif not agent_fix_result:
            st.info("Run the fix agent from the sidebar to generate AI analysis for the selected issue.")
        else:
            left, right = st.columns(2)

            with left:
                st.markdown("**Identified severity**")
                st.write(agent_fix_result.get("identified_severity", "-") if agent_fix_result else "—")

                st.markdown("**Identified priority**")
                st.write(agent_fix_result.get("identified_priority", "-") if agent_fix_result else  "—")
                
                st.markdown("**Explanation**")
                st.text_area(
                    "Explanation",
                    value=agent_fix_result.get("explanation", "-") if agent_fix_result else "—",
                    height=200,
                    key="ai_explanation_display",
                    disabled=False,
                    label_visibility="collapsed",
                )
                
                st.markdown("**Fix description**")
                st.text_area(
                    "Fix description",
                    value=agent_fix_result.get("fix_description", "-") if agent_fix_result else "—",
                    height=200,
                    key="ai_fix_description_display",
                    disabled=False,
                    label_visibility="collapsed",
                )

            with right:
                
                st.markdown("**Patch**")
                st.code(agent_fix_result.get("patch", "-") if agent_fix_result else "-", language="diff")


def run_agent_fix(issue: CoverityIssue) -> None:
    with st.spinner("Running fix agent..."):
        try:
            agentFixResult: AgentFixResult = asyncio.run(fix_issue(issue))
            st.session_state.agent_fix_result = agentFixResult
            st.session_state.rubric_evaluation = None
        except Exception as e:
            st.error(f"Fix agent failed: {e}")


def evaluate_agent_fix(
    rubric: Rubric,
    coverity_issue: CoverityIssue,
    rule: Optional[CertCRule],
    ai_analysis: AgentFixResult,
) -> RubricEvaluation:
    return evaluate_example(
        rubric=rubric,
        ai_analysis=ai_analysis,
        coverity_issue=coverity_issue,
        rule=rule,
    )


def render_rubric_evaluation(
    evaluation: RubricEvaluation,
    google_api_key_present: bool,
) -> None:
    with st.expander("Rubric-Based LLM Evaluation", expanded=False):
        if not google_api_key_present:
            st.warning("GOOGLE_API_KEY not found (only needed if your evaluator uses it).")

        metric_rows = [
            {
                "Metric": item.get("metric", {}).get("metric", ""),
                "Status": item.get("status", ""),
                "Comparison": item.get("comparison", ""),
                "Reasoning": item.get("reasoning", ""),
            }
            for item in evaluation["metricEvaluations"]
        ]

        if metric_rows:
            st.dataframe(
                metric_rows,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("Evaluator returned no metric details.")


def main() -> None:
    st.set_page_config(page_title="CERT-C Guided Evaluator", layout="wide")
    app_state_defaults()

    st.title("Evaluation of Coverity Findings & AI Fixes")

    related_certc_ids = cast(List[str], st.session_state.get("related_certc_ids") or [])
    coverity_issue_cids = cast(List[str], st.session_state.get("coverity_issue_cids") or [])
    selected_rule_id = cast(str, st.session_state.get("selected_cert_rule_id") or "")
    selected_issue_cid = cast(str, st.session_state.get("selected_coverity_issue_cid") or "")
    cert_rule = cast(Optional[CertCRule], st.session_state.get("certCRule"))
    coverity_issue = cast(Optional[CoverityIssue], st.session_state.get("coverity_issue"))
    agent_fix_result = cast(Optional[AgentFixResult], st.session_state.get("agent_fix_result"))
    evaluation_state = cast(Optional[RubricEvaluation], st.session_state.get("rubric_evaluation"))
    rubric = cast(Optional[Rubric], st.session_state.get("rubric"))

    run_fix_agent, run_rubric_eval, new_rule_id, new_cid = render_sidebar_controls(
        selected_rule_id,
        selected_issue_cid,
        related_certc_ids,
        coverity_issue_cids,
        bool(cert_rule),
        bool(coverity_issue),
    )

    updates: Dict[str, Optional[str]] = {}
    if new_rule_id != selected_rule_id:
        updates["selected_cert_rule_id"] = new_rule_id or None
    if new_cid != selected_issue_cid:
        updates["selected_coverity_issue_cid"] = new_cid or None
    if updates:
        update_app_state(**updates)
        # refresh locals
        selected_rule_id = cast(str, st.session_state.get("selected_cert_rule_id") or "")
        selected_issue_cid = cast(str, st.session_state.get("selected_coverity_issue_cid") or "")
        cert_rule = cast(Optional[CertCRule], st.session_state.get("certCRule"))
        coverity_issue = cast(Optional[CoverityIssue], st.session_state.get("coverity_issue"))

    if run_fix_agent:
        if coverity_issue:
            run_agent_fix(cast(CoverityIssue, coverity_issue))
            agent_fix_result = cast(Optional[AgentFixResult], st.session_state.get("agent_fix_result"))
        else:
            st.warning("Select a Coverity issue before running the fix agent.")

    if run_rubric_eval:
        if coverity_issue and cert_rule:
            try:
                with st.spinner("Evaluating with rubric..."):
                    # If the user hasn't run the fix agent yet, pass an empty payload (will just produce empty evals)
                    agent_fix_result = cast(AgentFixResult, agent_fix_result or {})
                    result = evaluate_agent_fix(
                        cast(Rubric, rubric or {"metrics": []}),
                        cast(CoverityIssue, coverity_issue),
                        cast(CertCRule, cert_rule),
                        agent_fix_result,
                    )
                st.session_state.rubric_evaluation = cast(RubricEvaluation, result)
                evaluation_state = cast(Optional[RubricEvaluation],
                                    st.session_state.get("rubric_evaluation"))
            except Exception as exc:  # noqa: BLE001
                st.session_state.rubric_evaluation = None
                st.error(f"Rubric evaluation failed: {exc}")
        else:
            st.warning("Select both a Coverity issue and a CERT-C rule before running the rubric evaluation.")

    # --- Panels ---
    if rubric:
        render_rubric(cast(Rubric, rubric))
    else:
        st.info("No rubric available.")
        
    if coverity_issue:
        render_coverity_details(cast(CoverityIssue, coverity_issue))
    else:
        with st.expander("Coverity Finding", expanded=True):
            st.info("No issue loaded.")

    if cert_rule:
        render_rule_details(cast(CertCRule, cert_rule))
    else:
        with st.expander("Related CERT-C Rule Details", expanded=True):
            st.info("No rule loaded.")

    render_agent_fix(selected_issue_cid, agent_fix_result)

    google_api_key_present = bool(os.getenv("GOOGLE_API_KEY"))
    if evaluation_state:
        render_rubric_evaluation(
            cast(RubricEvaluation, evaluation_state),
            google_api_key_present,
        )
    else:
        with st.expander("Rubric-Based LLM Evaluation", expanded=True):
            if not google_api_key_present:
                st.warning("GOOGLE_API_KEY not found (only needed if your evaluator uses it).")
            if not coverity_issue or not cert_rule:
                st.info("Select both a Coverity issue and a CERT-C rule to enable rubric evaluation from the sidebar.")
            else:
                st.info("Use the sidebar to run the rubric evaluation.")


if __name__ == "__main__":
    main()
