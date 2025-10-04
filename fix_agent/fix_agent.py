import os
import json
import asyncio
import time
from typing import TypedDict, Literal, Optional, cast

from agents import Agent, Runner, set_default_openai_key
from agents.model_settings import ModelSettings
from agents.mcp import MCPServerStreamableHttp

from coverity import (
    CoverityIssue,
    OWNER,
    REPO,
    REPO_URL,
    DEFAULT_BRANCH,
    COMMIT_SHA,
    COMMIT_URL,
)

from dotenv import load_dotenv
load_dotenv()

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
PRIORITY_OPTIONS = [f"P{i}" for i in range(1, 19)]

GITHUB_PAT = os.getenv("NO_PRIVILGE_GITHUB_PERSONAL_ACCESS_TOKEN", "")
assert GITHUB_PAT, "Set NO_PRIVILGE_GITHUB_PERSONAL_ACCESS_TOKEN (classic PAT with NO scopes for public read-only)."

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
assert OPENAI_API_KEY, "Set OPENAI_API_KEY"
set_default_openai_key(OPENAI_API_KEY)

GITHUB_MCP_URL = os.getenv("GITHUB_MCP_URL", "https://api.githubcopilot.com/mcp/")

FIX_CACHE_PATH = os.getenv("EVAL_CACHE_PATH", "./fix_agent/fix_cache.json")
FORCE_REGENERATE = os.getenv("FORCE_REGENERATE", "").lower() in {"1", "true", "yes"}

SeverityLiteral = Literal["Low", "Medium", "High", "Critical"]
PriorityLiteral = Literal[
    "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9",
    "P10", "P11", "P12", "P13", "P14", "P15", "P16", "P17", "P18"
]

class AgentFixResult(TypedDict, total=False):
    identified_severity: SeverityLiteral
    identified_priority: PriorityLiteral
    explanation: str
    fix_description: str
    patch: str

async def get_github_mcp_server(github_mcp_url: str, github_pat: str, timeout: int = 20):
    return MCPServerStreamableHttp(
        name="github-mcp",
        params={
            "url": github_mcp_url,
            "headers": {"Authorization": f"Bearer {github_pat}"},
            "timeout": timeout,
        },
        cache_tools_list=True,
        max_retry_attempts=3,
    )

def create_response_format() -> dict:
    return {
        "type": "json_schema",
        "name": "coverity_fix_evaluation",
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "identified_severity": {"type": "string", "enum": list(SEVERITY_ORDER)},
                "identified_priority": {"type": "string", "enum": list(PRIORITY_OPTIONS)},
                "explanation": {"type": "string"},
                "fix_description": {"type": "string"},
                "patch": {"type": "string"},
            },
            "required": [
                "identified_severity",
                "identified_priority",
                "explanation",
                "fix_description",
                "patch",
            ],
        },
        "strict": True,
    }

def create_agent(mcp_server):
    model_settings = ModelSettings(
        tool_choice="auto",
        temperature=0.0,
        max_tokens=1200,
        truncation="auto",
        extra_body={"text": {"format": create_response_format()}},
    )
    return Agent(
        name="RepoAgent",
        model="gpt-4.1-mini",
        instructions=(
            "You may use available MCP tools to achieve the user's goal. "
            "This is a public, read-only repo—do not attempt any write operations. "
            "Prefer listing files and reading content to build a quick map of the codebase."
        ),
        mcp_servers=[mcp_server],
        model_settings=model_settings,
    )

def build_prompt(
    coverity_context_json: str,
    owner: str,
    repo: str,
    repo_url: str,
    repo_branch: str,
    commit_sha: str,
    commit_url: str,
) -> str:
    return (
        f"You are fixing a single Coverity finding in repo {owner}/{repo} at commit {commit_sha}.\n"
        f"Repo URL: {repo_url}\n"
        f"Branch: {repo_branch}\n"
        f"Commit URL: {commit_url}\n"
        f"Read-only actions only via MCP (list files, open file contents at specific paths/lines, etc.).\n\n"
        f"COVERITY_CONTEXT (exact CSV fields preserved):\n{coverity_context_json}\n\n"
        f"Do the following and return ONLY a JSON object that matches the provided schema:\n"
        f"- Open the file path in 'File' at commit {commit_sha} and inspect ~30 lines around 'Line Number'.\n"
        f"- Based on 'Type'/'Category' and 'CWE', explain if/why this is a real problem in this context.\n"
        f"- Propose a minimal, behavior-preserving fix as a unified diff.\n"
        f"- Choose an overall severity (use CSV 'Severity' or 'Impact' as a guide) from: {', '.join(SEVERITY_ORDER)}.\n"
        f"- Choose a priority that matches the urgency from: {', '.join(PRIORITY_OPTIONS)}.\n"
        f'- Return JSON with keys exactly: "identified_severity", "identified_priority", "explanation", "fix_description", "patch".\n'
    )

def get_from_cache(cache_path: str, key: str) -> Optional[AgentFixResult]:
    try:
        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                db = json.load(f)
                val = db.get(key)
                if isinstance(val, dict):
                    return cast(AgentFixResult, val)
    except Exception:
        pass
    return None

def save_in_cache(cache_path: str, key: str, evaluation_json: AgentFixResult) -> None:
    try:
        db: dict = {}
        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                try:
                    db = json.load(f) or {}
                except Exception:
                    db = {}
        db[key] = evaluation_json
        os.makedirs(os.path.dirname(os.path.abspath(cache_path)), exist_ok=True)
        tmp = cache_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        os.replace(tmp, cache_path)
    except Exception:
        pass

async def agent_fix(
    coverity_issue: CoverityIssue,
    owner: str,
    repo: str,
    repo_url: str,
    default_branch: str,
    commit_sha: str,
    commit_url: str,
    github_mcp_url: str,
    github_pat: str,
) -> AgentFixResult:
    coverity_issue_json = json.dumps(coverity_issue, indent=2)
    prompt = build_prompt(
        coverity_context_json=coverity_issue_json,
        owner=owner,
        repo=repo,
        repo_url=repo_url,
        repo_branch=default_branch,
        commit_sha=commit_sha,
        commit_url=commit_url,
    )

    mcp_server = await get_github_mcp_server(github_mcp_url=github_mcp_url, github_pat=github_pat)
    async with mcp_server:
        agent = create_agent(mcp_server)
        result = await Runner.run(agent, prompt)

        text = getattr(result, "final_output", None) or str(result)

        try:
            obj = json.loads(text)
            return cast(AgentFixResult, {
                "identified_severity": obj.get("identified_severity", ""),
                "identified_priority": obj.get("identified_priority", ""),
                "explanation": obj.get("explanation", ""),
                "fix_description": obj.get("fix_description", ""),
                "patch": obj.get("patch", ""),
            })
        except json.JSONDecodeError:
            sev_raw = str(coverity_issue.get("Severity") or coverity_issue.get("Impact") or "").strip().title()
            severity: SeverityLiteral = cast(SeverityLiteral, sev_raw if sev_raw in SEVERITY_ORDER else "Low")
            priority_guess = "P1" if severity in {"High", "Critical"} else "P2"
            priority: PriorityLiteral = priority_guess if priority_guess in PRIORITY_OPTIONS else "P1"

            return {
                "identified_severity": severity,
                "identified_priority": priority,
                "explanation": "Model returned non-JSON; raw output is placed in patch.",
                "fix_description": "N/A",
                "patch": text,
            }

async def fix_issue(
    issue: CoverityIssue,
    owner: str = OWNER,
    repo: str = REPO,
    repo_url: str = REPO_URL,
    default_branch: str = DEFAULT_BRANCH,
    commit_sha: str = COMMIT_SHA,
    commit_url: str = COMMIT_URL,
    github_mcp_url: str = GITHUB_MCP_URL,
    github_pat: str = GITHUB_PAT,
    cache_path: str = FIX_CACHE_PATH,
    force_regenerate: bool = FORCE_REGENERATE,
) -> AgentFixResult:
    cid_str = str(issue.get("CID", "")).strip()
    key = f"{owner}/{repo}:{commit_sha}:CID={cid_str}"

    cached = None if force_regenerate else get_from_cache(cache_path, key)
    if cached is not None:
        return cached

    evaluation_json = await agent_fix(
        coverity_issue=issue,
        owner=owner,
        repo=repo,
        repo_url=repo_url,
        default_branch=default_branch,
        commit_sha=commit_sha,
        commit_url=commit_url,
        github_mcp_url=github_mcp_url,
        github_pat=github_pat,
    )

    save_in_cache(cache_path, key, evaluation_json)
    return evaluation_json

if __name__ == "__main__":
    from coverity import load_coverity_issue
    issue = load_coverity_issue("473947")
    result = asyncio.run(fix_issue(issue))
    print("=== Result ===")
    print(json.dumps(result, indent=2))
