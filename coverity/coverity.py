import pandas as pd
from urllib.parse import quote
from typing import TypedDict, NotRequired, cast, List

from .scrape_cwe import get_cwe_url

OWNER = "zlib-ng"
REPO = "zlib-ng"
REPO_URL = f"https://github.com/{OWNER}/{REPO}"
DEFAULT_BRANCH = "develop"
COMMIT_SHA = "287c4dce22a3244a0e2602d9e5bf0929df74fd27"
COMMIT_URL = f"{REPO_URL}/commit/{COMMIT_SHA}"

COVERITY_SCAN_PATH = "https://scan.coverity.com/projects/zlib-ng-zlib-ng?tab=project_settings"
RAW_COVERITY_ISSUES_CSV_PATH = "./coverity/coverity_issues_raw.csv"
COVERITY_ISSUES_CSV_PATH = "./coverity/coverity_issues.csv"

RELEVANT_COLUMNS = [
    "CID",
    "Type",
    "Category",
    "Checker",
    "CWE",
    "Impact",
    "Severity",

    "File",
    "Function",
    "Line Number",
    "Language",

    "First Snapshot Date",
    "First Snapshot Version",
    "First Snapshot Stream",
    "Last Snapshot Date",
    "Last Snapshot Version",
    "Last Snapshot Stream",
]

class CoverityIssue(TypedDict, total=False):
    CID: str
    Type: NotRequired[str]
    Category: NotRequired[str]
    Checker: NotRequired[str]
    CWE: NotRequired[str]
    Impact: NotRequired[str]
    Severity: NotRequired[str]
    github_link: NotRequired[str]
    coverity_link: NotRequired[str]
    cwe_link: NotRequired[str]
    File: NotRequired[str]
    Function: NotRequired[str]
    Line_Number: NotRequired[str]  
    Language: NotRequired[str]
    First_Snapshot_Date: NotRequired[str]
    First_Snapshot_Version: NotRequired[str]
    First_Snapshot_Stream: NotRequired[str]
    Last_Snapshot_Date: NotRequired[str]
    Last_Snapshot_Version: NotRequired[str]
    Last_Snapshot_Stream: NotRequired[str]

_NORMALIZE_KEYS = {
    "Line Number": "Line_Number",
    "First Snapshot Date": "First_Snapshot_Date",
    "First Snapshot Version": "First_Snapshot_Version",
    "First Snapshot Stream": "First_Snapshot_Stream",
    "Last Snapshot Date": "Last_Snapshot_Date",
    "Last Snapshot Version": "Last_Snapshot_Version",
    "Last Snapshot Stream": "Last_Snapshot_Stream",
}

def convert_coverity_csv_to_relevant(
    raw_csv_path: str = RAW_COVERITY_ISSUES_CSV_PATH,
    out_csv_path: str = COVERITY_ISSUES_CSV_PATH,
) -> str:
    df = pd.read_csv(raw_csv_path)
    df.columns = [c.strip() for c in df.columns]

    keep = [c for c in RELEVANT_COLUMNS if c in df.columns]
    if not keep:
        raise ValueError("No expected columns found in the raw Coverity CSV export.")

    out = df[keep].copy()
    out.to_csv(out_csv_path, index=False)
    return out_csv_path

def get_coverity_issue_cids(csv_path: str = COVERITY_ISSUES_CSV_PATH) -> List[str]:
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    if "CID" not in df.columns:
        raise ValueError("CSV does not contain a 'CID' column.")
    return df["CID"].astype(str).str.strip().tolist()

def get_coverity_issues_cwes(csv_path: str = COVERITY_ISSUES_CSV_PATH) -> List[str]:
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    if "CWE" not in df.columns:
        raise ValueError("CSV does not contain a 'CWE' column.")
    cwes = df["CWE"].astype(str).str.strip().tolist()
    unique_cwes = sorted(set(cwe for cwe in cwes if cwe and cwe.lower() != "nan"))
    return unique_cwes

def github_flag_link(
    owner: str,
    repo: str,
    commit_sha: str,
    file_path: str,
    line_number: str,
) -> str:
    norm_path = (file_path or "").lstrip("/")
    quoted_path = "/".join(quote(seg) for seg in norm_path.split("/") if seg)
    return f"https://github.com/{owner}/{repo}/blob/{commit_sha}/{quoted_path}#L{line_number}"

def get_coverity_link(cid: str) -> str:
    return f"https://scan3.scan.coverity.com/#/project-view/69675/12538?selectedIssue={cid}"

def _normalize_issue_row(row: dict) -> CoverityIssue:
    out: dict = {}
    for k, v in row.items():
        val = "" if pd.isna(v) else v
        nk = _NORMALIZE_KEYS.get(k, k)  
        out[nk] = val
    return cast(CoverityIssue, out)

def load_coverity_issue(target_cid: str, csv_path: str = COVERITY_ISSUES_CSV_PATH) -> CoverityIssue:
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    if "CID" not in df.columns:
        raise ValueError("CSV does not contain a 'CID' column.")
    
    df["__CID_STR__"] = df["CID"].astype(str).str.strip()
    target_cid = str(target_cid).strip()
    hit = df[df["__CID_STR__"] == target_cid]
    if hit.empty:
        sample = ", ".join(df["__CID_STR__"].head(20).tolist())
        raise ValueError(f"CID {target_cid} not found in CSV. Sample CIDs: {sample}")
    
    row = hit.iloc[0].to_dict()
    row.pop("__CID_STR__", None)
    
    coverity_issue = _normalize_issue_row(row)
    
    coverity_issue["github_link"] = github_flag_link(
        owner=OWNER,
        repo=REPO,
        commit_sha=COMMIT_SHA,
        file_path=str(coverity_issue.get("File", "") or "").strip(),
        line_number= coverity_issue.get("Line_Number", "") or "0"
    )
    coverity_issue["coverity_link"] = get_coverity_link(target_cid)
    
    cwe = str(coverity_issue.get("CWE") or "")
    coverity_issue["cwe_link"] = get_cwe_url(cwe) if cwe else ""
        
    return coverity_issue


if __name__ == "__main__":
    print("Converting Coverity CSV to relevant fields...")
    out_path = convert_coverity_csv_to_relevant()
    print(f"Wrote trimmed Coverity issues to: {out_path}")
