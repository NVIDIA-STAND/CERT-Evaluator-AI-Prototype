import json
import re
import requests
from bs4 import BeautifulSoup
from pathlib import Path
from typing import List, Dict

CWE_BASE_URL = "https://cwe.mitre.org/data/definitions/"
CWE_MAPPINGS_PATH = "./coverity/cwe_mappings.json"
CERTC_ID_RE = re.compile(r"^[A-Z]{3}\d{2}-C$")  # ARR30-C, INT30-C

CWEToCertCMap = Dict[str, List[str]]

def get_cwe_url(cwe_id: str) -> str:
    cwe_id = cwe_id.split(".", 1)[0]  # "125.0" -> "125"
    return f"{CWE_BASE_URL}{cwe_id}.html"

def build_cwe_mappings_json(mapping: CWEToCertCMap, out_path: str = CWE_MAPPINGS_PATH) -> None:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")

def get_cwe_mappings(path: str = CWE_MAPPINGS_PATH) -> CWEToCertCMap:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    
def extract_cwe_mappings(cwe_ids: List[str]) -> CWEToCertCMap:
    out: CWEToCertCMap = {}
    for cwe_display in cwe_ids:
        url = get_cwe_url(cwe_display)
        out[cwe_display] = extract_certc_ids(url)
    return out
    
    
# ---Scraping logic---
def extract_certc_ids(cwe_url: str) -> List[str]:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0 Safari/537.36"
    }
    r = requests.get(cwe_url, headers=headers, timeout=20)
    if r.status_code != 200:
        return []
    ctype = r.headers.get("Content-Type", "")
    if "html" not in ctype.lower():
        return []

    soup = BeautifulSoup(r.text, "html.parser")

    def collect_from_table(table) -> List[str]:
        ids: List[str] = []
        for tr in table.find_all("tr")[1:]:
            cells = tr.find_all(["td", "th"])
            if len(cells) < 3:  
                continue
            taxonomy = cells[0].get_text(" ", strip=True)
            node_id  = cells[1].get_text(" ", strip=True)
            fit      = cells[2].get_text(" ", strip=True)

            if (
                "CERT C Secure Coding" in taxonomy
                and CERTC_ID_RE.fullmatch(node_id)
                and fit.strip().lower() == "cwe more abstract"
            ):
                if node_id not in ids:
                    ids.append(node_id)
        return ids

    header = next(
        (t for t in soup.find_all(["h2", "h3", "div", "span"])
         if t.get_text(" ", strip=True).strip().lower() == "taxonomy mappings"),
        None
    )
    if header:
        table = header.find_next("table")
        if table:
            found = collect_from_table(table)
            if found:
                return found

    all_ids: List[str] = []
    for tbl in soup.find_all("table"):
        ids = collect_from_table(tbl)
        for x in ids:
            if x not in all_ids:
                all_ids.append(x)

    return all_ids

def get_related_certc_cids(cwe_id: str, cew_mappings_path: str = CWE_MAPPINGS_PATH) -> List[str]:
    key = str(cwe_id).strip()
    try:
        key = f"{int(float(key))}.0"
    except Exception:
        pass  

    mappings: CWEToCertCMap = get_cwe_mappings(cew_mappings_path)
    related_certc_cids = mappings.get(key, [])
    return related_certc_cids

if __name__ == "__main__":
    from coverity import get_coverity_issues_cwes
    
    cwes = get_coverity_issues_cwes() 
    if not cwes:
        print("No CWEs found in Coverity issues.")
        exit(1)
    print("Finding CWE to CERT-C mappings for: ", cwes, "...")
    
    print("Extracting mappings from URL and building json ...")
    mappings_from_url = extract_cwe_mappings(cwes)
    build_cwe_mappings_json(mappings_from_url)  
    
    print("Showing created json mappings...")
    cwe_mappings = get_cwe_mappings()
    print(json.dumps(mappings_from_url, indent=2))
    
    print (f"Example: Getting mappings for cwe{cwes[0]} from json")
    related_certc_cids = get_related_certc_cids(cwes[0])
    print(related_certc_cids)
