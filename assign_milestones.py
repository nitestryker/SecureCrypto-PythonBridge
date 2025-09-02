# assign_milestones.py (robust matching)
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# --- CONFIG ---
REPO = "nitestryker/SecureCrypto-PythonBridge"  # owner/name
DRY_RUN = False  # set True to preview without changing anything

# Label → milestone mapping (case-insensitive)
LABEL_TO_MILESTONE = {
    "ci": "v1.2 – Testing & CI",
    "testing": "v1.2 – Testing & CI",
    "documentation": "v1.6 – Docs & Site",
    "security": "v1.4 – Security Hardening",
    "feature": "v1.1 – Developer Ergonomics",
    "enhancement": "v1.1 – Developer Ergonomics",
}

# Keyword → milestone mapping (regex matched in title/body, case-insensitive)
KEYWORD_TO_MILESTONE = [
    # v1.1
    (r"\b(pypi|wheel|package|publish)\b", "v1.1 – Developer Ergonomics"),
    (r"\b(cli|command[- ]?line|entry[- ]?point)\b", "v1.1 – Developer Ergonomics"),
    (r"\b(type\s*hints?|typing|docstrings?)\b", "v1.1 – Developer Ergonomics"),
    (r"\b(helper|convenience|encrypt_and_sign|verify_and_decrypt)\b", "v1.1 – Developer Ergonomics"),
    (r"\b(example|examples|demo)\b", "v1.1 – Developer Ergonomics"),
    (r"\b(benchmark|performance)\b", "v1.1 – Developer Ergonomics"),
    # v1.2
    (r"\b(pytest|unit\s*tests?|coverage|lint|format(ting)?|pre-commit)\b", "v1.2 – Testing & CI"),
    (r"\b(ci|workflow|github\s*actions)\b", "v1.2 – Testing & CI"),
    # v1.3
    (r"\b(linux|macos|cross[- ]?platform|mono|\.net\s*(6|7))\b", "v1.3 – Cross-Platform"),
    # v1.4
    (r"\b(dpapi|keychain|libsecret|key\s*storage|key\s*rotation|constant[- ]?time|timing[- ]?safe)\b", "v1.4 – Security Hardening"),
    (r"\b(encrypt(ed)?\s*private\s*key|pem)\b", "v1.4 – Security Hardening"),
    # v1.5
    (r"\b(strong[- ]?name|signed\s*dll|signed\s*release|pipx|dev\s*container|docker)\b", "v1.5 – Packaging & Distribution"),
    # v1.6
    (r"\b(api\s*reference|mkdocs|docs\s*site|tutorial|diagram|faq)\b", "v1.6 – Docs & Site"),
    # v2.0
    (r"\b(stream(ing)?|chunk(ed|ing)|parallel|multi[- ]?thread(ed)?|aes[- ]?gcm|argon2id|version(ed|ing)|rest|fastapi|flask)\b", "v2.0 – Advanced Features"),
]

def find_gh() -> str:
    p = shutil.which("gh")
    if p:
        return p
    for c in (r"C:\Program Files\GitHub CLI\gh.exe",
              r"C:\Users\%USERNAME%\AppData\Local\Programs\GitHub CLI\gh.exe"):
        c = os.path.expandvars(c)
        if Path(c).exists():
            return c
    raise FileNotFoundError("Cannot find gh.exe; add it to PATH or update this script.")

def gh_json(gh: str, args: List[str]) -> list:
    res = subprocess.run([gh] + args, text=True, capture_output=True)
    if res.returncode != 0:
        print("[gh error]", res.stderr.strip(), file=sys.stderr)
        res.check_returncode()
    return json.loads(res.stdout) if res.stdout.strip() else []

def list_open_issues(gh: str, repo: str) -> List[dict]:
    return gh_json(gh, [
        "issue", "list",
        "--repo", repo,
        "--state", "open",
        "--limit", "1000",
        "--json", "number,title,body,labels,milestone"
    ])

def normalize_title(s: str) -> str:
    # unify dashes and whitespace; lowercase
    s = (s or "").replace("\u2013", "-").replace("\u2014", "-")
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s

def fetch_milestones(gh: str, repo: str) -> Tuple[Dict[str, int], Dict[str, str]]:
    arr = gh_json(gh, ["api", f"repos/{repo}/milestones?state=all&per_page=100"])
    norm_to_num: Dict[str, int] = {}
    num_to_title: Dict[str, str] = {}
    for m in arr:
        title = m.get("title", "")
        num = m.get("number")
        if num is None:
            continue
        norm_to_num[normalize_title(title)] = num
        num_to_title[str(num)] = title
    return norm_to_num, num_to_title

def choose_milestone(title: str, body: str, labels: List[str]) -> Optional[str]:
    lower_labels = {l.lower() for l in labels}
    for lab, milestone in LABEL_TO_MILESTONE.items():
        if lab.lower() in lower_labels:
            return milestone
    text = f"{title}\n{body or ''}"
    for pattern, milestone in KEYWORD_TO_MILESTONE:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return milestone
    return None

def assign_issue_to_milestone(gh: str, repo: str, issue_number: int, milestone_number: int, dry_run: bool = False) -> None:
    if dry_run:
        print(f"[dry-run] would assign issue #{issue_number} -> milestone #{milestone_number}")
        return
    res = subprocess.run([
        gh, "api", "-X", "PATCH",
        f"repos/{repo}/issues/{issue_number}",
        "-f", f"milestone={milestone_number}"
    ], text=True, capture_output=True)
    if res.returncode != 0:
        print(f"[assign error] issue #{issue_number}: {res.stderr.strip()}", file=sys.stderr)
        res.check_returncode()

def main():
    gh = find_gh()
    repo = REPO

    # fetch milestones and show what we have
    norm_map, num_to_title = fetch_milestones(gh, repo)
    if not norm_map:
        print("No milestones found. Create milestones first.")
        return

    print("[milestones found]")
    for num, title in sorted(num_to_title.items(), key=lambda x: int(x[0])):
        print(f"  #{num}: {title}")

    issues = list_open_issues(gh, repo)
    if not issues:
        print("No open issues found.")
        return

    assigned = 0
    skipped = 0

    for issue in issues:
        number = issue.get("number")
        title = issue.get("title", "")
        body = issue.get("body") or ""
        labels = [l.get("name", "") for l in (issue.get("labels") or [])]
        current_ms = issue.get("milestone", {}).get("title") if issue.get("milestone") else None

        if current_ms:
            print(f"[skip] issue #{number} already in milestone: {current_ms} ({title})")
            skipped += 1
            continue

        chosen_title = choose_milestone(title, body, labels)
        if not chosen_title:
            print(f"[skip] no match for issue #{number}: {title}")
            skipped += 1
            continue

        norm_chosen = normalize_title(chosen_title)
        ms_num = norm_map.get(norm_chosen)

        # fallback: try prefix match on version e.g., "v1.2"
        if not ms_num and chosen_title.lower().startswith("v"):
            ver = chosen_title.split("–", 1)[0].split("-", 1)[0].strip().lower()  # "v1.2"
            for k, v in norm_map.items():
                if k.startswith(ver):
                    ms_num = v
                    break

        if not ms_num:
            print(f"[warn] milestone not found in repo: {chosen_title} (issue #{number}: {title})")
            skipped += 1
            continue

        print(f"[assign] issue #{number}: '{title}' → {chosen_title}")
        try:
            assign_issue_to_milestone(gh, repo, number, ms_num, dry_run=DRY_RUN)
            assigned += 1
        except subprocess.CalledProcessError:
            pass

    print(f"Done. Assigned: {assigned}, Skipped: {skipped}")

if __name__ == "__main__":
    main()
