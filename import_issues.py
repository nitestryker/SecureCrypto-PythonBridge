
import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path

# --- CONFIG ---
REPO = "https://github.com/nitestryker/SecureCrypto-PythonBridge"  # <-- change this
CSV_PATH = "github_issues.csv"                    # or absolute path

def find_gh() -> str:
    """Return full path to gh.exe, or raise a clear error."""
    gh_path = shutil.which("gh")
    if gh_path:
        return gh_path

    # Common install locations on Windows
    candidates = [
        r"C:\Program Files\GitHub CLI\gh.exe",
        r"C:\Users\%USERNAME%\AppData\Local\Programs\GitHub CLI\gh.exe",
    ]

    for c in candidates:
        resolved = os.path.expandvars(c)
        if Path(resolved).exists():
            return resolved

    raise FileNotFoundError(
        "Could not find GitHub CLI (gh.exe). Make sure it's installed and in PATH, "
        "or update the candidates list in this script. "
        "After installing via winget, you may need to add its folder to PATH and open a NEW terminal."
    )

def main():
    gh = find_gh()

    csv_file = Path(CSV_PATH)
    if not csv_file.exists():
        print(f"CSV not found: {csv_file.resolve()}", file=sys.stderr)
        sys.exit(1)

    with csv_file.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            title = (row.get("Title") or "").strip()
            body = (row.get("Body") or "").strip()
            labels_raw = (row.get("Labels") or "").strip()

            if not title:
                print(f"[skip] Row {i}: missing Title")
                continue

            # Allow comma or semicolon separated labels
            labels_parts = [x.strip() for x in labels_raw.replace(";", ",").split(",") if x.strip()]
            # gh accepts multiple --label flags; add one per label
            label_flags = []
            for lab in labels_parts:
                label_flags += ["--label", lab]

            cmd = [gh, "issue", "create", "--repo", REPO, "--title", title, "--body", body] + label_flags
            print(f"[{i}] Creating issue: {title}")
            subprocess.run(cmd, check=True)

    print("Done. All issues created.")

if __name__ == "__main__":
    main()
