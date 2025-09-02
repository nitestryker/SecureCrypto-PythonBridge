import os, shutil, subprocess, sys
from pathlib import Path

# --- CONFIG ---
REPO = "nitestryker/SecureCrypto-PythonBridge"  # owner/name

MILESTONES = [
    ("v1.1 – Developer Ergonomics", "Ergonomics: PyPI, CLI, helpers, types, docs"),
    ("v1.2 – Testing & CI", "Unit tests, coverage, lint/format, CI polish"),
    ("v1.3 – Cross-Platform", "Linux/macOS CI, runtime docs, .NET 6/7 validation"),
    ("v1.4 – Security Hardening", "Key storage, encrypted private keys, rotation, constant-time checks"),
    ("v1.5 – Packaging & Distribution", "Signed releases, strong-named DLL, pipx, dev container"),
    ("v1.6 – Docs & Site", "API reference, tutorials, diagrams, security FAQ"),
    ("v2.0 – Advanced Features", "Streaming/chunked, parallel, AES-GCM, Argon2id, format versioning, REST example"),
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

def existing_titles(gh: str, repo: str) -> set[str]:
    # Use query params in the URL for GET; include paginate + jq
    cmd = [
        gh, "api",
        f"repos/{repo}/milestones?state=all&per_page=100",
        "--paginate",
        "--jq", ".[].title"
    ]
    res = subprocess.run(cmd, text=True, capture_output=True)
    if res.returncode != 0:
        print("[milestone] list error:", res.stderr.strip(), file=sys.stderr)
        res.check_returncode()
    return {t.strip() for t in res.stdout.splitlines() if t.strip()}

def create_milestone(gh: str, repo: str, title: str, description: str) -> None:
    print(f"[milestone] creating: {title}")
    cmd = [
        gh, "api", f"repos/{repo}/milestones",
        "-f", f"title={title}",
        "-f", f"description={description}",
        "-f", "state=open"
    ]
    res = subprocess.run(cmd, text=True, capture_output=True)
    if res.returncode != 0:
        print("[milestone] create error:", res.stderr.strip(), file=sys.stderr)
        res.check_returncode()

def main():
    gh = find_gh()
    repo = REPO

    exists = existing_titles(gh, repo)
    for title, desc in MILESTONES:
        if title in exists:
            print(f"[milestone] exists: {title}")
            continue
        try:
            create_milestone(gh, repo, title, desc)
        except subprocess.CalledProcessError:
            # already printed stderr in create_milestone
            pass

    print("Done. Check repo milestones.")

if __name__ == "__main__":
    main()
