#!/usr/bin/env python3
"""Pre-publish hygiene gate scanning tracked files, paths, and reachable commit history."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from hygiene_patterns import FORBIDDEN_PATH_GLOBS, PATTERNS  # noqa: E402

EXCLUDED_SCAN_FILES = {
    "scripts/hygiene_patterns.py",
    "scripts/public-hygiene-gate.py",
    "scripts/hygiene_allowlist.json",
    "tests/test_public_hygiene_gate.py",
}


def utc_timestamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


@dataclass
class Hit:
    surface: str
    path: str
    pattern: str
    line: int = 0
    severity: str = "fatal"


@dataclass
class GateResult:
    status: str = "pass"
    scanned: int = 0
    hits: list[Hit] = field(default_factory=list)

    def finalize(self) -> "GateResult":
        if any(h.severity == "fatal" for h in self.hits):
            self.status = "fail"
        return self


def _git(repo_root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo_root), *args],
        text=True,
        stderr=subprocess.DEVNULL,
    )


def scan_paths(repo_root: Path) -> GateResult:
    res = GateResult()
    files = [ln.strip() for ln in _git(repo_root, "ls-files").splitlines() if ln.strip()]
    res.scanned = len(files)
    for rel in files:
        if any(rel.startswith(prefix) for prefix in FORBIDDEN_PATH_GLOBS) or rel.endswith((".db", ".sqlite", ".csv")):
            res.hits.append(Hit(surface="path", path=rel, pattern="forbidden_tracked_path"))
    return res.finalize()


def scan_worktree_files(repo_root: Path) -> GateResult:
    res = GateResult()
    files = [ln.strip() for ln in _git(repo_root, "ls-files").splitlines() if ln.strip()]
    compiled = [
        (p, re.compile(p.regex))
        for p in PATTERNS
        if p.surface in ("all", "content")
    ]
    for rel in files:
        if rel in EXCLUDED_SCAN_FILES:
            continue
        full = repo_root / rel
        if not full.is_file():
            continue
        try:
            text = full.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        res.scanned += 1
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pat, rx in compiled:
                if rx.search(line):
                    res.hits.append(
                        Hit(surface="worktree", path=rel, pattern=pat.name, line=lineno, severity=pat.severity)
                    )
    return res.finalize()


def scan_git_history(repo_root: Path) -> GateResult:
    res = GateResult()
    try:
        revs = [
            ln.strip()
            for ln in _git(repo_root, "rev-list", "HEAD").splitlines()
            if ln.strip()
        ]
    except subprocess.CalledProcessError:
        return res

    msg_patterns = [(p, re.compile(p.regex)) for p in PATTERNS if p.surface in ("all", "commit_msg")]
    diff_patterns = [(p, re.compile(p.regex)) for p in PATTERNS if p.surface in ("all", "content")]

    for rev in revs:
        res.scanned += 1
        msg = _git(repo_root, "show", "-s", "--format=%B", rev)
        for lineno, line in enumerate(msg.splitlines(), start=1):
            for pat, rx in msg_patterns:
                if rx.search(line):
                    res.hits.append(
                        Hit(surface="commit_msg", path=rev[:12], pattern=pat.name, line=lineno, severity=pat.severity)
                    )
        patch_text = _git(
            repo_root,
            "show",
            "--format=",
            "--unified=0",
            rev,
            "--",
            ".",
            ":(exclude)scripts/hygiene_patterns.py",
            ":(exclude)scripts/public-hygiene-gate.py",
            ":(exclude)tests/test_public_hygiene_gate.py",
        )
        cur_file = rev[:12]
        for line in patch_text.splitlines():
            if line.startswith("+++ b/"):
                cur_file = f"{rev[:8]}:{line[6:]}"
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue
            added = line[1:]
            for pat, rx in diff_patterns:
                if rx.search(added):
                    res.hits.append(
                        Hit(surface="git_history", path=cur_file, pattern=pat.name, line=0, severity=pat.severity)
                    )
    return res.finalize()


def run_all_gates(repo_root: Path, write_evidence: bool = False) -> dict:
    ts = utc_timestamp()
    gates = {
        "tracked_paths": scan_paths(repo_root),
        "worktree_content": scan_worktree_files(repo_root),
        "git_history": scan_git_history(repo_root),
    }
    overall = "pass" if all(g.status == "pass" for g in gates.values()) else "fail"
    report = {
        "timestamp": ts,
        "generated_by": "scripts/public-hygiene-gate.py",
        "overall": overall,
        "gates": {
            k: {
                "status": v.status,
                "scanned": v.scanned,
                "hits": [asdict(h) for h in v.hits],
            }
            for k, v in gates.items()
        },
    }
    if write_evidence:
        ev_dir = repo_root / "evidence" / ts
        ev_dir.mkdir(parents=True, exist_ok=True)
        out_file = ev_dir / "public-hygiene-report.json"
        out_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        os.chmod(out_file, 0o600)
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="public-hygiene-gate.py")
    p.add_argument("--repo-root", default=".")
    p.add_argument("--write-evidence", action="store_true")
    args = p.parse_args(argv)
    report = run_all_gates(Path(args.repo_root).resolve(), write_evidence=args.write_evidence)
    print(json.dumps(report, indent=2))
    return 0 if report["overall"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
