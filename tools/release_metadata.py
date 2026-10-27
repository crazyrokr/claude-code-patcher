"""Release metadata shared by the CI binder and the registry migration.

One GitHub Release per binding: the tag is `auto-mode-timeout-<name>`, the
release carries the entry verbatim as its single asset verified_site.json.
The tag/asset/notes shapes and the gh/curl accessors live here so the CI
publish path (ci_bind_new_version), the one-shot migration
(migrate_registry_to_releases) and a consumer-side change (a renamed asset
or a moved URL) all speak the same release vocabulary from one place.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

ASSET_NAME = "verified_site.json"
TAG_PREFIX = "auto-mode-timeout-"


def tag_for(name: str) -> str:
    return f"{TAG_PREFIX}{name}"


def entry_serialization(entry: dict) -> str:
    """The asset bytes: the entry object, same deterministic JSON the
    registry uses (indent=2, trailing newline) - a round trip must come
    back byte-identical."""
    return json.dumps(entry, indent=2) + "\n"


def notes_for(name: str, entry: dict) -> str:
    """The release body: a short evidence summary (the machine contract
    lives in the asset; the body is for humans skimming the release)."""
    lines = [
        f"Oracle-verified classifier timeout binding for Claude Code {name}.",
        "",
        f"- binary size: {entry['size']} B",
    ]
    sha256 = entry.get("sha256")
    lines.append(
        f"- sha256: {sha256}"
        if isinstance(sha256, str)
        else "- sha256: not recorded (pre-stamp entry)"
    )
    for site in entry.get("sites", []):
        role = site.get("role", "")
        lines.append(
            f"- site @ {site['offset']}: {site['old']} -> {site['target']} ({role})"
            if role
            else f"- site @ {site['offset']}: {site['old']} -> {site['target']}"
        )
    ci = (
        entry.get("evidence", {}).get("ci_e2e")
        if isinstance(entry.get("evidence"), dict)
        else None
    )
    if isinstance(ci, dict):
        lines.append(
            f"- end-to-end: probed at {ci.get('probe_cap_s')} s, "
            f"rc={ci.get('rc')} (still waiting), "
            f"{ci.get('date')}"
        )
    else:
        lines.append("- end-to-end: not stamped (pre-stamp entry)")
    date = (
        entry.get("evidence", {}).get("date")
        if isinstance(entry.get("evidence"), dict)
        else None
    )
    if isinstance(date, str):
        lines.append(f"- evidence date: {date}")
    lines.append("")
    lines.append("One release per binding; the asset is the entry verbatim.")
    return "\n".join(lines) + "\n"


def repo_from_origin():
    """The checkout's own repository as OWNER/NAME (the scripts' origin
    derivation: the full ref with refs/remotes/origin/ stripped; github
    https remotes only). None when it cannot be derived."""
    try:
        remote = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
    except (OSError, ValueError):
        return None
    for prefix in ("https://github.com/", "http://github.com/"):
        if remote.startswith(prefix):
            repo = remote[len(prefix) :]
            return repo[:-4] if repo.endswith(".git") else repo
    return None


def gh_available() -> bool:
    return shutil.which("gh") is not None


def release_exists(repo: str, tag: str):
    """True/False, or None when gh cannot answer (missing, unauthenticated,
    or a network failure) - the caller then publishes and lets a
    duplicate-tag refusal surface there."""
    if not gh_available():
        return None
    proc = subprocess.run(
        ["gh", "release", "view", tag, "--json", "url"]
        + (["--repo", repo] if repo else []),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return True
    combined = proc.stdout + proc.stderr
    if (
        "not found" in combined.lower()
        or "no result" in combined.lower()
        or "404" in combined
    ):
        return False
    return None


def create_release(
    repo: str, tag: str, title: str, notes_file: str, asset_file: str
) -> bool:
    # The asset is a POSITIONAL argument of `gh release create` (this
    # form is the one every gh version understands; there is no --files
    # flag on the command).
    cmd = [
        "gh",
        "release",
        "create",
        tag,
        "--title",
        title,
        "--notes-file",
        notes_file,
        asset_file,
    ]
    if repo:
        cmd += ["--repo", repo]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(
            f"gh release create {tag} failed: {(proc.stdout + proc.stderr).strip()}",
            file=sys.stderr,
        )
        return False
    return True


def download_asset(repo: str, tag: str) -> bytes | None:
    """The asset at its release URL (curl, the same fetch the consumers
    use). None on any failure."""
    url = f"https://github.com/{repo}/releases/download/{tag}/{ASSET_NAME}"
    with tempfile.TemporaryDirectory(prefix="migrate_rt_") as tmp:
        out = os.path.join(tmp, ASSET_NAME)
        proc = subprocess.run(
            ["curl", "-fsSL", "--max-time", "30", url, "-o", out],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not os.path.isfile(out):
            return None
        with open(out, "rb") as f:
            return f.read()
