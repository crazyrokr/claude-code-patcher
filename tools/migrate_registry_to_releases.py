#!/usr/bin/env python3
"""Migrate the verified_sites registry to one GitHub Release per binding.

The registry (verified_sites.json, the in-repo document keyed by build name)
is replaced by a GitHub Release per entry: the tag is
`auto-mode-timeout-<name>`, the release carries the entry verbatim as its
single asset `verified_site.json` (size/sites/evidence - sha256 and the
ci_e2e stamp included when the entry carries them). Consumers then fetch
exactly the release named after the binary on their machine; nothing
binding-related is tracked in the repository any more.

For every entry the script publishes the release (gh release create,
skipping entries whose release already exists - a re-run is idempotent)
and then verifies the round trip: the asset is downloaded from its
release URL (curl) and must be byte-identical to the published entry. An
existing release whose asset differs from the registry entry is REFUSED
(reported, never overwritten). Every entry is validated before any
publish (a non-object registry, or an entry without a positive integer
size, is a refusal - the no-guess shape, same as the binder's).

Usage:
    python3 tools/migrate_registry_to_releases.py
        # the repo-root registry, the checkout's own repository
    python3 tools/migrate_registry_to_releases.py --registry PATH \
        --repo OWNER/NAME --dry-run

Exit: 0 = every entry published and round-trip verified (or already
published, byte-identical); 1 = a refused entry or a round-trip
mismatch; 2 = usage error (missing registry, missing gh, no repository).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile

import release_metadata as rm

_HERE = os.path.dirname(os.path.abspath(__file__))
# The registry FILE left the repository (one release per binding); the
# default document to migrate is the local binding cache now.
_DEFAULT_REGISTRY = os.path.join(
    os.path.expanduser("~"), ".local", "share", "claude", "verified_sites.json"
)


def validate_entry(name: str, entry: object):
    """The no-guess shape check (same contract as live_scan's loader for a
    single entry). Returns an error string, or None when the entry is
    publishable."""
    if not isinstance(entry, dict):
        return f"entry {name!r} is not a JSON object"
    size = entry.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        return f"entry {name!r} has no positive integer size"
    sites = entry.get("sites")
    if not isinstance(sites, list) or not sites:
        return f"entry {name!r} has no sites"
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--registry",
        default=_DEFAULT_REGISTRY,
        help="the registry document to migrate (default: the local binding "
        "cache ~/.local/share/claude/verified_sites.json)",
    )
    ap.add_argument(
        "--repo",
        help="OWNER/NAME of the release repository (default: "
        "derived from the checkout's origin remote)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and report what would be published; no gh or network calls",
    )
    args = ap.parse_args(argv)

    if not os.path.isfile(args.registry):
        print(f"error: registry {args.registry} not found", file=sys.stderr)
        return 2

    try:
        doc = json.load(open(args.registry, encoding="utf-8"))
    except ValueError as exc:
        print(
            f"error: registry {args.registry} is not valid JSON: {exc}", file=sys.stderr
        )
        return 2
    if not isinstance(doc, dict):
        print(
            f"error: registry {args.registry} does not hold a JSON object",
            file=sys.stderr,
        )
        return 2
    if not doc:
        print("registry is empty - nothing to migrate")
        return 0

    # Validate EVERY entry before any publish (a refusal must not leave
    # half the registry published).
    refused = []
    for name, entry in doc.items():
        problem = validate_entry(name, entry)
        if problem:
            refused.append(problem)
    if refused:
        for problem in refused:
            print(f"REFUSED: {problem}", file=sys.stderr)
        print(
            f"{len(refused)} entr{'y' if len(refused) == 1 else 'ies'} "
            f"refused - nothing was published.",
            file=sys.stderr,
        )
        return 1

    repo = args.repo or rm.repo_from_origin()
    if args.dry_run:
        # Validation only: no gh, no network (the plan is printed; a real
        # run is what checks which releases already exist).
        print(
            f"dry run: {len(doc)} entries are publishable, repository "
            f"{repo or '<unresolved>'}; tags:"
        )
        for name in doc:
            print(
                f"  {rm.tag_for(name)}: size {doc[name]['size']} B, "
                f"{len(doc[name]['sites'])} site(s)"
            )
        return 0
    if not rm.gh_available():
        print(
            "error: the gh CLI is required to publish releases (or use --dry-run)",
            file=sys.stderr,
        )
        return 2

    published, skipped, failed = [], [], []
    for name in doc:
        tag = rm.tag_for(name)
        exists = rm.release_exists(repo, tag)
        if exists:
            skipped.append(name)
            print(f"{tag}: already published - skipped")
            continue
        workdir = tempfile.mkdtemp(prefix="migrate_pub_")
        try:
            asset = os.path.join(workdir, rm.ASSET_NAME)
            with open(asset, "w", encoding="utf-8") as f:
                f.write(rm.entry_serialization(doc[name]))
            notes = os.path.join(workdir, "notes.md")
            with open(notes, "w", encoding="utf-8") as f:
                f.write(rm.notes_for(name, doc[name]))
            if rm.create_release(
                repo,
                tag,
                f"Claude Code {name} - classifier timeout binding",
                notes,
                asset,
            ):
                published.append(name)
                print(f"{tag}: published")
            else:
                failed.append(name)
                print(f"{tag}: REFUSED (release creation failed)", file=sys.stderr)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # Round-trip verification (every entry, published or skipped: an
    # existing release whose asset drifted is a refusal, never an
    # overwrite).
    mismatches = []
    for name in doc:
        if name in failed:
            continue
        tag = rm.tag_for(name)
        if not repo:
            print(
                f"error: no repository to verify {tag} against "
                f"(pass --repo OWNER/NAME)",
                file=sys.stderr,
            )
            return 2
        fetched = rm.download_asset(repo, tag)
        if fetched is None:
            mismatches.append(f"{tag}: the asset could not be fetched")
            continue
        expected = rm.entry_serialization(doc[name]).encode("utf-8")
        if fetched != expected:
            mismatches.append(
                f"{tag}: the published asset is not "
                f"byte-identical to the registry entry"
            )
        else:
            print(f"{tag}: round trip verified")
    if mismatches:
        for mismatch in mismatches:
            print(f"REFUSED: {mismatch}", file=sys.stderr)
        return 1

    if failed:
        print(
            f"migrated: {len(doc)} entries "
            f"({len(published)} published, {len(skipped)} already present, "
            f"{len(failed)} REFUSED - see above)",
            file=sys.stderr,
        )
        return 1
    print(
        f"migrated: {len(doc)} entries "
        f"({len(published)} published, {len(skipped)} already present, "
        f"all round-trip verified)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
