#!/usr/bin/env python3
"""Record a newly-released Claude Code build into the verified_sites registry.

This is the CI half of the patcher: the *recording* cost (the 20-60 min oracle
probe) is paid here, on a runner, instead of on every user's machine. It
downloads (or takes a local copy of) a build, runs the existing oracle binder
(oracle_bind_auto.bind), and leaves an updated verified_sites.json for the
workflow to commit. Users then just run patch.sh, which looks the record up
(jq, local then repo) and applies it - no probe.

The binding is no-guess: every site and target is measurement-defined by the
probe (oracle_bind_auto.bind refuses rather than record anything it cannot
measure). A build whose key is already bound at the same size is a no-op
("already bound"); a build that refuses leaves the registry untouched.

Usage:
    # bind an existing local binary (no download; tests, manual use)
    python3 ci_bind_new_version.py --binary /path/to/2.1.273 --registry verified_sites.json

    # download a specific version (CI; the URL is the one open detail)
    python3 ci_bind_new_version.py --version 2.1.273 \
        --download-url "$CLAUDE_BINARY_URL" --registry verified_sites.json

The registry key is the binary's basename, so a downloaded build must be saved
under its version name (e.g. 2.1.273) for the key to read as the version.

The download URL may point at the binary itself or at a tarball containing it
(the github release assets ship claude-<platform>.tar.gz; the npm platform
packages ship the binary inside their tarball). A tarball is unpacked with a
no-guess member rule (see extract_binary): a regular file named `claude` wins,
else exactly one regular file; anything else is refused.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tarfile
import tempfile
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "experiments", "recompile"))
import oracle_bind_auto as oba  # noqa: E402

_DEFAULT_REGISTRY = os.path.join(_HERE, "verified_sites.json")
_DEFAULT_PROBE = os.path.join(_HERE, "experiments", "recompile", "run_probe.sh")


_GZIP_MAGIC = b"\x1f\x8b"


def extract_binary(archive: str, dest: str) -> str:
    """Place the build's binary at `dest`. If `archive` is not a tarball it IS
    the binary and is moved to `dest`. A tarball is unpacked under a no-guess
    member rule: a regular file named `claude` (both the github release
    tarballs and the npm platform tarballs carry exactly one) wins; failing
    that, an archive of exactly one regular file; anything else (zero
    members, several candidates) is refused (ValueError). Member names are
    extracted through tarfile's `data` filter (no paths escaping dest)."""
    with open(archive, "rb") as f:
        magic = f.read(2)
    if magic != _GZIP_MAGIC:
        shutil.move(archive, dest)
        return dest

    try:
        with tarfile.open(archive, "r:gz") as tar:
            members = [m for m in tar.getmembers() if m.isreg()]
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"archive {archive} is unreadable: {exc}") from exc

    named = [m for m in members if os.path.basename(m.name) == "claude"]
    if len(named) == 1:
        pick = named[0]
    elif len(members) == 1:
        pick = members[0]
    else:
        listing = ", ".join(sorted(m.name for m in members)) or "no regular files"
        raise ValueError(
            f"cannot identify the binary in {archive}: members are [{listing}] "
            "- no 'claude' member and not a single-file archive"
        )

    workdir = tempfile.mkdtemp(prefix="ci_extract_")
    try:
        with tarfile.open(archive, "r:gz") as tar:
            tar.extract(pick, path=workdir, filter="data")
        extracted = os.path.join(workdir, *pick.name.split("/"))
        shutil.move(extracted, dest)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return dest


def download_version(url: str, dest: str, timeout: int = 600) -> str:
    """Fetch the build at `url` and place it at `dest`. Isolated on purpose:
    this is the one mechanism that must track however Claude Code distributes
    a given version (the self-updater URL, the npm package, a release asset
    tarball). Keep it a single swappable function - the rest of the script
    only sees a local file. A tarball answer is unpacked first (the member is
    identified, never guessed). Returns `dest`; raises on a failed fetch or
    an unidentifiable archive."""
    print(f"download: {url} -> {dest}")
    workdir = tempfile.mkdtemp(prefix="ci_dl_")
    tmp = os.path.join(workdir, "download")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp, open(tmp, "wb") as out:
            shutil.copyfileobj(resp, out)
        extract_binary(tmp, dest)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    os.chmod(dest, 0o755)
    return dest


def resolve_binary(args: argparse.Namespace) -> str:
    """Return the local path of the build to bind. With --binary it is that
    file; otherwise the build is downloaded to a workdir file named after the
    version (so the registry key reads as the version). Refuses (SystemExit 2)
    when neither a local binary nor a download URL is available."""
    if args.binary:
        if not os.path.isfile(args.binary):
            print(f"error: binary {args.binary} not found", file=sys.stderr)
            raise SystemExit(2)
        return os.path.abspath(args.binary)

    url = args.download_url or os.environ.get("CLAUDE_BINARY_URL", "")
    if not url:
        print(
            "error: no build to bind: pass --binary PATH, or --download-url URL "
            "(or set CLAUDE_BINARY_URL) so the build can be fetched.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if not args.version:
        print(
            "error: a download needs --version (it names the downloaded file, "
            "which becomes the registry key).",
            file=sys.stderr,
        )
        raise SystemExit(2)
    workdir = tempfile.mkdtemp(prefix="ci_bind_")
    dest = os.path.join(workdir, args.version)
    try:
        download_version(url, dest)
    except ValueError as exc:
        print(f"error: build at {url} is not bindable: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except OSError as exc:
        print(f"error: download of {url} failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
    return dest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--binary",
                    help="an existing local build to bind (no download)")
    ap.add_argument("--version",
                    help="the version label; names a downloaded build and "
                         "documents the record")
    ap.add_argument("--download-url",
                    help="URL of the build to fetch (or set CLAUDE_BINARY_URL)")
    ap.add_argument("--registry", default=_DEFAULT_REGISTRY,
                    help="verified_sites registry to record into (default: "
                         "verified_sites.json at the repo root)")
    ap.add_argument("--probe", default=_DEFAULT_PROBE,
                    help="probe script with the run_probe.sh contract "
                         "(default: experiments/recompile/run_probe.sh)")
    ap.add_argument("--nearest", type=int, default=5,
                    help="how many nearest ceiling candidates the binder tries "
                         "(default 5)")
    args = ap.parse_args(argv)

    binary = resolve_binary(args)
    if args.binary:
        print(f"binding {binary}")
    else:
        print(f"binding version {args.version} from {binary}")

    if not os.path.isfile(args.probe):
        print(f"error: probe script {args.probe} not found", file=sys.stderr)
        return 2

    try:
        ok = oba.bind(binary, args.registry, oba.probe_via_script(args.probe),
                      nearest=args.nearest)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if ok:
        print(f"registry: {args.registry} now records this build")
        return 0
    print("binding refused: no registry entry was recorded (no-guess invariant)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
