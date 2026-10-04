#!/usr/bin/env python3
"""Record a newly-released Claude Code build as a GitHub Release binding.

This is the CI half of the patcher: the *recording* cost (the 20-60 min
oracle probe) is paid here, on a runner, instead of on every user's
machine. It downloads (or takes a local copy of) a build, runs the
existing oracle binder (oracle_bind_auto.bind), and - after the recorded
entry passes the end-to-end test - emits the release artifact (the entry
verbatim as verified_site.json, plus the release title and notes) for the
workflow to publish as the GitHub release `auto-mode-timeout-<name>`.
Users then just run patch.sh, which fetches exactly that release and
applies it - no probe.

Before anything is published, the recorded entry is tested end-to-end: it
is applied through the canonical apply path (patch_classifier_timeout.py
--apply-live, the same byte re-check and --version gate the local patcher
runs) and the artifact is probed at the 150 s cap - rc=124 (killed, still
waiting) is the pass, and the result is stamped into the entry's evidence.
When the test fails the entry is removed and the OTHER found values are
tried one by one (oracle_bind_auto.bind_candidates: each candidate driver
measured against its own ceiling, then the end-to-end test again), up to
--max-candidates. A winning candidate's entry passes the same canonical
apply-path test (and gets the same stamp) before it is emitted. The
artifact is emitted only for a binding that passed the end-to-end test, so
a release is never published for a binding that did not pass.

Every recorded entry also carries the sha256 of the binary it was measured
on: a byte-identical local build applies without any local probe (patch.sh
hashes the target and compares - the 150 s test was paid here).

The binding is no-guess: every site and target is measurement-defined by
the probe (oracle_bind_auto.bind refuses rather than record anything it
cannot measure). A build whose release `auto-mode-timeout-<name>` already
exists is a no-op ("already bound" - the existing release stands, nothing
is re-measured, nothing is emitted); a build that refuses leaves no
artifact behind.

Usage:
    # bind an existing local binary (no download; tests, manual use)
    python3 tools/ci_bind_new_version.py --binary /path/to/2.1.273 \
        --out publish

    # download a specific version (CI; the URL is the one open detail)
    python3 tools/ci_bind_new_version.py --version 2.1.273 \
        --download-url "$CLAUDE_BINARY_URL" --out publish

The release name is the binary's basename, so a downloaded build must be
saved under its version name (e.g. 2.1.273) for the release tag to read as
the version.

The download URL may point at the binary itself or at a tarball containing
it (the github release assets ship claude-<platform>.tar.gz; the npm
platform packages ship the binary inside their tarball). A tarball is
unpacked with a no-guess member rule (see extract_binary): a regular file
named `claude` wins, else exactly one regular file; anything else is
refused.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "binder"))
import migrate_registry_to_releases as mrt  # noqa: E402
import oracle_bind_auto as oba  # noqa: E402

_DEFAULT_PROBE = os.path.join(_HERE, "binder", "run_probe.sh")


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
    version (so the release name reads as the version). Refuses (SystemExit 2)
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
            "which becomes the release name).",
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


def stamp_ci_e2e(registry: str, label: str, rc: int, elapsed: float,
                 cap_s: int) -> None:
    """Record the end-to-end result in the entry's evidence (the CI trust
    mark, next to the entry's sha256: the test was paid here, on the
    runner, for exactly these bytes)."""
    import time
    doc = oba.load_registry_doc(registry)
    entry = doc.get(label)
    if not isinstance(entry, dict):
        raise ValueError(f"registry has no entry {label!r} to stamp")
    entry.setdefault("evidence", {})["ci_e2e"] = {
        "date": time.strftime("%Y-%m-%d"),
        "probe_cap_s": cap_s,
        "rc": rc,
        "elapsed_s": round(elapsed, 1),
        "verified_by": ("tools/ci_bind_new_version.py (GitHub Actions): the "
                        "recorded entry was applied through the canonical "
                        "apply path and the artifact was probed at the "
                        "end-to-end cap"),
    }
    oba.write_registry_doc(registry, doc)


def remove_entry(registry: str, label: str) -> None:
    """Drop a recorded entry that did not pass the end-to-end test (the
    candidate fallback then records a passing one, or nothing is
    published)."""
    doc = oba.load_registry_doc(registry)
    if label not in doc:
        raise ValueError(f"registry has no entry {label!r} to remove")
    del doc[label]
    oba.write_registry_doc(registry, doc)


def e2e_verify_entry(binary: str, registry: str, label: str, probe: str,
                     cap_s: int = oba.PROBE_CAP_S):
    """The end-to-end test of a recorded entry (the ~150 s wait, paid here
    instead of on every user's machine): the entry is applied through the
    canonical apply path (patch_classifier_timeout.py --apply-live - the
    same recorded-byte re-check and --version execute gate the local
    patcher runs), and the resulting artifact is probed at the cap:
    rc=124 (killed by the probe timeout, still inside the classifier wait)
    is the pass - the recorded targets really extend the wait. Returns
    (passed, rc, elapsed, note)."""
    workdir = tempfile.mkdtemp(prefix="ci_e2e_")
    artifact = os.path.join(workdir, os.path.basename(binary) + ".patched")
    try:
        apply = subprocess.run(
            [sys.executable,
             os.path.join(_HERE, "patch_classifier_timeout.py"),
             "--registry", registry, "--out", artifact, binary,
             "--apply-live"],
            capture_output=True, text=True,
        )
        if apply.returncode != 0 or not os.path.isfile(artifact):
            lines = (apply.stdout + apply.stderr).strip().splitlines()
            last = lines[-1] if lines else "apply failed"
            return False, None, None, \
                f"the recorded entry no longer applies to these bytes ({last})"
        proc = subprocess.run(["bash", probe, artifact, "e2e", str(cap_s)],
                              capture_output=True, text=True)
        result = oba.parse_probe_result(proc.stdout + "\n" + proc.stderr)
        if result is None:
            return False, None, None, "the e2e probe produced no result line"
        rc, elapsed = result
        note = (f"artifact applied from the recorded entry, probed at the "
                f"{cap_s} s cap: rc={rc} elapsed={elapsed:.1f} s"
                + (" (still waiting - PASS)" if rc == 124
                   else " (the wait collapsed - FAIL)"))
        return rc == 124, rc, elapsed, note
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def emit_release_artifact(out_dir: str, name: str, registry: str) -> None:
    """Write the release artifact into `out_dir` (the workflow publishes
    it as `gh release create auto-mode-timeout-<name>`): the entry verbatim
    as verified_site.json, plus the release title and notes. The entry
    carries everything a consumer needs - size, sites, evidence, and the
    sha256 + ci_e2e stamps when recorded."""
    doc = oba.load_registry_doc(registry)
    entry = doc.get(name)
    if not isinstance(entry, dict):
        raise ValueError(f"registry has no entry {name!r} to publish")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, mrt.ASSET_NAME), "w", encoding="utf-8") as f:
        f.write(mrt.entry_serialization(entry))
    with open(os.path.join(out_dir, "release_title.txt"), "w",
              encoding="utf-8") as f:
        f.write(f"Claude Code {name} - classifier timeout binding\n")
    with open(os.path.join(out_dir, "release_notes.md"), "w",
              encoding="utf-8") as f:
        f.write(mrt.notes_for(name, entry))
    print(f"release artifact: {os.path.join(out_dir, mrt.ASSET_NAME)} "
          f"(to be published as {mrt.tag_for(name)})")


def _fallback(args: argparse.Namespace, binary: str, base: str, state: dict,
              skip_driver: int = None, registry: str = None) -> int:
    """Patch another found value and run the end-to-end test again, up to
    args.max_candidates attempts (each candidate measured against its own
    ceiling, each tested end-to-end). Returns the exit code: 0 = a
    candidate passed, was recorded and emitted (the workflow publishes
    it), 1 = every attempt failed or was refused (nothing to publish)."""
    if args.max_candidates <= 0:
        print("no candidate attempts allowed (--max-candidates 0); "
              "nothing was recorded")
        return 1
    print(f"\n== candidate fallback: up to {args.max_candidates} other found "
          f"values, the end-to-end test per candidate ==")
    ok = oba.bind_candidates(binary, registry,
                            oba.probe_via_script(args.probe),
                            max_candidates=args.max_candidates,
                            nearest=args.nearest,
                            skip_driver=skip_driver, state=state)
    if not ok:
        print("all candidate attempts failed: no registry entry was recorded "
              "(nothing to publish)")
        return 1
    # The recorded candidate passes the same end-to-end gate as the primary
    # entry: the canonical apply path and the 150 s probe. The binder's own
    # boundary probe measured the same targets on the runner; this re-checks
    # them through the exact path the local patcher applies.
    print(f"\n== end-to-end test (the recorded candidate entry, "
          f"{oba.PROBE_CAP_S} s cap) ==")
    passed, rc, elapsed, note = e2e_verify_entry(binary, registry, base,
                                                 args.probe)
    print(f"e2e: {note}")
    if passed:
        stamp_ci_e2e(registry, base, rc, elapsed, oba.PROBE_CAP_S)
        emit_release_artifact(args.out, base, registry)
        print(f"the recorded candidate entry is emitted "
              f"(candidate fallback, end-to-end verified on the runner)")
        return 0
    print("e2e: the recorded candidate entry did not pass; removing it "
          "(nothing to publish)")
    remove_entry(registry, base)
    return 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--binary",
                    help="an existing local build to bind (no download)")
    ap.add_argument("--version",
                    help="the version label; names a downloaded build and "
                         "documents the release")
    ap.add_argument("--download-url",
                    help="URL of the build to fetch (or set CLAUDE_BINARY_URL)")
    ap.add_argument("--probe", default=_DEFAULT_PROBE,
                    help="probe script with the run_probe.sh contract "
                         "(default: tools/binder/run_probe.sh)")
    ap.add_argument("--nearest", type=int, default=5,
                    help="how many nearest ceiling candidates the binder tries "
                         "(default 5)")
    ap.add_argument("--max-candidates", type=int, default=5,
                    help="when the end-to-end test fails (or the primary "
                         "binding refuses), how many other found driver "
                         "values to try before giving up (default 5; 0 = no "
                         "fallback)")
    ap.add_argument("--out",
                    help="directory for the emitted release artifact "
                         "(verified_site.json + release_title.txt + "
                         "release_notes.md; the workflow publishes it). "
                         "Default: a temporary directory removed on exit.")
    args = ap.parse_args(argv)

    # A user-supplied --out is kept (the workflow publishes from it); the
    # auto-created default is cleaned up with the rest of the workdir.
    created_out = False
    if args.out is None:
        args.out = tempfile.mkdtemp(prefix="ci_publish_")
        created_out = True

    binary = resolve_binary(args)
    if args.binary:
        print(f"binding {binary}")
    else:
        print(f"binding version {args.version} from {binary}")

    if not os.path.isfile(args.probe):
        print(f"error: probe script {args.probe} not found", file=sys.stderr)
        return 2
    if args.max_candidates < 0:
        print("error: --max-candidates must be 0 or more", file=sys.stderr)
        return 2

    base = os.path.basename(binary)

    # The already-bound no-op: the release for this build's name exists
    # (a previous run published it, or the migration did). The existing
    # release stands - nothing is re-measured, nothing is emitted.
    repo = mrt.repo_from_origin()
    exists = mrt.release_exists(repo, mrt.tag_for(base))
    if exists:
        print(f"release: {mrt.tag_for(base)} already exists - already bound "
              f"(the existing release stands; nothing to publish)")
        return 0

    # The binding runs against a WORKDIR registry (the repo tracks nothing
    # binding-related any more); a passing entry is emitted as the release
    # artifact, a failing one leaves no artifact behind.
    workdir = tempfile.mkdtemp(prefix="ci_bind_work_")
    registry = os.path.join(workdir, "registry.json")
    try:
        state = {}
        try:
            ok = oba.bind(binary, registry, oba.probe_via_script(args.probe),
                          nearest=args.nearest, state=state)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if ok:
            # A new entry was recorded: the end-to-end test (the ~150 s
            # wait) must pass before anything is published.
            print(f"\n== end-to-end test (the recorded entry, {oba.PROBE_CAP_S} s cap) ==")
            passed, rc, elapsed, note = e2e_verify_entry(binary, registry,
                                                         base, args.probe)
            print(f"e2e: {note}")
            if passed:
                stamp_ci_e2e(registry, base, rc, elapsed, oba.PROBE_CAP_S)
                emit_release_artifact(args.out, base, registry)
                print(f"the recorded entry is emitted "
                      f"(end-to-end verified on the runner)")
                return 0
            print("e2e: the recorded entry did not pass; removing it and "
                  "trying the other found values")
            remove_entry(registry, base)
            return _fallback(args, binary, base, state,
                             skip_driver=state.get("driver"),
                             registry=registry)

        print("binding refused: no registry entry was recorded (no-guess "
              "invariant); trying the other found values")
        return _fallback(args, binary, base, state, skip_driver=None,
                         registry=registry)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        if created_out:
            shutil.rmtree(args.out, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
