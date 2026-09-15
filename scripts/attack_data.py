"""Downloading ATT&CK STIX bundles. Build-time only — never imported by the server.

Every network call in this project lives in ``scripts/``; the package under
``src/`` reads files and nothing else. This module is the one place that knows
where MITRE publishes bundles and how to name a versioned one, so the mappings
generator, the Mongo ingester and the version differ do not each hardcode a URL.

MITRE keeps every release beside the current one:

* ``master/enterprise-attack/enterprise-attack.json`` — whatever is current
* ``master/enterprise-attack/enterprise-attack-<VERSION>.json`` — a pinned release
* ``master/index.json`` — the catalogue of releases that actually exist

The version list is fetched rather than hardcoded, because a hardcoded one is
wrong the day after the next release.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import urllib.request
from pathlib import Path

RAW_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
STIX_URL = f"{RAW_BASE}/enterprise-attack/enterprise-attack.json"
INDEX_URL = f"{RAW_BASE}/index.json"

COLLECTION = "Enterprise ATT&CK"

# Bundles are ~53MB each and two of them get diffed, so they are cached in the
# system temp dir and re-used across runs rather than re-downloaded.
CACHE_DIR = Path(tempfile.gettempdir()) / "mcp-hayabusa-stix"
MIN_BUNDLE_BYTES = 1_000_000


def bundle_url(version: str) -> str:
    """URL of a pinned ATT&CK Enterprise release."""
    return f"{RAW_BASE}/enterprise-attack/enterprise-attack-{version}.json"


def _download(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {url} ...", file=sys.stderr)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url) as resp, tmp.open("wb") as fh:  # noqa: S310 - fixed https host
        while chunk := resp.read(1 << 20):
            fh.write(chunk)
    tmp.replace(dest)
    return dest


def fetch(url: str = STIX_URL) -> Path:
    """Download ``url`` to the bundle cache, reusing a previous download."""
    dest = CACHE_DIR / url.rsplit("/", 1)[-1]
    if dest.is_file() and dest.stat().st_size > MIN_BUNDLE_BYTES:
        print(f"using cached {dest} ({dest.stat().st_size / 1e6:.0f}MB)", file=sys.stderr)
        return dest
    return _download(url, dest)


def fetch_index() -> dict:
    """The ATT&CK release catalogue (``index.json``), fetched fresh each run.

    Small enough (a few KB) that caching it would only risk answering with a
    stale view of which releases exist.
    """
    with urllib.request.urlopen(INDEX_URL) as resp:  # noqa: S310 - fixed https host
        return json.loads(resp.read().decode("utf-8"))


def _version_key(version: str) -> tuple:
    try:
        return (0, tuple(int(p) for p in str(version).split(".")))
    except ValueError:
        return (1, str(version))


def list_versions(collection: str = COLLECTION) -> list[dict]:
    """Every published release of ``collection``, newest first.

    Each entry is ``{"version", "url", "modified"}`` straight from index.json.
    """
    index = fetch_index()
    for entry in index.get("collections") or []:
        if entry.get("name") == collection:
            versions = list(entry.get("versions") or [])
            versions.sort(key=lambda v: _version_key(v.get("version", "")), reverse=True)
            return versions
    raise SystemExit(f"collection {collection!r} not found in {INDEX_URL}")


def resolve_version(version: str, collection: str = COLLECTION) -> str:
    """Validate a requested version against index.json, or fail with the list.

    ``"latest"`` resolves to the newest published release.
    """
    published = list_versions(collection)
    names = [str(v["version"]) for v in published]
    if version in ("", "latest"):
        return names[0]
    if version not in names:
        raise SystemExit(f"ATT&CK {version} is not published. Available: {', '.join(names)}")
    return version


def release_date(version: str, collection: str = COLLECTION) -> str:
    for entry in list_versions(collection):
        if str(entry.get("version")) == version:
            return str(entry.get("modified") or entry.get("released") or "")
    return ""


def sha256(path: Path) -> str:
    """Content hash of a bundle, recorded in framework_versions as provenance."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()
