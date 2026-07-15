"""Thin, safe wrapper around the hayabusa CLI binary.

Every MCP tool ultimately funnels through :func:`run`, which is the single
place that spawns a subprocess. Keeping it centralized means path validation,
timeouts, and error shaping are enforced uniformly and are easy to test with a
fake binary.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import CONFIG, ROOT


class HayabusaError(RuntimeError):
    """Raised when hayabusa cannot be run or exits non-zero."""


@dataclass
class Result:
    """Outcome of a single hayabusa invocation."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    def as_dict(self) -> dict:
        return {
            "command": " ".join(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def resolve_binary() -> str:
    """Return a path to the hayabusa binary or raise.

    A relative ``HAYABUSA_PATH`` is also tried against the repo root, because an
    MCP client starts the server with a working directory of its own choosing —
    the conventional ``./hayabusa/hayabusa`` must not depend on being launched
    from the project directory.
    """
    candidates = [CONFIG.binary]
    if not Path(CONFIG.binary).is_absolute():
        candidates.append(str(ROOT / CONFIG.binary))

    for candidate in candidates:
        found = shutil.which(candidate) or (candidate if Path(candidate).is_file() else None)
        if found:
            return found

    tried = ", ".join(repr(c) for c in candidates)
    raise HayabusaError(
        f"hayabusa binary not found (HAYABUSA_PATH={CONFIG.binary!r}; tried {tried}). "
        "Run 'make install-hayabusa', or install it from "
        "https://github.com/Yamato-Security/hayabusa/releases and set HAYABUSA_PATH."
    )


def safe_path(raw: str, *, must_exist: bool = True) -> Path:
    """Resolve ``raw`` and, if a workdir sandbox is configured, confine it there.

    ``must_exist`` is False for output paths that hayabusa will create.
    """
    path = Path(raw).expanduser().resolve()

    if CONFIG.workdir:
        root = Path(CONFIG.workdir).expanduser().resolve()
        if root not in path.parents and path != root:
            raise HayabusaError(f"path {path} is outside the allowed workdir {root}")

    if must_exist and not path.exists():
        raise HayabusaError(f"path does not exist: {path}")
    return path


def input_flag(path: Path) -> list[str]:
    """Hayabusa takes ``-d`` for a directory of evtx and ``-f`` for one file."""
    return ["-d", str(path)] if path.is_dir() else ["-f", str(path)]


def run(args: list[str], *, timeout: float | None = None) -> Result:
    """Execute ``hayabusa <args>`` and return a structured :class:`Result`.

    Raises :class:`HayabusaError` on a missing binary, timeout, or non-zero exit.
    """
    binary = resolve_binary()
    command = [binary, *args]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout if timeout is not None else CONFIG.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HayabusaError(
            f"hayabusa timed out after {exc.timeout:.0f}s: {' '.join(command)}"
        ) from exc

    result = Result(command, proc.returncode, proc.stdout, proc.stderr)
    if proc.returncode != 0:
        raise HayabusaError(
            f"hayabusa exited {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return result
