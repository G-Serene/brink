"""Subprocess wrapper around the brink-run binary."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


def _find_binary() -> Path:
    """Locate brink-run in order of preference:
    1. $BRINK_BIN env var
    2. On PATH
    3. ../target/release/brink-run  (repo checkout, built with cargo build --release)
    """
    if env := os.environ.get("BRINK_BIN"):
        p = Path(env)
        if p.is_file():
            return p
        raise FileNotFoundError(f"BRINK_BIN={env!r} does not exist")

    if which := shutil.which("brink-run"):
        return Path(which)

    # Repo layout: brink_agent/ sits next to Cargo.toml
    repo_bin = Path(__file__).parent.parent / "target" / "release" / "brink-run"
    if repo_bin.is_file():
        return repo_bin

    raise FileNotFoundError(
        "brink-run binary not found. Build it with:\n"
        "  cargo build --release --bin brink-run\n"
        "or set the BRINK_BIN environment variable."
    )


@dataclass
class RunResult:
    exit_status: int
    stdout: str
    stderr: str
    wall_time_ms: int
    peak_memory_bytes: int
    cpu_time_us: int
    termination: str
    seccomp_violation: int | None

    @property
    def success(self) -> bool:
        return self.exit_status == 0 and self.termination.startswith("exited")

    def summary(self) -> str:
        lines = [
            f"termination : {self.termination}",
            f"exit_status : {self.exit_status}",
            f"wall_time   : {self.wall_time_ms} ms",
            f"cpu_time    : {self.cpu_time_us} µs",
            f"peak_memory : {self.peak_memory_bytes // 1024} KiB",
        ]
        if self.stdout:
            lines.append(f"stdout:\n{self.stdout.rstrip()}")
        if self.stderr:
            lines.append(f"stderr:\n{self.stderr.rstrip()}")
        return "\n".join(lines)


class BrinkRunner:
    """Runs arbitrary commands inside the brink sandbox."""

    def __init__(
        self,
        *,
        cgroup_parent: str = "/sys/fs/cgroup/user.slice/user-0.slice",
        memory_mb: int = 128,
        cpu_pct: int = 50,
        timeout_secs: int = 10,
        pids_max: int = 64,
        extra_ro_mounts: list[tuple[str, str]] | None = None,
        binary: str | Path | None = None,
    ) -> None:
        self._bin = Path(binary) if binary else _find_binary()
        self._cgroup_parent = cgroup_parent
        self._memory_mb = memory_mb
        self._cpu_pct = cpu_pct
        self._timeout_secs = timeout_secs
        self._pids_max = pids_max
        self._extra_ro_mounts: list[tuple[str, str]] = extra_ro_mounts or []

    def run(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        workspace: str | Path | None = None,
    ) -> RunResult:
        """Run *argv* in the sandbox and return a RunResult."""
        with tempfile.TemporaryDirectory(prefix="brink-ws-") as tmp:
            ws = str(workspace) if workspace else tmp
            job = {
                "argv":             argv,
                "env":              list((env or {}).items()),
                "workspace":        ws,
                "cgroup_parent":    self._cgroup_parent,
                "memory_mb":        self._memory_mb,
                "cpu_pct":          self._cpu_pct,
                "timeout_secs":     self._timeout_secs,
                "pids_max":         self._pids_max,
                "extra_ro_mounts":  self._extra_ro_mounts,
            }
            proc = subprocess.run(
                [str(self._bin)],
                input=json.dumps(job),
                capture_output=True,
                text=True,
                timeout=self._timeout_secs + 5,  # outer guard
            )

        if proc.returncode != 0:
            raise RuntimeError(
                f"brink-run exited {proc.returncode}: {proc.stderr.strip()}"
            )

        data = json.loads(proc.stdout)
        if not data.get("ok"):
            raise RuntimeError(f"sandbox error: {data.get('error', proc.stdout)}")

        return RunResult(
            exit_status       = data["exit_status"],
            stdout            = data["stdout"],
            stderr            = data["stderr"],
            wall_time_ms      = data["wall_time_ms"],
            peak_memory_bytes = data["peak_memory_bytes"],
            cpu_time_us       = data["cpu_time_us"],
            termination       = data["termination"],
            seccomp_violation = data.get("seccomp_violation"),
        )

    def run_script(
        self,
        interpreter: str,
        code: str,
        *,
        env: dict[str, str] | None = None,
        ro_mounts: list[tuple[str, str]] | None = None,
    ) -> RunResult:
        """Write *code* to /workspace/script and run it via *interpreter*.

        interpreter: absolute path to the interpreter inside the sandbox,
                     e.g. '/usr/bin/python3' or '/usr/bin/node'.
        ro_mounts:   extra read-only bind mounts for this call only.
        """
        with tempfile.TemporaryDirectory(prefix="brink-ws-") as ws_dir:
            ws = Path(ws_dir)
            (ws / "script").write_text(code, encoding="utf-8")

            # Merge per-call mounts with instance defaults
            mounts = list(self._extra_ro_mounts)
            if ro_mounts:
                mounts.extend(ro_mounts)

            job = {
                "argv":             [interpreter, "/workspace/script"],
                "env":              list((env or {}).items()),
                "workspace":        str(ws),
                "cgroup_parent":    self._cgroup_parent,
                "memory_mb":        self._memory_mb,
                "cpu_pct":          self._cpu_pct,
                "timeout_secs":     self._timeout_secs,
                "pids_max":         self._pids_max,
                "extra_ro_mounts":  mounts,
            }
            proc = subprocess.run(
                [str(self._bin)],
                input=json.dumps(job),
                capture_output=True,
                text=True,
                timeout=self._timeout_secs + 5,
            )

        if proc.returncode != 0:
            raise RuntimeError(
                f"brink-run exited {proc.returncode}: {proc.stderr.strip()}"
            )

        data = json.loads(proc.stdout)
        if not data.get("ok"):
            raise RuntimeError(f"sandbox error: {data.get('error', proc.stdout)}")

        return RunResult(
            exit_status       = data["exit_status"],
            stdout            = data["stdout"],
            stderr            = data["stderr"],
            wall_time_ms      = data["wall_time_ms"],
            peak_memory_bytes = data["peak_memory_bytes"],
            cpu_time_us       = data["cpu_time_us"],
            termination       = data["termination"],
            seccomp_violation = data.get("seccomp_violation"),
        )
