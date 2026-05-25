"""Subprocess wrapper around the brink-run binary."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


def _find_binary() -> Path:
    """Locate brink-run:
    1. $BRINK_BIN env var
    2. On PATH
    3. ../target/release/brink-run  (repo checkout)
    """
    if env := os.environ.get("BRINK_BIN"):
        p = Path(env)
        if p.is_file():
            return p
        raise FileNotFoundError(f"BRINK_BIN={env!r} does not exist")
    if which := shutil.which("brink-run"):
        return Path(which)
    repo_bin = Path(__file__).parent.parent / "target" / "release" / "brink-run"
    if repo_bin.is_file():
        return repo_bin
    raise FileNotFoundError(
        "brink-run not found. Build it with:\n"
        "  cargo build --release --bin brink-run\n"
        "or set BRINK_BIN."
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


def _call_binary(binary: Path, job: dict, timeout_secs: int) -> RunResult:
    """Serialise *job* to JSON, call brink-run, parse the result."""
    proc = subprocess.run(
        [str(binary)],
        input=json.dumps(job),
        capture_output=True,
        text=True,
        timeout=timeout_secs + 5,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"brink-run exited {proc.returncode}: {proc.stderr.strip()}")
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


class BrinkRunner:
    """Runs commands inside the brink sandbox."""

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
        ro_mounts: list[tuple[str, str]] | None = None,
    ) -> RunResult:
        """Run *argv* directly inside the sandbox.

        workspace: host-side directory mounted at /workspace (rw).
                   If None, a temp dir is created and deleted after the run.
        ro_mounts: extra read-only bind mounts for this call only,
                   merged with the instance-level mounts.
        """
        mounts = list(self._extra_ro_mounts)
        if ro_mounts:
            mounts.extend(ro_mounts)

        if workspace is not None:
            ws_str = str(workspace)
            job = self._build_job(argv, env, ws_str, mounts)
            return _call_binary(self._bin, job, self._timeout_secs)

        with tempfile.TemporaryDirectory(prefix="brink-ws-") as tmp:
            job = self._build_job(argv, env, tmp, mounts)
            return _call_binary(self._bin, job, self._timeout_secs)

    def run_script(
        self,
        interpreter: str,
        code: str,
        *,
        script_name: str = "script",
        env: dict[str, str] | None = None,
        ro_mounts: list[tuple[str, str]] | None = None,
        context_files: dict[str, str] | None = None,
    ) -> RunResult:
        """Write *code* to /workspace/<script_name> and run via *interpreter*.

        context_files: optional mapping of filename → text content.
                       Each file is written to /workspace/<filename> before
                       the interpreter starts, so the code can open them with
                       open('/workspace/<filename>').

        interpreter: absolute path visible inside the sandbox,
                     e.g. '/usr/bin/python3', '/bin/bash', '/usr/bin/node'.
        """
        mounts = list(self._extra_ro_mounts)
        if ro_mounts:
            mounts.extend(ro_mounts)

        with tempfile.TemporaryDirectory(prefix="brink-ws-") as ws_dir:
            ws = Path(ws_dir)

            # Write the main script
            (ws / script_name).write_text(code, encoding="utf-8")

            # Write any context files the code needs to read
            if context_files:
                for filename, content in context_files.items():
                    target = ws / filename
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8")

            job = self._build_job(
                [interpreter, f"/workspace/{script_name}"],
                env,
                str(ws),
                mounts,
            )
            return _call_binary(self._bin, job, self._timeout_secs)

    def _build_job(
        self,
        argv: list[str],
        env: dict[str, str] | None,
        workspace: str,
        mounts: list[tuple[str, str]],
    ) -> dict:
        return {
            "argv":            argv,
            "env":             list((env or {}).items()),
            "workspace":       workspace,
            "cgroup_parent":   self._cgroup_parent,
            "memory_mb":       self._memory_mb,
            "cpu_pct":         self._cpu_pct,
            "timeout_secs":    self._timeout_secs,
            "pids_max":        self._pids_max,
            "extra_ro_mounts": mounts,
        }
