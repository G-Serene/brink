"""OpenAI Agents SDK integration for the brink sandbox.

Usage:
    import asyncio, os
    os.environ["OPENAI_API_KEY"] = "sk-..."
    from brink_agent import run_agent
    asyncio.run(run_agent("Write Python that sums 1..100"))
"""

from __future__ import annotations

import asyncio
import os
import sys

from agents import Agent, Runner, function_tool

from ._runner import BrinkRunner, RunResult

# ── Language configurations ───────────────────────────────────────────────────

# interpreter path → (ro_mounts needed, extra env, extra argv flags)
_LANG_CONFIG: dict[str, dict] = {
    "python": {
        "interpreter": "/usr/bin/python3",
        "ext": "py",
        "ro_mounts": [("/usr", "/usr"), ("/lib", "/lib"), ("/lib64", "/lib64")],
        "env": {"PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        "argv_prefix": [],
    },
    "bash": {
        "interpreter": "/bin/bash",
        "ext": "sh",
        "ro_mounts": [("/bin", "/bin"), ("/usr", "/usr"), ("/lib", "/lib"), ("/lib64", "/lib64")],
        "env": {},
        "argv_prefix": [],
    },
    "sh": {
        "interpreter": "/bin/sh",
        "ext": "sh",
        "ro_mounts": [("/bin", "/bin"), ("/usr", "/usr"), ("/lib", "/lib"), ("/lib64", "/lib64")],
        "env": {},
        "argv_prefix": [],
    },
    "node": {
        "interpreter": "/usr/bin/node",
        "ext": "js",
        "ro_mounts": [("/usr", "/usr"), ("/lib", "/lib"), ("/lib64", "/lib64")],
        "env": {"NODE_ENV": "production"},
        "argv_prefix": [],
    },
    "ruby": {
        "interpreter": "/usr/bin/ruby",
        "ext": "rb",
        "ro_mounts": [("/usr", "/usr"), ("/lib", "/lib"), ("/lib64", "/lib64")],
        "env": {},
        "argv_prefix": [],
    },
    "java": {
        # Requires OpenJDK installed on the host and mounted.
        # Uses SerialGC to minimise syscall surface (G1/ZGC need extra syscalls).
        "interpreter": "/usr/bin/java",
        "ext": "java",          # compiled first — see _run_java()
        "ro_mounts": [("/usr", "/usr"), ("/lib", "/lib"), ("/lib64", "/lib64"), ("/etc/java-21-openjdk", "/etc/java-21-openjdk")],
        "env": {"JAVA_TOOL_OPTIONS": "-XX:+UseSerialGC -Xmx96m"},
        "argv_prefix": [],
    },
}


# ── Default runner ────────────────────────────────────────────────────────────

def _default_runner() -> BrinkRunner:
    return BrinkRunner(
        cgroup_parent=os.environ.get(
            "BRINK_CGROUP_PARENT",
            "/sys/fs/cgroup/user.slice/user-0.slice",
        ),
        memory_mb=int(os.environ.get("BRINK_MEMORY_MB", "128")),
        cpu_pct=int(os.environ.get("BRINK_CPU_PCT", "50")),
        timeout_secs=int(os.environ.get("BRINK_TIMEOUT_SECS", "15")),
    )


# ── Core execution helper ─────────────────────────────────────────────────────

def _execute(
    runner: BrinkRunner,
    language: str,
    code: str,
    context_files: dict[str, str] | None = None,
) -> str:
    """Write code + context files to the workspace and run inside the sandbox."""
    lang = language.lower().strip()
    if lang not in _LANG_CONFIG:
        supported = ", ".join(sorted(_LANG_CONFIG))
        return f"[error] unsupported language '{lang}'. Supported: {supported}"

    cfg = _LANG_CONFIG[lang]

    if lang == "java":
        return _run_java(runner, code, context_files or {})

    script_name = f"script.{cfg['ext']}"

    try:
        result: RunResult = runner.run_script(
            interpreter=cfg["interpreter"],
            code=code,
            script_name=script_name,
            env=cfg["env"],
            ro_mounts=cfg["ro_mounts"],
            context_files=context_files,
        )
    except Exception as e:
        return f"[error] sandbox launch failed: {e}"

    return _format_result(result)


def _run_java(runner: BrinkRunner, code: str, context_files: dict[str, str]) -> str:
    """Compile Java in the workspace, then run it inside the sandbox."""
    import tempfile, subprocess, shutil
    from pathlib import Path

    cfg = _LANG_CONFIG["java"]

    # We need javac on the host to compile; sandbox only runs the JVM.
    javac = shutil.which("javac")
    if not javac:
        return "[error] javac not found on host — install openjdk to run Java"

    # Extract public class name from code (simplistic but works for agent-written code).
    import re
    match = re.search(r"public\s+class\s+(\w+)", code)
    class_name = match.group(1) if match else "Main"

    with tempfile.TemporaryDirectory(prefix="brink-java-") as ws:
        ws_path = Path(ws)
        src = ws_path / f"{class_name}.java"
        src.write_text(code, encoding="utf-8")

        # Write context files to workspace
        for name, content in context_files.items():
            (ws_path / name).write_text(content, encoding="utf-8")

        # Compile on the host
        result = subprocess.run(
            [javac, str(src)],
            capture_output=True, text=True, cwd=str(ws_path),
        )
        if result.returncode != 0:
            return f"[compile error]\n{result.stderr.strip()}"

        # Run compiled class inside sandbox
        try:
            run_result = runner.run(
                argv=[cfg["interpreter"]] + ["-XX:+UseSerialGC", "-Xmx96m", class_name],
                env={"CLASSPATH": "/workspace"},
                workspace=ws_path,
                ro_mounts=cfg["ro_mounts"],
            )
        except Exception as e:
            return f"[error] sandbox launch failed: {e}"

        return _format_result(run_result)


def _format_result(result: RunResult) -> str:
    parts: list[str] = []
    if result.stdout:
        parts.append(f"stdout:\n{result.stdout.rstrip()}")
    if result.stderr:
        parts.append(f"stderr:\n{result.stderr.rstrip()}")
    parts.append(
        f"\n[{result.termination} | {result.wall_time_ms}ms | "
        f"{result.peak_memory_bytes // 1024} KiB peak]"
    )
    if not result.success and not result.stdout and not result.stderr:
        parts.insert(0, f"(no output — terminated: {result.termination})")
    return "\n".join(parts)


# ── Tools ─────────────────────────────────────────────────────────────────────

def _make_tools(runner: BrinkRunner):
    @function_tool
    def run_code(language: str, code: str) -> str:
        """Run code in a secure Linux sandbox and return its output.

        Supported languages: python, bash, sh, node, ruby, java.

        The sandbox has no network access, 128 MiB RAM, and a 15-second
        wall-clock timeout. The /workspace directory is writable.

        Args:
            language: One of: python, bash, sh, node, ruby, java.
            code:     Complete source code to execute.
        """
        return _execute(runner, language, code)

    @function_tool
    def run_code_with_files(
        language: str,
        code: str,
        context_files: dict[str, str],
    ) -> str:
        """Run code that needs to read input files, inside a secure sandbox.

        All files in context_files are written to /workspace/<filename>
        before the code runs. The code can open them with open('/workspace/<filename>').
        Any files the code writes to /workspace/ are discarded after the run.

        Args:
            language:      One of: python, bash, sh, node, ruby, java.
            code:          Complete source code to execute.
            context_files: Mapping of filename → file content (text).
                           Example: {"data.csv": "a,b\\n1,2\\n3,4"}
        """
        return _execute(runner, language, code, context_files)

    return [run_code, run_code_with_files]


# ── Public API ────────────────────────────────────────────────────────────────

def make_agent(runner: BrinkRunner | None = None) -> Agent:
    """Return an Agent wired up to brink sandbox tools."""
    r = runner or _default_runner()
    return Agent(
        name="Brink Sandbox Agent",
        instructions=(
            "You are a coding assistant that executes code safely inside a Linux sandbox. "
            "You can run Python, Bash, Node.js, Ruby, and Java. "
            "Use run_code for plain code. "
            "Use run_code_with_files when the code needs to read input data "
            "(CSV, JSON, text files, etc.) — pass the file contents as context_files. "
            "Always show the code you ran. "
            "If the code fails, read the error, fix the code, and retry. "
            "The sandbox has no internet access."
        ),
        tools=_make_tools(r),
    )


async def run_agent(
    prompt: str,
    *,
    runner: BrinkRunner | None = None,
    stream: bool = False,
) -> str:
    """Run the sandbox agent on *prompt* and return the final output."""
    agent = make_agent(runner)
    result = await Runner.run(agent, prompt)
    return result.final_output


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m brink_agent.agent '<prompt>'")
        sys.exit(1)
    prompt = " ".join(sys.argv[1:])
    print(f"Prompt: {prompt}\n")
    print(asyncio.run(run_agent(prompt)))
