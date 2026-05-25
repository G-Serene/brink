"""OpenAI Agents SDK integration for the brink sandbox.

Usage:
    import asyncio
    from brink_agent import run_agent

    asyncio.run(run_agent("Write a Python script that prints the first 10 Fibonacci numbers"))
"""

from __future__ import annotations

import asyncio
import os
import sys

from agents import Agent, Runner, function_tool

from ._runner import BrinkRunner, RunResult

# ── Default runner (configurable via env vars) ────────────────────────────────

def _default_runner() -> BrinkRunner:
    return BrinkRunner(
        cgroup_parent=os.environ.get(
            "BRINK_CGROUP_PARENT",
            "/sys/fs/cgroup/user.slice/user-0.slice",
        ),
        memory_mb=int(os.environ.get("BRINK_MEMORY_MB", "128")),
        cpu_pct=int(os.environ.get("BRINK_CPU_PCT", "50")),
        timeout_secs=int(os.environ.get("BRINK_TIMEOUT_SECS", "10")),
        # Standard mounts so Python and common libs are visible inside sandbox
        extra_ro_mounts=[
            ("/usr", "/usr"),
            ("/lib", "/lib"),
            ("/lib64", "/lib64"),
        ],
    )


# ── Tools ────────────────────────────────────────────────────────────────────

def _make_tools(runner: BrinkRunner):
    @function_tool
    def run_python(code: str) -> str:
        """Execute Python 3 code inside a secure sandbox and return its output.

        The code runs with no network access, limited memory (128 MiB), and a
        10-second wall-clock timeout. The /workspace directory is writable;
        everything else is read-only or unavailable.

        Args:
            code: Complete Python 3 source code to execute.
        """
        result: RunResult = runner.run_script(
            interpreter="/usr/bin/python3",
            code=code,
            env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"},
        )
        return _format_result(result)

    @function_tool
    def run_bash(script: str) -> str:
        """Execute a bash script inside a secure sandbox and return its output.

        Same restrictions as run_python: no network, 128 MiB RAM, 10s timeout.

        Args:
            script: Bash script source to execute.
        """
        result: RunResult = runner.run_script(
            interpreter="/bin/bash",
            code=script,
        )
        return _format_result(result)

    return [run_python, run_bash]


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
        parts.insert(0, f"(no output — process ended with: {result.termination})")
    return "\n".join(parts)


# ── Public API ───────────────────────────────────────────────────────────────

def make_agent(runner: BrinkRunner | None = None) -> Agent:
    """Return an Agent wired up to the brink sandbox tools.

    Pass a custom *runner* to override cgroup path, memory limits, etc.
    """
    r = runner or _default_runner()
    return Agent(
        name="Brink Sandbox Agent",
        instructions=(
            "You are a coding assistant that can run Python or Bash code safely "
            "inside a Linux sandbox. When the user asks you to compute something, "
            "write and run code to produce an exact answer. "
            "Always show the code you ran. "
            "If the code fails, diagnose the error, fix it, and retry."
        ),
        tools=_make_tools(r),
    )


async def run_agent(
    prompt: str,
    *,
    runner: BrinkRunner | None = None,
    stream: bool = True,
) -> str:
    """Run the sandbox agent on *prompt* and return the final output."""
    agent = make_agent(runner)

    if stream:
        result = Runner.run_streamed(agent, prompt)
        async for event in result.stream_events():
            # Print tool-call activity so the user can see code being executed
            if event.type == "raw_response_event":
                pass  # handled by final_output below
        return (await result.get_final_result()).final_output
    else:
        result = await Runner.run(agent, prompt)
        return result.final_output


# ── CLI entrypoint ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m brink_agent.agent '<prompt>'")
        sys.exit(1)

    prompt = " ".join(sys.argv[1:])
    print(f"Prompt: {prompt}\n")

    answer = asyncio.run(run_agent(prompt, stream=False))
    print(answer)
