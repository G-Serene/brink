"""
brink + OpenAI Agents SDK — end-to-end demo

Run on the Hetzner VM (or any Ubuntu 24.04 machine with kernel 6.8+, cgroup v2):

    export OPENAI_API_KEY=sk-...
    export BRINK_BIN=/path/to/target/release/brink-run      # or put it on PATH
    export BRINK_CGROUP_PARENT=/sys/fs/cgroup/user.slice/user-0.slice  # root
    python examples/agent_demo.py

The agent will write code, execute it inside the brink sandbox, and return
the output — all in one conversation turn.
"""

import asyncio
import os
import sys

# Allow running from the repo root without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agents import Runner
from brink_agent import BrinkRunner
from brink_agent.agent import make_agent

# ── Configure the sandbox runner ─────────────────────────────────────────────

runner = BrinkRunner(
    # cgroup v2 delegation root. Adjust for your setup:
    #   root on Hetzner/bare-metal : /sys/fs/cgroup/user.slice/user-0.slice
    #   non-root with systemd      : /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice
    cgroup_parent=os.environ.get(
        "BRINK_CGROUP_PARENT",
        "/sys/fs/cgroup/user.slice/user-0.slice",
    ),
    memory_mb=128,
    cpu_pct=50,
    timeout_secs=10,
    # Make standard system paths visible inside the sandbox rootfs.
    extra_ro_mounts=[
        ("/bin",  "/bin"),
        ("/lib",  "/lib"),
        ("/lib64", "/lib64"),
        ("/usr",  "/usr"),
    ],
)

agent = make_agent(runner)

# ── Run a few demo prompts ────────────────────────────────────────────────────

PROMPTS = [
    "Write a Python script that prints the first 10 Fibonacci numbers and run it",
    "Use bash to count how many files are in /usr/bin and show me the top 5 by name",
    "Write Python code that raises a ZeroDivisionError and show me what happens",
]


async def main() -> None:
    for prompt in PROMPTS:
        print(f"\n{'='*60}")
        print(f"Prompt: {prompt}")
        print("=" * 60)
        result = await Runner.run(agent, prompt)
        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
