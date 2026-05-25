"""
brink + OpenAI Agents SDK — multi-language demo with file context

Run on the Linux VM:
    export OPENAI_API_KEY=sk-...
    export BRINK_BIN=~/sandbox-core/target/release/brink-run
    export BRINK_CGROUP_PARENT=/sys/fs/cgroup/user.slice/user-0.slice
    python examples/agent_demo.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agents import Runner
from brink_agent import BrinkRunner
from brink_agent.agent import make_agent

runner = BrinkRunner(
    cgroup_parent=os.environ.get(
        "BRINK_CGROUP_PARENT",
        "/sys/fs/cgroup/user.slice/user-0.slice",
    ),
    memory_mb=128,
    cpu_pct=50,
    timeout_secs=15,
    extra_ro_mounts=[
        ("/bin",  "/bin"),
        ("/lib",  "/lib"),
        ("/lib64", "/lib64"),
        ("/usr",  "/usr"),
    ],
)

agent = make_agent(runner)

PROMPTS = [
    # Python — plain code
    "Write Python that prints the first 10 Fibonacci numbers",

    # Bash
    "Use bash to count the number of files in /usr/bin and print the result",

    # Python with file context — agent should use run_code_with_files
    (
        "I have a CSV file with columns name,score. "
        "Calculate the average score and print it. "
        "The file content is:\n"
        "name,score\nAlice,85\nBob,92\nCarol,78\nDave,95\nEve,88"
    ),

    # Error handling — seccomp violation
    "Write Python that tries to open a raw TCP socket to 8.8.8.8 and show what happens",

    # Ruby
    "Write a Ruby one-liner that prints the squares of 1..10",
]


async def main() -> None:
    for prompt in PROMPTS:
        print(f"\n{'='*60}")
        print(f"Prompt: {prompt[:80]}{'...' if len(prompt) > 80 else ''}")
        print("=" * 60)
        result = await Runner.run(agent, prompt)
        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
