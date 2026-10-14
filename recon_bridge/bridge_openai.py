"""ChatGPT / OpenAI bridge.

Lets an OpenAI-compatible model (ChatGPT via the API, or anything that speaks
the same function-calling format) drive the exact same recon tools as the MCP
server. The tool schemas are generated from the shared registry, so there is
only one place to add a capability.

This is an agentic loop: the model is offered the tools, you pass a natural-
language instruction, and the loop executes whatever tools the model calls —
always through the scope/audit/rate-limit backbone — feeding results back until
the model produces a final answer.

Two ways to reach this toolkit from the OpenAI side:
  1. This bridge — programmatic, works with the API and any OpenAI-compatible
     endpoint. Good for scripts and headless runs.
  2. ChatGPT's own MCP connector support (Developer Mode) — point it straight
     at the MCP server from server.py; no bridge needed. See the README.

Run::

    export OPENAI_API_KEY=sk-...
    python -m recon_bridge.bridge_openai "Fingerprint https://app.example.com and list its missing security headers"
"""

from __future__ import annotations

import json
import sys

from .context import Context, ToolRefused
from .tools import BY_NAME, REGISTRY

_SYSTEM = (
    "You are a reconnaissance assistant operating under a strict authorization "
    "scope. You may only gather information using the provided tools. If a tool "
    "returns a message starting with 'REFUSED:', the target is out of scope or "
    "rate-limited — do not retry it; explain the refusal. Summarize findings "
    "clearly and never fabricate results you did not get from a tool."
)


def _openai_tool_schemas() -> list[dict]:
    """Translate the shared registry into OpenAI tool definitions."""
    return [
        {
            "type": "function",
            "function": {
                "name": spec.name,
                "description": spec.description,
                "parameters": spec.parameters,
            },
        }
        for spec in REGISTRY
    ]


def _dispatch(ctx: Context, name: str, arguments: dict) -> str:
    spec = BY_NAME.get(name)
    if spec is None:
        return f"Unknown tool: {name}"
    try:
        result = spec.fn(ctx, **arguments)
    except ToolRefused as exc:
        return f"REFUSED: {exc}"
    except TypeError as exc:
        return f"Bad arguments for {name}: {exc}"
    except Exception as exc:  # noqa: BLE001
        return f"Error running {name}: {exc}"
    return json.dumps(result, ensure_ascii=False)


def run(instruction: str, model: str = "gpt-4o", max_steps: int = 12) -> str:
    try:
        from openai import OpenAI
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "The OpenAI bridge needs the openai package. Install it with:\n"
            "    pip install 'recon-bridge[openai]'   (or: pip install openai)"
        ) from exc

    ctx = Context.bootstrap()
    client = OpenAI()
    tools = _openai_tool_schemas()
    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": instruction},
    ]

    for _ in range(max_steps):
        resp = client.chat.completions.create(model=model, messages=messages, tools=tools)
        msg = resp.choices[0].message

        if not msg.tool_calls:
            return msg.content or "(no content returned)"

        # Record the assistant turn that requested the tools.
        messages.append(
            {
                "role": "assistant",
                "content": msg.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in msg.tool_calls
                ],
            }
        )

        # Execute each requested tool through the backbone.
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            output = _dispatch(ctx, tc.function.name, args)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": output})

    return "Reached the step limit without a final answer; inspect the audit log."


def main() -> None:
    if len(sys.argv) < 2:
        print('Usage: python -m recon_bridge.bridge_openai "your instruction"')
        raise SystemExit(2)
    print(run(" ".join(sys.argv[1:])))


if __name__ == "__main__":
    main()
