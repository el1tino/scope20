# recon-bridge

An **authorization-aware reconnaissance toolkit** exposed over the Model Context
Protocol (MCP), so any LLM — Claude Code, Claude Desktop, ChatGPT, or an
OpenAI-compatible model — can drive the same recon tools through the same safety
backbone.

It is built for **authorized engagements**: every tool refuses any target that
is not explicitly listed in an engagement scope file, enforces a per-port
allowlist, honours an engagement expiry date, rate-limits itself, and writes an
append-only audit trail of everything it does — including every refusal.

> ⚠️ Use this only against systems you own or have **written authorization** to
> test. Unauthorized scanning is illegal in most jurisdictions. The scope file
> is where you record that authorization; the toolkit will not act outside it.

---

## Why this design

Three ideas do most of the work:

1. **One registry, many front-ends.** Every capability is a plain function
   listed once in `recon_bridge/tools/__init__.py`. The MCP server and the
   ChatGPT bridge both read that registry, so "works with ChatGPT *and* Claude"
   costs no duplicated code — and a new tool is one entry, wired to both at once.

2. **The safety backbone is the only path to a target.** No tool talks to the
   network directly. Each one calls `ctx.guard(...)`, which enforces scope,
   checks the rate limit, and opens an audit record before a single packet
   leaves the host. Get the boundary right once, and every present and future
   tool inherits it.

3. **A single engagement task tree carries state across phases.** Every recon
   tool feeds one resumable structure — assets, findings, a phased to-do — so
   each phase's results seed the next, and any model (or you) can inspect it,
   ask what to do next, and export a report. This is lifted from
   [PentestGPT](https://github.com/GreyDGL/PentestGPT)'s *Pentesting Task Tree*,
   but kept deterministic and model-agnostic: the state layer needs no LLM, and
   suggestions are always filtered back through scope (see
   [Credits](#credits)).

---

## What it can do

**Recon tools** — each one acts on the network, always inside scope:

| Tool | What it does | Impact |
|------|--------------|--------|
| `dns_lookup` | Resolve A/AAAA/MX/NS/TXT/CNAME/SOA for an in-scope host | Passive |
| `subdomain_enum` | Discover subdomains from Certificate Transparency logs (crt.sh); returns only in-scope names | Passive |
| `port_scan` | TCP port/service scan — `nmap -sV` when installed, else a built-in Python TCP-connect scan | Active |
| `http_fingerprint` | One GET to an in-scope URL: status, server banner, title, security-header posture, redirects | Low |

**Engagement controls** — the task-tree operators (inspired by PentestGPT's
`todo` / `next` / `discuss`); these read and advance local state only and touch
no network:

| Tool | What it does |
|------|--------------|
| `explain_scope` | Report exactly what the engagement authorizes (`discuss`) |
| `engagement_status` | Show discovered assets, findings by severity, and the pending to-do (`todo`) |
| `next_steps` | Suggest the next **in-scope** recon actions from current findings (`next`) |
| `record_finding` | Jot a manual observation into the tree |
| `export_report` | Render the tree as a Markdown recon report |

`nmap` is optional: if it is not installed, `port_scan` falls back to a pure-Python
connect scan of a common-ports list, so the toolkit runs anywhere. Install `nmap`
on your engagement machine for service/version detection.

---

## Install

```bash
git clone <your-repo> recon-bridge && cd recon-bridge
python3 -m venv .venv && source .venv/bin/activate
pip install -e .              # core
pip install -e '.[openai]'    # + the ChatGPT bridge
```

Then create your config:

```bash
cp .env.example .env
cp examples/scope.example.yaml scope.yaml   # then EDIT scope.yaml for your engagement
python -m recon_bridge.server --check        # validates scope, prints the summary
```

`--check` is your pre-flight: it loads the scope file, prints what is authorized,
and exits. If it errors, the server will not start either — misconfiguration
fails loudly, by design.

---

## The scope file — your authorization boundary

`scope.yaml` is the written edge of the engagement. The toolkit treats it as
ground truth and acts on nothing outside it. See
`examples/scope.example.yaml` for the full shape. The essentials:

- `allow.hosts` / `allow.cidrs` — what is in scope. Wildcards (`*.acme.example`)
  match one label.
- `deny.*` — always wins over allow; carve out anything you must not touch.
- `ports` — optional; if present, `port_scan` refuses ports outside the list.
- `expires` — after this date, every tool refuses until you renew authorization.

Protected ranges (loopback, RFC1918 private space, link-local, and the cloud
metadata endpoint) are refused **even if** a broad rule like `0.0.0.0/0` would
otherwise allow them. Opting one back in requires a *specific* allow CIDR that is
a subnet of the protected range — a deliberate carve-out, never an accident.

Keep `scope.yaml` and `logs/` out of version control (the included `.gitignore`
already does this): both can name real targets.

---

## Driving it from Claude

### Claude Code
Register the server as an MCP server (adjust the path and interpreter):

```bash
claude mcp add recon-bridge -- python -m recon_bridge.server
```

Run `claude mcp add` from the project directory (with your venv active) so the
scope file and logs resolve correctly, or set `RECON_BRIDGE_SCOPE` to an absolute
path.

### Claude Desktop
Add an entry to your `claude_desktop_config.json` MCP servers block that launches
`python -m recon_bridge.server`, with `RECON_BRIDGE_SCOPE` pointing at your scope
file. Restart Claude Desktop; the four tools appear in the tool list.

Once connected, just ask in natural language — "enumerate subdomains of
acme.example and fingerprint the web host." Claude calls the tools; the backbone
keeps every call inside scope.

---

## Driving it from ChatGPT / OpenAI

You have two independent options:

**1. ChatGPT's MCP connector (no bridge).** ChatGPT's Developer Mode / connector
support can point directly at the MCP server from `server.py` — the same server
Claude uses. Nothing extra to run.

**2. The API bridge (`bridge_openai.py`).** For scripts, headless runs, or any
OpenAI-compatible endpoint, this runs an agentic loop that offers the tools to
the model and executes whatever it calls — through the same backbone:

```bash
export OPENAI_API_KEY=sk-...
python -m recon_bridge.bridge_openai "Fingerprint https://app.acme.example and list missing security headers"
```

Because both paths read the shared registry, ChatGPT and Claude get identical
tools with identical guardrails.

---

## The engagement task tree

Recon is rarely one call. `subdomain_enum` finds names you then want to scan;
`port_scan` finds a web port you then want to fingerprint. recon-bridge threads
those phases together through one **engagement task tree**, persisted to
`engagement.json` (configurable via `RECON_BRIDGE_ENGAGEMENT`) so a long
engagement survives a restart.

Every recon tool feeds it automatically. The engagement controls read it:

```text
explain_scope        →  what am I allowed to touch?
engagement_status    →  assets discovered, findings by severity, pending to-do
next_steps           →  the next in-scope actions, derived from what's known
export_report        →  a Markdown recon report of the whole tree
```

`next_steps` is deterministic — it reads the current findings and proposes the
obvious follow-ups (resolve an asset that has no DNS yet, scan one with no port
data, fingerprint a host with a web port open) — and **every suggestion is run
back through the same `Scope`**, so the tree can only ever point at authorized
targets. A typical loop, whether driven by a model or by hand:

```text
subdomain_enum acme.example  →  next_steps  →  port_scan app.acme.example
                             →  next_steps  →  http_fingerprint https://app.acme.example
                             →  export_report
```

Because the state layer needs no LLM, the suggestions are reproducible and the
report is the same whether Claude, ChatGPT, or a shell script drove the session.

`engagement.json` and generated reports can name real targets, so (like
`scope.yaml` and `logs/`) the included `.gitignore` keeps them out of version
control.

---

## The audit trail

Every invocation appends one JSON line to `logs/audit.jsonl` (configurable):
timestamp, operator, tool, target, arguments (secrets redacted), and a result
summary. Refusals are logged too, so the record shows not just what was touched
but what was *attempted and blocked*. On a real engagement this is your evidence
of scope discipline.

```bash
tail -f logs/audit.jsonl | python -m json.tool   # watch it live
```

---

## Adding a tool

1. Write `recon_bridge/tools/your_tool.py` as `fn(ctx, **kwargs) -> dict`, and
   call `ctx.guard(tool=..., target=..., arguments=..., resolved_ips=...)` at the
   top so it inherits scope + audit + rate limiting.
2. Add one `ToolSpec` entry to `REGISTRY` in `recon_bridge/tools/__init__.py`.
3. Add a typed wrapper + `server.add_tool(...)` in `server.py`.

The ChatGPT bridge picks it up automatically from the registry.

---

## Tests

```bash
pip install pytest
pytest -q
```

The suite covers two layers. The authorization boundary: wildcard matching,
deny-over-allow precedence, protected-range refusal, port allowlists, engagement
expiry, and refusing a host that resolves into private space. And the engagement
task tree: finding de-duplication, persistence round-trips, scope-filtered
suggestions (including skipping an asset that has fallen out of scope), and
report rendering.

---

## Roadmap ideas

- TLS/certificate inspection tool, feeding findings into the same tree
- Per-engagement audit log paths keyed off the scope file
- A `prioritize` control that ranks the to-do by likely exposure
- Richer report formats (HTML, or a findings export for a reporting pipeline)

---

## Credits

The engagement task tree is inspired by
[PentestGPT](https://github.com/GreyDGL/PentestGPT) (Gelei Deng et al., USENIX
Security 2024) and its **Pentesting Task Tree** — a single structure that
carries engagement state so each phase seeds the next. recon-bridge borrows the
idea but not the implementation: the state layer here is deterministic and
model-agnostic, every suggestion is filtered through the engagement scope, and
the toolkit stays firmly in passive/low-impact reconnaissance. Like PentestGPT,
it is for **authorized and educational use only**.

---

## License

MIT. You are responsible for using it lawfully and only within authorized scope.
