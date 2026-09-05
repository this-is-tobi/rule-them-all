# Rule Them All :ring:

**Rule them all** — `rta` on the command line — is one binary over the tools you already juggle: databases, object storage, secrets, networking, certificates, host telemetry, HTTP APIs. Every capability is written once and rendered on three surfaces: a scriptable CLI, an interactive TUI, and an MCP server for AI agents.

## It works with your agent, not instead of it

rta is not another AI CLI, and it does not want to be the thing you talk to. It is the layer underneath the one you already use — Claude Code, Codex, Cursor, Copilot, Gemini — the part that decides what those agents are actually allowed to touch.

That is the whole proposition. Handing an agent a shell is **one decision that covers everything it will ever do**. Pointing it at rta is a different shape: read-only by default, everything else granted per capability, narrowed to one record, expiring on its own, and written down. You keep your agent; it gets a smaller blast radius and you get a record.

Which is why the security chapters below are not an appendix, and why every one of them is also usable by a person at a terminal. The same capability serves both — nothing here is an agent-only feature bolted on.

## Documentation

**Website:** <https://this-is-tobi.com/rule-them-all/introduction>

**Table of Contents** *- md sources*:

*Getting started*
- [Installation](./docs/10-getting-started/10-installation.md) *- Build it, verify it, put it on `$PATH`, turn on completion*
- [Quick start](./docs/10-getting-started/20-quickstart.md) *- Ten minutes: the CLI, the TUI, and an agent that can only read*

*Using it*
- [The CLI](./docs/20-using/10-cli.md) *- Output formats, exit codes, `--dry-run`, `explain`, scripting*
- [The TUI](./docs/20-using/20-tui.md) *- The dashboard, the catalogue, forms and confirmations*
- [Seeing the shape of things](./docs/20-using/30-trees.md) *- Mapping a directory, a bucket, a Vault mount or an etcd keyspace in one call*
- [Profiles](./docs/20-using/40-profiles.md) *- Naming an environment once and pointing every plugin at it*
- [Secrets (`kv`)](./docs/20-using/50-secrets.md) *- An encrypted local store for passwords, certificates and key files*

*The boundary* — worth reading in this order: each chapter is a smaller blast radius than the one before it
- [What rta actually bounds](./docs/30-boundary/10-the-boundary.md) *- Read this first before giving an agent access: an agent with a shell is not bounded by rta, and this is how to be in the configuration where it is*
- [MCP and the safety gate](./docs/30-boundary/20-mcp.md) *- Connecting a client, naming it, and what it can reach before you grant anything*
- [Grants](./docs/30-boundary/30-grants.md) *- Time-boxed permission for one capability, optionally one record*
- [The record](./docs/30-boundary/40-audit-trail.md) *- What agents asked for, what they got, and what is waiting on you*
- [Team policy](./docs/30-boundary/50-team-policy.md) *- A ceiling a repository can commit, which can only ever subtract*
- [Connecting your AI tool](./docs/30-boundary/60-ai-clients.md) *- Claude Code, VS Code, Cursor, Codex, Gemini, Copilot, and anything else that speaks MCP*

*Plugins*
- [Using plugins](./docs/40-plugins/10-plugins.md) *- Discovery, trust, indexes, install and upgrade*
- [Writing a plugin](./docs/40-plugins/20-writing-a-plugin.md) *- The SDK, the conformance suite, `plugin new` and `plugin dev`, and publishing it to an index*

*Recipes*
- [Recipes](./docs/90-recipes/01-readme.md) *- Worked end-to-end examples: incident triage, a scoped agent, CI checks, backups*

## What is in it

**20 built-in plugins, 123 capabilities** in the default build, and `rta plugin list` is the inventory:

`sys` · `net` · `http` · `cert` · `fs` · `kv` · `note` · `gen` · `codec` · `time` · `audit` · `grant` · `agent` · `operator` · `lock` · `pkg` · `debug` · `keys` · `git` · `eol`

Plus anything you install. Ten first-party plugins live in [rta-plugins](https://github.com/this-is-tobi/rta-plugins) as proof the contract works — `pg`, `mysql`, `mariadb`, `etcd`, `qdrant`, `s3`, `vault`, `kube`, `cnpg` and `docker` — each a separate binary from a separate module, so the ones you skip cost you nothing, and `rta plugin index add official` is how they arrive.

## The shape of the thing

Everything in rta is a **capability** — a small, declared unit of work with typed inputs, a safety class, and one implementation. `sys.cpu` is a capability. So is `kv.get`, `pg.query` and `net.dns`.

A capability declares itself once, and the surfaces are generated from that declaration:

```mermaid
flowchart LR
    C["capability<br/>declared once"]
    C --> CLI["CLI<br/>rta sys cpu --cores"]
    C --> TUI["TUI<br/>a form, a table, a chart"]
    C --> MCP["MCP<br/>a tool an agent can call"]
```

Which means three things worth knowing early:

- **`rta explain <capability>`** prints the same card the TUI and the MCP schema are built from. It is the authoritative reference for any command, and it is never out of date.
- **A safety class travels with the capability**, not with the surface. `read`, `write` and `destructive` mean the same thing whoever is asking — the difference is what each surface does about it.
- **Adding a plugin adds capabilities to all three surfaces at once.** There is no separate MCP registration step, and no way for a plugin to appear on one surface and not another.
