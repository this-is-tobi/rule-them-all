# Grants

A grant is permission for **one capability**, optionally **one record**, that **expires on its own**.

It is the fine-grained half of the model. The `--allow-write` and `--allow-destructive` switches on `rta mcp serve` are decided once, at startup, for every call the server will ever make. A grant is decided when you need it, for as little as you need, and then stops being true without anybody remembering to revoke it.

## Issuing one

```bash
rta grant allow kv.get db-password --ttl 30m
```

That reads as: allow `kv.get`, but only the key `db-password`, for thirty minutes.

| Part | What it means |
| --- | --- |
| `<target>` | A capability ID (`kv.get`) or a plugin name (`kv`, covering all of it) |
| `[scope]` | One record — a key, a table, a bucket. Omit to cover the whole capability |
| `--ttl` | How long: `30s`, `15m`, `2h`. **Default 15m, maximum 24h** |
| `--agent` | Narrow to one named agent — the name `rta mcp serve --as` uses |
| `--profile` | Narrow to one configured connection (staging, not production) |
| `--max-uses` | Expire after this many successful calls |
| `--rate` | Bound how *fast*, as calls/window — `10/1h` |
| `--note` | Why, shown by `grant list` |

**Only a person at a terminal can issue one.** An agent that could grant itself access would be no gate at all, so there is no MCP tool for this and no flag that makes one.

## The four bounds, and what each is for

They compose. A grant stops at whichever is reached first.

```bash
rta grant allow kv.get deploy-key --ttl 5m --max-uses 1
```

- **`--ttl` bounds time.** The one you always get, because it is the only bound that keeps working when you forget.
- **`scope` bounds reach.** `rta grant allow kv.get` allows the whole store. `rta grant allow kv.get db-password` allows one key. Reach for the second unless you mean the first.
- **`--max-uses` bounds quantity.** `--max-uses 1` is the shape for a value that should be read exactly once — a deploy key, a one-time token.
- **`--rate` bounds speed.** `--rate 10/1h` allows ten calls in any hour and tells the agent when to come back. A session that has gone wrong slows to something you can notice, rather than draining at machine speed.

The last one is worth dwelling on. Time and quantity both fail the same way: an agent in a loop exhausts them immediately and correctly. A rate limit is the only one of the four that turns a runaway into something a human can catch while it is happening.

## Naming the agent

```bash
rta grant allow pg.query --agent claude --profile staging --ttl 1h
```

Without `--agent`, a grant covers **every** MCP client on this machine. That is rarely what you mean once you have more than one: consent given while pairing with one editor should not silently follow the agent running in a CI container.

The name comes from `rta mcp serve --as <name>`, which `rta mcp install` sets for you. Both halves name the same thing on purpose.

An empty agent on a grant is not a wildcard — it matches a server started without `--as`, and nothing else. Matching is exact in both directions, which is the same rule `--profile` already used.

## Seeing and taking back

```bash
rta grant list                       # what is allowed right now
rta grant renew kv.get db-password   # push out the deadline
rta grant revoke kv.get db-password  # take it back now
rta grant revoke kv                  # or all of it
```

`grant list` shows the target, the scope, what remains of each bound, the agent and profile it is narrowed to, and your `--note`. It is the answer to "what can an agent do right now", and it is the one screen worth checking before you walk away from a machine with a server running.

Revoking takes back what grants gave — it does not touch the ungated read tools an agent's token still opens. When the need is "this agent makes no call of any kind until I say so", that is a [lock](./20-mcp.md#locks-the-instant-no): `rta lock add agent <name>`, effective on its next call, no restart.

## Live consent, when you would rather be asked

With `rta mcp serve --consent`, a call that needs a grant nobody issued is **parked** rather than refused:

```bash
rta agent pending
rta agent show 5473aa62      # what it would do, from the capability's own --dry-run
rta agent allow 5473aa62
```

Answering `allow` runs that one call. It does not create a standing grant — if the agent asks again, you are asked again. That is the difference between consent and permission, and rta keeps them separate.

The same three commands take `--server <name>` to answer a call parked on a remote server, as a signed call over [the operator channel](./20-mcp.md#the-operator-channel) — where, unlike here, even the one-shot answer costs your operator key's passphrase, because "an agent with a shell could have done this anyway" is true at your terminal and false across a network.

See [MCP and the safety gate](./20-mcp.md#live-consent) for why this is off by default.

## The file, and why it is sealed

Grants live in `~/.local/share/rta/grants.json`, and the file carries a tamper seal.

The seal stops a forged line from a process that cannot read the key. It does not stop an agent that can run `rta grant allow` itself — which is why every grant also records [whether anybody was at the terminal when it was issued](./10-the-boundary.md#what-a-grant-says-about-where-it-came-from).

The reason is asymmetry: **a forged line in a grant file *adds* permission.** Anything that can write that file can write itself an allowance, and rta would honour it. So the file is sealed, and a grant file that does not verify is not honoured — `rta doctor` says so plainly rather than failing quietly.

This is exactly why a [team policy ceiling](./50-team-policy.md) needs no seal: it can only ever subtract, so the worst a hostile edit achieves is making rta refuse more.

## The guard: a passphrase in front of issuance

The seal's limit above has an answer, and it is opt-in:

```bash
rta grant guard on
```

From then on, issuing or renewing a grant asks for a passphrase — including `rta agent allow --ttl`, which also mints one. Every grant is signed with a key that exists only encrypted under that passphrase, and a grant without a valid signature is not honoured. The difference from the seal is one of kind, not degree: the seal's key sits on disk where anything running as you can read it, while the guard's passphrase lives in your head. An agent that runs `rta grant allow` from its shell is *refused*, however it invokes the binary — the ordinary self-granting path moves from detection (the Origin column, after the fact) to prevention.

Honest edges, stated rather than implied:

- **Enabling and disabling both clear the grant file.** Grants issued without a passphrase would be laundered by blessing them wholesale, and signatures with no guard beside them read as tampering. Grants last a day at most; re-issuing costs minutes.
- **Revoking never asks.** Taking authority away is the fail-safe direction, and an incident is the wrong moment to demand a secret.
- **A forgotten passphrase costs at most a day.** `rm` the guard state, `rta grant revoke --all`, `rta grant guard on` with a new passphrase — loud, bounded, and no secret is ever recoverable from disk.
- **File tampering stays in the detection regime.** Something running as you can still delete the guard's state or swap its key; every such rewrite rta can notice is refused loudly and fails closed. The cheapest rollback is worth naming: deleting the guard state *and* the grant file together leaves a machine indistinguishable from one where the guard was never enabled. A running MCP server pins the guard state at startup and refuses every grant-gated call if it weakens mid-session — which covers exactly the session the attacker is talking through. Across restarts nothing on disk can testify, and [the boundary chapter](./10-the-boundary.md) owns what remains.
- **One-shot consent answers stay passphrase-free.** `rta agent allow <id>` without `--ttl` releases exactly one already-parked call — something an agent with a shell could have run directly — and every such call is in the ledger. The guard prices authority that *outlives* the conversation; the harness deny list from `rta audit agents --fix` is the layer that stops an agent answering its own questions at all.
- **The passphrase never travels on the command line.** `--passphrase` is refused from the CLI — argv is readable by every process you run and lands in shell history — so the channels are the prompt and the TUI's masked field, both of which land nowhere.
- **There is no environment variable for the passphrase, and there will not be one.** The kv store accepts `RTA_KV_PASSPHRASE` because some setups need unattended unlocks, and `rta doctor` warns about the inheritance. The guard exists for the opposite trade: issuance is rare, attended, and nothing an agent inherits may satisfy it.

`rta grant guard status` says whether it is on, since when, and under which key; `rta doctor` carries the same fact.

### Remote mode: a guard whose keys are elsewhere

For a machine whose humans are not at its terminal — an `rta mcp serve --http` gateway — the guard has a second shape: `rta grant guard remote operators.txt --url https://rta.example.com` enrolls the public keys from an operator roster (minus any `role=read` rows — a watching key is not a signing key), bound to this server's canonical URL, and from then on a grant is honoured only when one of those keys signed it for this server — the URL sits inside the signed authority, so a fleet sharing one roster stays many trust domains: a row signed for staging is refused on prod however its bytes travel. No key material lives on the machine at all: nothing to steal, no passphrase to phish out of a server process, and `rta grant allow` at its own shell finds nothing to unlock — refused by construction, which on a remote server is the boundary completing itself rather than a gap. Issuance happens from an enrolled operator's own machine over [the operator channel](./20-mcp.md#the-operator-channel), each grant signed there under that operator's passphrase and attributed to their roster label in the listing's Origin column. Turning remote mode off asks for no passphrase — there is none here to ask for — so it costs presence at the machine's terminal, and clears the grants the operators signed, the same clean-slate rule as every other guard transition.

## What a grant does not do

- **It does not open a safety class.** If `note.rm` is destructive and the server was started without `--allow-destructive note.rm`, no grant makes it reachable. The startup gate is upstream of grants and is not negotiable at run time.
- **It does not widen a path root.** Path confinement is checked separately, on every path argument.
- **It does not survive a ceiling.** If a `.rta-policy.yaml` says `maxTTL: 15m`, a `--ttl 2h` grant is clamped to 15m and told so.
- **It does not authorize a profile you have not configured.** `--profile staging` matches the connection named `staging`, exactly.
- **It does not blur instances.** When an environment holds several connections to one plugin — `pg` and `pg/analytics` — a grant names exactly one (`--profile staging/analytics`), and asking for the bare name is refused with the list rather than resolved into a consent you did not give. Each grant pins the instance it was issued against, so re-aiming that one connection revokes exactly that grant.

## Next

- [The record](./40-audit-trail.md) — what agents actually did with what you granted
- [Team policy](./50-team-policy.md) — a ceiling nobody on the team can raise
- [Profiles](../20-using/40-profiles.md) — what `--profile` is naming
