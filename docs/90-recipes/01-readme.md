# Recipes

Worked examples. Each one is a real shape rather than a demonstration of a flag.

## Pair with an agent on a staging database, for an hour

The common case, and the one worth learning first. You want your editor's agent to help debug a slow query against staging — not production, not forever, and with a record afterwards.

```bash
# 1. Take production off the table entirely, for as long as you are working.
rta use staging --for 2h

# 2. Let one named agent read that one environment.
rta grant allow pg.query --profile staging --agent claude --ttl 1h \
  --rate 30/1h --note "slow query on orders"

# 3. Work. Then see what actually happened.
rta agent log --limit 50
```

Three bounds, each doing a different job:

- **`rta use staging`** means `rta mcp serve` refuses every other profile, whatever grants exist. It cannot grant anything — only take away — so it is safe to reach for first.
- **`--agent claude`** keeps the grant off your other MCP clients.
- **`--rate 30/1h`** is the one people skip. A time bound and a use bound both fail the same way: an agent in a loop exhausts them correctly and instantly. A rate limit turns a runaway into something you can notice while it is happening.

When the hour is up, all of it lapses on its own.

## Hand over one secret, once

```bash
rta grant allow kv.get deploy-token --ttl 5m --max-uses 1
```

One key, five minutes, one read. The clearest case in the whole model — and the record shows that `kv.get deploy-token` happened without showing what came back.

To make the broad form impossible for everyone on the team, put it in the repository:

```yaml
# .rta-policy.yaml
requireScope:
  - kv.get
```

Now `rta grant allow kv.get` — which would cover the entire store — is an error. Only a grant naming one key is accepted. See [Team policy](../30-boundary/50-team-policy.md).

## A ceiling a repository carries

Commit this next to your code and every clone inherits it:

```yaml
# .rta-policy.yaml
maxTTL: 15m
never:
  - pg.dump
  - vault.kv.get
neverProfile:
  - production
requireScope:
  - kv.get
  - s3.object.get
```

No seal, no key distribution, no trust in how it reached the machine — because **it can only subtract**. The worst a hostile edit achieves is making rta refuse more than you wanted.

A subdirectory may tighten it and cannot loosen it, so a service inside a monorepo can be stricter than the repository root without any mechanism for that.

## Morning triage

```bash
rta sys overview
rta agent overview
rta doctor
```

`sys overview` is host health grouped rather than seven commands. `agent overview` is the last hour of agent calls, how many were refused, and anything parked waiting on you. `doctor` is what rta can reach — read the `info` rows, not just the failures.

Once a week, the machine itself:

```bash
rta pkg managers          # which managers this machine has, version and path — and which it does not
rta pkg overview          # every package manager's outdated count, the OS, the kernel, a reboot owed
rta pkg outdated          # the packages, with the exact upgrade command on every row
rta pkg upgrade brew      # one manager at a time, never everything; apt and friends print the sudo command instead
```

Binaries you installed from GitHub releases have no manager; list them once under `plugins: pkg: tools:` as `- gh=github:cli/cli` and `rta pkg tools` compares each against its latest release, and `rta pkg upgrade gh` installs it in place — fetched, hashed, checked against the digest the release publishes, swapped in atomically. Binaries from `go install` need no entry: they carry their module path, and appear under the go manager.

Then the detail on whatever looked wrong:

```bash
rta sys overview --detail
rta agent log --refused
```

## Certificate expiry as a cron job

```bash
rta cert expiry example.com api.example.com -o json \
  | jq -r '.rows[] | select(.[2] | tonumber < 30) | .[0] + " expires in " + .[2] + " days"'
```

Exit codes make it a gate rather than a report:

```bash
rta cert expiry example.com || echo "check failed" >&2
```

## Dependency review before a release

```bash
rta audit deps -o md >> release-notes.md
rta audit why some-package
```

`audit deps` checks what you already declare against OSV, and each hit says whether **you** asked for that package or something else pulled it in — which is the difference between a fix you make and a fix you wait for. `audit why` draws the whole route from the lockfile.

## Audit every repository a team owns

`audit deps` reads what a project already committed, and from a terminal `--path` also takes a repository URL — cloned shallowly in memory, never written to disk. So auditing a repository is one command, and auditing all of them is that command in a loop:

```bash
gh repo list my-org --limit 200 --json url --jq '.[].url' |
  while read -r repo; do
    rta audit deps "$repo" -o json | jq -c --arg r "$repo" '{repo: $r, grade: .rows[0][1], detail: .rows[0][2]}'
  done
```

Nothing is installed, resolved or built — a lockfile is a list a package manager already committed, and reading a list is not scanning. The whole tree does arrive in memory, so a very large monorepo is a very large process; `--recursive` is what finds the manifests in one.

**It is refused over MCP, and that is not an oversight.** `audit deps` is read-only and needs no grant, which is what puts it on an agent's tool list with nothing asked. A URL an agent composes is a request rta makes on its behalf, to a host the agent chose, with the reply landing in its context — the thing `http.get` carries a grant for. Point an agent at a checkout you made.

`--detail` ends with the tools that answer what this cannot, with the target already substituted in — severity and fixed versions, the ecosystem's own auditor, the dependencies nothing imports, and an SBOM worth committing:

```
severity            `trivy fs .` or `grype dir:.` — the OSV batch endpoint carries identifiers only
reachability        `govulncheck ./...` — whether your code can reach the vulnerable function
unused              `go mod tidy` — declared dependencies nothing imports
an sbom to keep     `syft . -o cyclonedx-json` — read once here, kept there
```

They are pointers, never wrappers: rta does not run them, parse them, or track their flags. What it owes is the invocation with the target already in it, so the next step is a paste and not a search. The rows fit what was actually read — a Go project is never told about `knip`, and a pnpm project is never told to run `npm audit`.

## A security review you can paste into an issue

```bash
{
  rta audit web example.com -o md
  rta audit mail example.com -o md
  rta cert chain example.com -o md
} > review.md
```

Every finding cites the OWASP Top 10 category and the CWE it comes from, so the output is reviewable by somebody who was not in the room.

## Fill a shell with credentials, without them touching disk

```bash
eval "$(rta kv env --prefix APP_)"
```

Or for a tool that wants a file:

```bash
rta kv get tls-cert --out /tmp/server.pem   # written at 0600
```

## Answer "what changed here" without parsing porcelain

```bash
rta git overview
rta git status -o json | jq '.rows'
rta git blame internal/grant/grant.go
```

`git overview` is the branch, what it tracks, how far it has drifted, any rebase or merge left half-finished, staged/modified/untracked told apart, and the last commit's age. It works against a local checkout or a remote URL cloned in memory, and it is read-only.

**A remote URL is a person's affordance, and rta refuses one over MCP.** Every `git` capability is read-only and needs no grant, which is what puts it on an agent's tool list with nothing asked — and a URL an agent composes is an outbound request on the way there and a stranger's commit messages arriving in the model's context on the way back. That is `http.get`, which is gated. Point an agent at a checkout you made.

## Run an agent against a scratch directory only

```bash
cd /tmp/scratch
rta mcp serve --as sandbox --root /tmp/scratch
```

Every path argument must sit under a root, and the default root is the directory the server started in. rta prints the roots at startup rather than leaving them to be discovered from a refusal.

Widen deliberately, never by default:

```bash
rta mcp serve --as sandbox --root ~/projects --root /tmp/scratch
```

## Be asked instead of refused, while you are at the machine

```bash
rta mcp serve --as claude --consent --consent-notify --allow-write note
```

A call needing a grant nobody issued parks rather than failing:

```bash
rta agent pending
rta agent show 5473aa62       # including what it would do, from its own --dry-run
rta agent allow 5473aa62
```

Answering `allow` runs that one call and creates no standing grant.

**Only turn this on when you are actually present.** A call parked in a server nobody is watching is worse than a refusal: the agent hangs and the timeout is the only thing that resolves it. That is why it is off by default.

## Ship the record somewhere durable

Every row carries the sequence number the ledger assigned it, and `--after` takes one, so an append picks up exactly where the last one stopped:

```bash
ARCHIVE=~/audit/rta.jsonl
cursor=$(jq -rs 'map(.[0] | tonumber) | max // 0' "$ARCHIVE" 2>/dev/null || echo 0)
rta agent log --after "$cursor" --limit 500 -o json | jq -c '.rows[]' >> "$ARCHIVE"
```

Run it on a timer and the archive grows by what happened and nothing else. The cursor lives in the archive itself, so there is no second file to lose, and a run that finds nothing new writes nothing.

`--since` asks the same question the way a person does — `--since 2h` while something is going wrong, `--since 2026-08-30` when writing it up. It is the right flag for reading and the wrong one for shipping: a duration has a boundary, and a sequence number does not.

The date appears on a row exactly when the rows are not all from today, so a live view stays narrow and an archive is still readable a month later.

## Put it on a dashboard

The Grafana stack takes this in two halves, and rta meets both without a listener or a port.

**Loki takes the lines.** The cursor above is already what a log shipper wants — an append-only record with a sequence number — so point Promtail or Alloy at the JSONL file the recipe above writes, or run the same loop into `logger`/`vector`.

**Prometheus takes the counters.** One command writes the standard text exposition format into node_exporter's textfile collector:

```bash
rta agent metrics > /var/lib/node_exporter/textfile_collector/rta.prom.$$ \
  && mv /var/lib/node_exporter/textfile_collector/rta.prom.$$ \
        /var/lib/node_exporter/textfile_collector/rta.prom
```

Write-then-rename because the collector reads the file whenever it likes, and half a file is a parse error that drops every series in it. A timer every minute is plenty; nothing here changes faster than that.

| Series | What it counts |
| --- | --- |
| `rta_agent_calls_total` | every call ever, including any retention has dropped — a counter that survives rotation |
| `rta_agent_calls_recorded_total{capability,agent,outcome,authorized}` | the retained record, split the four ways worth splitting |
| `rta_agent_calls_retired_total` | what retention dropped, so the gap between the two above is visible rather than merely handled |
| `rta_grants_active{capability,agent}` | reach in force right now |
| `rta_agent_pending` | calls parked, waiting for a person |
| `rta_ledger_intact` | 1 while the hash chain verifies end to end |
| `rta_ledger_bytes`, `rta_ledger_segments` | the record's own size |

**`rta_ledger_intact == 0` is the alert worth having.** A record that stops verifying is either a bug or somebody editing it, and both are things to hear about in minutes rather than at the next review:

```yaml
- alert: RtaLedgerBroken
  expr: rta_ledger_intact == 0
  for: 1m
  annotations:
    summary: "rta's agent record no longer verifies — run `rta agent log --detail`"
```

Nothing is kept to produce any of this: rta stores no counters, so every number is one you could recompute from the record itself.

The record is hash-chained, so an edited or missing entry is visible:

```bash
rta agent log --detail
```

That makes tampering *visible*, not impossible — which is the realistic goal for a local file, and enough to catch the quiet single-line edit.

## Set up a machine with no terminal

Everything here is idempotent, so it belongs in a provisioning script, a Dockerfile, or a dotfiles bootstrap that runs on every login:

```bash
# The credential goes in the store, never on a command line.
rta kv set staging-db-password --file /run/secrets/db-password

# The environment, one line per plugin.
rta profile set staging --note "shared staging" --ttl 8h \
    --plugin pg --set host=db.staging.internal --set sslmode=require \
    --secret password=kv:staging-db-password

rta profile set staging --plugin s3 --set endpoint=https://s3.staging.internal

# The ceiling, in your own policy file rather than in any repository.
rta policy require
```

Three rules worth knowing before you write that script:

- **A value on a command line is in `ps`, in your history, and in most CI logs.** `rta kv set` takes `--file`, and `--file /dev/stdin` works from a pipe. `rta profile set --set` refuses a declared credential outright, so this is enforced rather than advised.
- **`--set` states the whole block.** A second run that mentions only `host` removes `sslmode` — and says which keys it dropped. Restate the block you mean.
- **`$RTA_CONFIG` matters in a container.** With no config directory the config path falls back to `./.rta.yaml`, and a working-directory file is not honoured: its `profiles:`, `plugins:` and `dashboard:` blocks are all ignored, because that file could have come from a repository you cloned. `rta profile set` refuses to write there rather than succeeding silently.

Then check it, without unlocking anything:

```bash
rta profile list && rta policy show && rta doctor
```

## One config for the whole team, in git

A team that names its deployments consistently can write the whole map once — every app, every environment, every cluster — and every member points rta at the same checked-in file. What makes this safe to share is that the file carries *references and coordinates, only*: where things are and which stored entry fills each credential, never a value.

`infra/rta.yaml`, in the repository the team already owns:

```yaml
# yaml-language-server: $schema=schema.json    # `rta config schema > schema.json`, committed beside it
profiles:
  shop-staging:
    note: "shop, staging — safe to hand to an agent"
    ttl: 8h
    plugins:
      pg@685186a7f1c2:
        kube: staging/shop/svc/postgres:5432
        secrets: {password: kube:postgres-creds/password}
      pg/analytics@685186a7f1c2:    # a second database, picked as --profile shop-staging/analytics
        kube: staging/shop/svc/postgres-analytics:5432
        secrets: {password: kube:analytics-creds/password}
      s3@a586c1f19b04:
        set: {endpoint: https://s3.staging.internal, bucket: shop-assets}
        secrets: {secret-key: kv:shop-staging-s3}
  shop-prod:
    note: "shop, production — grants only, short ones"
    ttl: 1h
    plugins:
      pg@685186a7f1c2:
        set: {host: db.prod.shop.internal, sslmode: require}
        secrets-from: prod/shop
        secrets: {password: kube:postgres-creds/password}
```

Each member's shell setup names it:

```bash
export RTA_CONFIG="$HOME/dev/infra/rta.yaml"
```

Two facts carry the whole arrangement:

- **`RTA_CONFIG` is the trust decision.** A config path somebody named is honoured in full; a `.rta.yaml` merely sitting in a cloned repository is not — its profiles are ignored, so a repository cannot ship a `prod` profile pointing at your cluster and wait for you to `cd` into it. Exporting the variable *is* the moment a person chooses to trust the team's file.
- **Credentials stay personal even though the map is shared.** `kv:shop-staging-s3` names an entry in each member's own encrypted store — the file says *which* entry, each person runs `rta kv set shop-staging-s3` once with their own value. `kube:` references go further: the Secret is read from the cluster at call time with each member's own kubectl credentials, so RBAC keeps deciding who can actually resolve the profile, and offboarding is the cluster access removal the team already does.

New machine, whole setup:

```bash
export RTA_CONFIG=... && rta kv set shop-staging-s3 --file /dev/stdin && rta doctor
```

`rta doctor` then names anything missing per profile — the pin that does not match the installed plugin, the store entry not yet created — which is the onboarding checklist, generated instead of maintained.

## Check a machine is set up, without unlocking anything

```bash
rta kv status      # where the store is and what can open it
rta profile list   # configured environments, and whether each is usable
rta doctor
```

`kv status` answers without unlocking the store, which makes it safe in a provisioning script.

## Back up a datastore, and put the backup somewhere else

Six plugins write a backup, and the shape is deliberately the same in each — `--out <file>` on the way out and, where rta has the other half, the file as the first argument on the way in. `vault` and `etcd` spell the first half `snapshot`, because that is the word each of them uses for it:

```bash
rta pg dump      --profile shop-prod --out shop-$(date +%F).dump
rta mysql dump   --profile shop-prod --out shop-$(date +%F).sql
rta mariadb dump --profile shop-prod --out shop-$(date +%F).sql
rta vault snapshot   --profile vault-prod --out vault-$(date +%F).snap
rta qdrant dump  --profile search-prod --collection docs --out docs-$(date +%F).snapshot
rta etcd snapshot    --profile coord-prod --out etcd-$(date +%F).snap
```

Every one of them writes `0600`, refuses to overwrite a file that already exists, removes what it made if the run fails, and prints how to restore the file it just wrote. That last line is the point: a backup nobody knows how to restore is a belief about a backup.

**Five of the six have an `rta` restore. `etcd` does not, and that is etcd rather than rta.** Its v3 protocol streams a snapshot out and takes nothing back in — no service in it carries a restore RPC — so restoring is `etcdutl snapshot restore`, which builds a data directory with etcd stopped, on every member, from the same file. `etcd.snapshot`'s own receipt prints that sequence at the moment you take the backup. rta ships no `etcd restore` rather than a command that would take the name of the thing you need and then not do it.

**All of them refuse over MCP**, and that is not a gap to be granted around. A whole datastore has no blast radius a grant could name, so the refusal is the answer rather than a missing feature — an agent that needs rows still has `pg.query` or `mysql.query`, bounded per call. Restores are `Destructive`, so a person types through `--yes` before a file replaces a database.

Getting the file off the machine is the second command, not a flag:

```bash
mkdir backups && mv shop-$(date +%F).dump backups/
rta s3 bucket upload backups --profile backups-s3 --bucket nightly --prefix shop/$(date +%F)/
```

And back, the same two steps in reverse:

```bash
rta s3 bucket download --profile backups-s3 --bucket nightly --prefix shop/2026-08-01/ --out restored
rta pg restore restored/shop-2026-08-01.dump --profile shop-staging --yes
```

Two gated commands rather than one capability reaching into two services, which is on purpose: each half is separately consented, separately scoped, and separately in the record.

**`cnpg` is the exception, and it is a different shape on purpose.** A CloudNativePG cluster already knows where its backups go — an object store, or a volume snapshot class, configured on the cluster itself — so there is no file for rta to write and no destination for it to choose:

```bash
rta cnpg backup request --cluster shop-prod-db   # ask the operator to take one now
rta cnpg backup list --cluster shop-prod-db      # what it did, and where it went
```

The request carries a cluster reference and nothing else. Destination, credentials, retention and encryption all come from the cluster, which is what makes this the one mutating capability in an otherwise read-only plugin: there is no place for a caller to point it at. It is `Write`, so it is off the default MCP surface until you pass `--allow-write cnpg`, and it needs a grant that names the cluster on top of that.

It is refused outright for a cluster that configures no backup. CloudNativePG accepts such a request and fails it minutes later, in a place nobody is watching — so rta reads the cluster first and tells you now.

**Know what your dump does not carry.** Each of these backs up one thing, and the material it needs beside itself lives somewhere the dump cannot reach. Every one of them says this on its own receipt as well, at the moment you take the backup — this table is the same facts where a backup strategy gets planned rather than where one gets run:

| Dump | What it leaves behind | Where that lives |
| --- | --- | --- |
| `pg.dump` | roles, tablespaces — a restore onto a fresh server fails on every ownership line | `pg_dumpall --globals-only` |
| `mysql.dump`, `mariadb.dump` | users and grants — a single-database dump carries no `mysql.user` rows | `mariadb-dump --system=users`; MySQL has no such flag, so `mysqldump mysql` |
| `qdrant.dump` | aliases — the snapshot restores the collection, not the name pointing at it | the alias API |
| `vault.snapshot` | the unseal keys, and the snapshot is **sealed with the source cluster's** — a restore without them is a file you cannot open | wherever `operator init` output was stashed, never Vault itself |
| `etcd.snapshot` | the cluster's own identity — membership, peer URLs and TLS material. The restore mints a new cluster ID and takes the topology from its own flags | your etcd configuration, wherever that is kept |

## Next

- [Grants](../30-boundary/30-grants.md) · [Team policy](../30-boundary/50-team-policy.md) · [The record](../30-boundary/40-audit-trail.md)
- [Writing a plugin](../40-plugins/20-writing-a-plugin.md) — if the capability you want does not exist yet
