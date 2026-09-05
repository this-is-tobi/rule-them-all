# Writing an rta plugin

A plugin is a program that returns a declaration. rta launches it, asks what it can do, and renders that on four surfaces — CLI, TUI, MCP and JSON — none of which your code mentions.

## Fifteen minutes, start to finish

```
rta plugin new weather        # a plugin that already builds and runs
cd rta-plugin-weather
rta plugin dev                # build it, and see what rta sees
rta plugin dev -- weather greet world
go build -o ~/.local/bin/rta-plugin-weather .
rta plugin trust weather
rta weather greet world
```

That is the whole loop. The mechanical part takes about two seconds; the rest is deciding what your capability should do.

**The `trust` step is not paperwork.** rta loads a plugin by *running* it — that is how it learns what you declared — so a file called `rta-plugin-*` on `$PATH` would execute before anybody typed a command naming it, including the `rta __complete` a tab press runs. Being on `$PATH` is not consent, so an artifact runs once somebody has approved that exact digest. Rebuild and it needs approving again, which during development is a keystroke and in production is the event worth stopping for. `rta plugin trust` on its own lists what is waiting.

Your inner loop does not need it at all: `rta plugin dev` compiles from a directory you named in the command you just typed, which is a stronger act of approval than a digest in a file, so it is exempt.

**Your binary's name is your namespace.** `rta-plugin-weather` declares `Name: "weather"`, and rta refuses it otherwise — the name an operator gave the file by installing it wins over the name the file gives itself, because anything on `$PATH` can claim to be anything — the same reason the artifact needs trusting before it runs at all. `rta plugin new` gets this right for you; `rta plugin dev` is exempt from both, so your inner loop does not care what the temporary binary is called.

> A scaffolded plugin needs a `replace` directive pointing at your rta checkout, so its `go.mod` can resolve `pkg/sdk`. `rta plugin new` adds one automatically when it can find one by walking up from your working directory or from the rta binary; otherwise pass `--rta-source <path>`. It tells you which happened.

## The one thing to understand

You return **data**, not output.

```go
func greet(_ context.Context, req plugin.Request) (view.View, error) {
	return view.Text{Body: "Hello, " + req.String("name") + "!"}, nil
}
```

`view.Text`, `view.Table`, `view.KeyValue`, `view.Tree`, `view.Chart` and `view.Sections` are the whole union. A `view.Table` becomes a bordered table in a terminal, a navigable list in the TUI, CSV under `-o csv`, a markdown table under `-o md`, and structured JSON to an AI agent. You write it once. A table whose rows are in time order says so with `Tail: true`: the newest row is last, the terminal ends on it, and the TUI opens on it — a log is read from where things are now, back.

The same applies to failure. Return a `view.Error` rather than a bare error where you can:

```go
return nil, view.Errorf("weather.nosuchcity", "no station for %q", city).
	WithHint("try `weather stations` for the ones that exist")
```

The code is stable enough for a script to branch on, and the hint is what the person does next. Both are lost by `fmt.Errorf`.

One error is not like the others: a **policy gate** — your handler declining a call over who is asking, not over what went wrong, like a capability that refuses the MCP surface outright. Build that one with `view.Refusef` instead of `view.Errorf`. The host's audit trail records refusals and failures as different outcomes, and only your handler knows which one it returned — an unmarked gate ledgers on the operator's machine as your plugin breaking.

## Declaring inputs

```go
Inputs: []plugin.Field{
	{Name: "city", Type: plugin.String, Positional: true, Required: true, Help: "which city"},
	{Name: "units", Type: plugin.String, Default: "c", Options: []string{"c", "f"}},
	{Name: "key", Type: plugin.Secret, Help: "API key"},
	{Name: "out", Type: plugin.Path, Local: true, Help: "write the report here"},
}
```

`Type` is mandatory and closed — there is no inference from the name, because `Secret` is what makes a value masked and `Path` is what makes it completable, and neither is guessable.

A credential a caller may give more than once is `SecretSlice`, not `StringSlice`. It is `Secret`'s masking with `StringSlice`'s shape, and declaring the list type alone is the mistake worth naming: the value is then written to the completion shortlist and, over MCP, into the audit log in cleartext, because every sink that hides a credential asks whether the *type* is one. `vault.kv.set --data 'password=…'` is the shape.

What each one buys you:

- **`Options`** becomes a TUI picker, shell completion, and an `enum` in the MCP schema. Use it for a fixed set.
- **`Suggest`** is a function returning what exists *right now* — your tags, their hostnames. It runs on human surfaces only, never for an agent: the list itself is information. It must be cheap and silent on failure, because it fires on a keystroke — no network call, no prompt, no connection opened. It receives what the caller has supplied so far, on the CLI and in a TUI form alike, so a suggestion can depend on a sibling field being typed above it. Tab completes it on both surfaces. Not accepted on a `Secret`, a `SecretSlice` or a `Text` input: the list renders in plain text beside the box, which defeats a mask, and a body is written in `$EDITOR` rather than completed.
- **`Local: true`** means the value names something on *this* machine, so it is refused over MCP. `--out` is the example: a grant authorises revealing a value, not choosing where on the operator's disk it lands.
- **`Path`** inputs are confined to the server's roots when an agent supplies them.
- **`Config`** names a key in the operator's configuration this input may be filled from when nobody passed it, so a connection is stated once instead of retyped. Precedence is caller, then config, then `Default`, and your handler cannot tell which it got.

```go
{Name: "host", Type: plugin.String, Required: true, Config: "host"},
{Name: "port", Type: plugin.Int, Default: 5432, Config: "port"},
{Name: "mode", Type: plugin.String, Default: "prefer", Config: "tls.mode"},
```

The operator writes it under your plugin's own section, which is pinned to the binary they installed rather than to the namespace you declare — anything on `$PATH` can claim a namespace, and their stated values must not go to whoever won that race:

```yaml
plugins:
  weather@1a2b3c4d5e6f:
    host: db.internal
```

`rta doctor` prints the exact line, digest included, and says so again if you upgrade and the pin goes stale. **`Config` is refused on a `Secret` or `SecretSlice` input** — configuration is a plaintext file read on every invocation, and a `Secret`'s default is published in your MCP tool schema. Use `Local: true` and let the host resolve it from its own environment.

**Declare it generously.** Anything a person would set once and keep — the scope a call works in (a cluster, a namespace, a bucket, a collection), a limit, a depth, a parallelism, a TTL convention, a storage class, a dump format — wants a key, because every one of them is a thing an operator otherwise retypes on every call and gets wrong on one. The caller always wins, so a configured value is a default, never a lock. Three kinds of input do not get one: a **selector of one record** (a key, a path, a container, a backup name — there is no sensible default), a **cursor** (`--after`, `--offset`), and a **destructive switch** (`--force`, `--overwrite`, `--replace`, `--clean`): a default that skips a safety check, in a file nobody is watching, is exactly the footgun the check exists to prevent.

**The scope is a flag, the record is the argument.** A config-backed input cannot be positional — arguments bind left to right, so a config-filled first argument would change what a typed one means — which is why `--cluster`, `--namespace` and `--bucket` are flags with keys while the pod, the object and the backup stay positional. kubectl draws the same line with `-n`.

## Safety is a claim, not a label

Every capability declares exactly one of `plugin.Read`, `plugin.Write` or `plugin.Destructive` — it is one value, not a set of flags.

It decides what an AI agent can reach without a human, so it is a statement about **blast radius** rather than about whether you touch the disk:

| Class | Meaning | What an agent needs |
|---|---|---|
| `Read` | changes nothing, reveals nothing sensitive | nothing |
| `Write` | changes something, **or reveals a secret** | `--allow-write <your-plugin>` |
| `Destructive` | removes something with no undo | an explicit per-capability allowlist **and** a grant a person issued |

The rule that catches people: **a capability that reveals a secret's plaintext is `Write`, even though it mutates nothing.** `kv get` is the canonical case. If yours prints a token, signs with a private key, or dumps an environment, it is not `Read`.

Set `NeedsGrant: true` when the class understates it, and `Scope: "city"` to name the input a grant can be narrowed to — then a person can allow one record rather than the capability.

Set `HostSpecific: true` if what a capability returns describes the machine your plugin's process happens to run on — its own filesystem, its own network configuration — rather than a configured remote service or a pure computation. A remote, HTTP-transport `rta mcp serve` hides a capability marked this way from `tools/list` entirely, since a caller on another machine is never the one it would be describing. Most plugins reach somewhere the operator configured (a database, a cluster) or compute from their own arguments, and never need this — it exists for the same reason rta's own `sys`, `fs` and `git` built-ins declare it themselves.

## If your plugin needs a credential location

Plugins run confined and rta denies them a standard list of credential directories — `~/.ssh`, `~/.aws`, `~/.kube` and the rest. If yours cannot work without one, declare it:

```go
plugin.Plugin{
    Name:  "clusters",
    Needs: []plugin.Need{plugin.NeedKubeconfig},
    ...
}
```

Declaring is asking. The operator runs `rta plugin allow <name>` to grant it, against your artifact's digest, and a rebuild asks again. Until then your plugin still loads and runs — it just fails at whatever call wanted the file, and `rta doctor` tells the operator which command fixes that.

`rta plugin dev` honours your declaration without any of that, for the same reason it skips trust: you compiled it from a directory you named in the command you just typed. Its report says what it allowed and what installing the plugin will need instead, so the difference is visible before somebody else hits it.

Ask for the least you need. Every location you declare is one the operator has to weigh, and a plugin that asks for four when it uses one is a plugin people stop granting anything to.

`rta explain <capability>` prints the exact flag an operator would need. So does `rta plugin dev`, in its `Agents` column, which is the fastest way to check you classified something the way you meant to.

## What rta does to your process

Worth knowing before you debug something surprising:

- **Your stdin is `/dev/null`.** The protocol owns the real one. Never prompt — declare a `plugin.Secret` input and let the surface ask.
- **On macOS you are sandboxed.** You cannot read or write rta's own config and data directories, and cannot read `~/.ssh`, `~/.aws`, `~/.kube` and the rest. Everything else is readable. `rta doctor` prints the set. Linux and Windows are **not** confined and say so.
- **Your environment is filtered** to `PATH`, `HOME`, `TMPDIR`, `TZ`, `LANG`, `LC_*` and the TLS cert variables. No `RTA_*`, no cloud credentials, nothing your user exported. If you need a value, take it as an input.
- **You are in your own process group** and everything you spawn dies with you.
- **One process serves every call**, started on the first one and reused. Do not assume a fresh process per capability, and do not hold per-call state in a global.
- **A panic in a handler is caught** and returned as an error naming your capability. It does not take the process down, so the other capabilities keep working — but it is still a bug and it still says your name.

## Declared text is checked

Your `Summary`, `Description`, `Help` and `Options` are published verbatim to AI agents as tool descriptions. rta refuses control characters, bidirectional overrides, invisible characters and its own framing markers at registration, and caps the lengths. If `rta plugin dev` refuses your plugin over a summary, that is why.

Write the `Description` for somebody deciding whether to call it. It is the text a model reads before choosing.

## Testing

`rta plugin new` ships a `main_test.go` wired to `pkg/sdk/sdktest`, so `go test` passes from the first minute:

```go
func TestPlugin(t *testing.T) {
	sdktest.Check(t, Plugin(), sdktest.WithInputs(conformanceInputs))
}
```

It runs the catalogue-wide invariants rta holds its own built-ins to — the shared verb vocabulary, every declared view rendering in every format it claims, dry-run honesty on anything that writes. It found a built-in sending real bytes on `--dry-run` the first time it was pointed at rta's own catalogue.

**Fill in `conformanceInputs` as you add capabilities.** The suite cannot invent a bucket name or a record id, so a capability with a required input and no value here is one it cannot drive — and almost every capability that *changes* something has one. A `Write` or `Destructive` capability the suite could not drive is a failure, not a skip, and the message names both ways out: supply a value, or state why not with `sdktest.Skip`. This is not defensiveness. rta's own external plugins each called `Check`, each went green, and behind that six handlers wrote to real systems under `--dry-run` because not one of them was ever run.

Two rules make the difference between a real check and a green nothing:

```go
func conformanceInputs(dir string) map[string]map[string]any {
	return map[string]map[string]any{
		// Point anything that connects at somewhere nothing is listening, so
		// a dry run that stops being dry fails as a refused connection rather
		// than as a request against somebody's real service.
		"acme.thing.set": {"endpoint": "127.0.0.1:1", "name": "conformance"},
		// Point every path inside dir, which is the directory the suite
		// watches — a write that should not have happened is then a test
		// failure rather than a file in a temp directory nobody looks at.
		"acme.thing.get": {"endpoint": "127.0.0.1:1", "out": filepath.Join(dir, "got")},
	}
}
```

Reads that cannot be driven stay a log line: that is missing coverage, not a broken promise, and demanding a live target for every diagnostic is exactly what rta's own fixture deliberately refuses to do.

## Conventions worth following

Use the shared verb vocabulary. `sdktest` warns on a novel verb, and when your word has a standard spelling it names it — it will tell you rta writes `delete` as `rm`, in four places already. The whole list:

```
add  done  edit  get  init  inspect  list  overview
reopen  rm  search  set  show  status  tags  toggle
```

`sdktest.Vocabulary()` returns the same list at runtime, so you never have to trust this page over the tool. The point is that learning one plugin teaches you all of them.

One of those words carries extra weight. **`<your-plugin>.overview` becomes your dashboard tile** — the panel the TUI draws for your plugin on its landing screen. Without one, the tile is whichever of your capabilities happens to come first and can run unattended, which means your declaration order picks it by accident. Declaring an overview is how you pick it on purpose.

A tile runs on load and then every few seconds with nobody watching, so it has to be `Read`, answerable from its defaults alone, and cheap enough to repeat. If your overview is none of those, set `NoPreview: true` on it — rta will tile something else rather than put it on a timer, and `overview` still means to a reader what it means everywhere else.

Name a capability for the **question it answers**, not the mechanism. `audit mail` is DNS lookups underneath, but nobody reaches for `net dns` while hardening a domain.

Give a detail page's sections an id. `view.Section` carries both an `ID` and a `Title` because they are different jobs: the title is what a person reads and should improve over time, while the id is what a script pulling one section out of your page — or an agent citing where a fact came from — addresses it by. `plugin.Page` spells them `PutAs` and `AddAs`:

```go
p.PutAs("summary", "at a glance", summary)
p.AddAs("stations", "nearby stations", listStations, nil)
```

It is optional — `Put` and `Add` work, and `Key()` falls back to the title — but then rewording a heading silently renames the handle. `sdktest` says so.

## Publishing it

An **index** is a git repository holding one `index/<name>.yaml` manifest per plugin. That is the entire format. rta clones it with your own `git`, so your remotes, proxies and credentials keep working — over `https`, `ssh`, or a path on this machine; a `<transport>::<argument>` remote helper and cleartext `http://`/`git://` are refused — and it answers `rta plugin search` from the manifests alone without fetching or running anything.

```
my-index/
└── index/
    ├── mytool.yaml
    └── othertool.yaml
```

**Do not write the manifest by hand.** Every claim in one is already in your declaration: the name, the version, the summary, each capability's ID, safety class and grant flag, and each credential location the plugin asks for. `rta plugin install` derives all of it again from the bytes it downloads and refuses the install when the two disagree — so a transcription slip does not surface for you, it surfaces on somebody else's machine as a message about an index they cannot fix.

Generate it instead:

```bash
rta plugin manifest bin/rta-plugin-mytool \
  --version v1.2.0 \
  --homepage https://github.com/you/rta-plugin-mytool \
  --checksums dist/checksums.txt \
  --platform linux/amd64=https://github.com/you/rta-plugin-mytool/releases/download/v1.2.0/mytool_linux_amd64.tar.gz \
  --platform darwin/arm64=https://github.com/you/rta-plugin-mytool/releases/download/v1.2.0/mytool_darwin_arm64.tar.gz \
  --index ../my-index
```

rta runs your binary the way a load does — sandboxed — and writes down what it declares. You supply the one thing the binary cannot know: where its bytes will live. `--checksums` reads the `<sha256>  <filename>` lines your release already publishes and matches them by filename; a `--platform` pointing at a file on your machine is hashed on the spot instead, and its archive is opened to prove the `bin:` claim while it is still in reach.

The reference page is generated the same way, for the same reason — a page written by hand goes stale on the first commit that touches a capability, and nobody notices, because the commit is about something else:

```bash
rta plugin doc bin/rta-plugin-mytool > README.md
```

One markdown page from the declaration: the capability table, every config key the plugin reads and which capabilities read it, and one section per capability holding the same card `rta explain` prints. Regenerate it in CI and fail when the committed copy differs, and the page cannot lie about the binary beside it.

Two things to know before you publish:

- **`.tar.gz`, or a bare binary.** rta extracts a single member from a gzipped tar and has no zip reader at all, so a `.zip` artifact cannot be installed — including on Windows, where GoReleaser's default format is zip. `rta plugin manifest` refuses one rather than letting it become a failed install somewhere else.

- **A registry works too, and needs no checksums file.** `--platform linux/amd64=oci://ghcr.io/you/rta-plugin-mytool:1.2.0-linux-amd64` names an OCI artifact — one layer, pushed with `oras push` or anything that speaks the distribution spec. rta reads the digest and the media type from the registry that will serve the bytes, which is a better source than a file sitting beside your build, so `--checksums` is for `https://` artifacts only.

  Pulls are **anonymous**: rta sends no credential to any registry, so the artifact has to be publicly readable. A package on ghcr is private until you make it public, and until you do, install refuses with *"ghcr.io will not serve … anonymously"*. That refusal is deliberate rather than a gap — an index is somebody else's repository, and authenticating to whatever host a manifest names would turn a search result into a way to spend your credentials.
- **Stamp the version at build time, don't type it.** A version is a fact about a release, and a literal in your source is a fact about nothing — it stays at `0.1.0` through every release you cut, because bumping it is a step nobody's build performs. `rta plugin new` scaffolds the pattern instead: a `var version = "dev"` the declaration reads, set by the linker.

  ```bash
  go build -ldflags "-X main.version=$(git describe --tags)" .
  ```

  That is GoReleaser's own default ldflag, so a release stamps it for free, and an unstamped build says `dev` rather than claiming a version that was never cut. `--version` still overrides, for the case where the tag and the artifact genuinely disagree.

Then attach your own index and take the round trip yourself, before anybody else does:

```bash
rta plugin index add mine /path/to/my-index
rta plugin search mytool
rta plugin install mine/mytool
```

Install is where claims meet evidence: rta fetches the artifact, hashes it, launches it in the same sandbox any load uses, and refuses if what it declares is not what your index said — naming your index. Earning that refusal on your own machine is the point of running it.

## Worked examples, in the order worth reading them

Ten first-party plugins live in [rta-plugins](https://github.com/this-is-tobi/rta-plugins), and they are not a showcase — they are the proof the contract works, written against the same public SDK you have, from the same released rta. Every one is a separate module that cannot reach into rta's internals, so anything they do, you can do.

Read them in this order and each one adds exactly one idea:

| Plugin | Read it for |
| --- | --- |
| [`examples/plugin-hello`](../../examples/plugin-hello/main.go) | The whole shape in one file — and the fixture rta's own host tests run against |
| [`builtin/eol`](../../builtin/eol/eol.go) | The smallest real one: a single capability over a public API, nothing to configure — built in, and the same declaration a plugin would make |
| [`kube`](https://github.com/this-is-tobi/rta-plugins/tree/main/plugins/kube) | Shelling out to a tool the operator already has (`kubectl`) instead of linking its client library, and why |
| [`cnpg`](https://github.com/this-is-tobi/rta-plugins/tree/main/plugins/cnpg) | The opposite choice from `kube`: one plain API read against a Custom Resource instead of a shell-out, and declaring a credential [`Need`](#if-your-plugin-needs-a-credential-location) rather than assuming one. Also a single `Write` among reads, and what it costs to add one |
| [`mysql`](https://github.com/this-is-tobi/rta-plugins/tree/main/plugins/mysql) | A connection: declared inputs, a `Secret` a profile fills, an endpoint role a tunnel can fill |
| [`mariadb`](https://github.com/this-is-tobi/rta-plugins/tree/main/plugins/mariadb) | Two plugins over one service family without either becoming a fork of the other |
| [`pg`](https://github.com/this-is-tobi/rta-plugins/tree/main/plugins/pg) | Safety classes doing real work — three dumps graded by what a grant can name, two refusing MCP outright |
| [`s3`](https://github.com/this-is-tobi/rta-plugins/tree/main/plugins/s3) | `Live` completion from the service itself, and a download that refuses any object key landing outside the directory you named |
| [`vault`](https://github.com/this-is-tobi/rta-plugins/tree/main/plugins/vault) | A plugin where almost everything is a secret, and what that does to every declaration |
| [`etcd`](https://github.com/this-is-tobi/rta-plugins/tree/main/plugins/etcd) · [`qdrant`](https://github.com/this-is-tobi/rta-plugins/tree/main/plugins/qdrant) | Tree views, and a plugin whose whole subject is a keyspace |
| [`docker`](https://github.com/this-is-tobi/rta-plugins/tree/main/plugins/docker) | A local daemon socket rather than a network endpoint |

`rta plugin new <name>` scaffolds one that builds, passes its conformance suite and runs, so none of these is where you start — they are where you look when your plugin needs the thing they already do.

## Reference

- [`rta explain <capability>`](../20-using/10-cli.md#rta-explain) — the authoritative card for any capability, generated from the declaration itself. The fastest way to check what rta made of yours.
- [`pkg/plugin`](../../pkg/plugin/) and [`pkg/view`](../../pkg/view/) — the contract in code, with the reasoning in the doc comments.
- [`pkg/sdk/sdktest`](../../pkg/sdk/sdktest/) — the conformance suite your plugin should pass.
