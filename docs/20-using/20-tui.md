# The TUI

```bash
rta
```

Bare `rta` on a terminal opens the interactive shell. In a pipe it prints help instead, so a script never hangs on an interface nobody can see.

It is the same capabilities as the CLI — the same declarations, the same safety classes, the same results. What changes is that you can browse them, fill inputs in a form, and see a table you can walk through.

## The landing dashboard

A search bar across the top, and one tile per plugin that has something to show at a glance. Typing filters every capability in the catalogue on the fly.

| Key | What it does |
| --- | --- |
| `/` | Search |
| `enter` | Open |
| `esc` | Back |
| `q` or `ctrl+c` | Quit |
| `[` `]` | Move a tile |
| `H` | Hide a tile |
| `p` | Plugin inventory — where a hidden tile comes back |
| `t` | Theme |
| `c` | Configure |

Tiles are yours to arrange. `H` hides one you never look at; `p` opens the inventory where any of them comes back.

### Stating the dashboard yourself

With no `dashboard:` block, rta builds one: a tile per plugin that has a capability which is `Read`, needs no input, and is cheap enough to run unasked. Plugins installed later appear on their own.

There are two ways to change that, and the difference is whether tomorrow's plugin still shows up.

**Adjust the automatic set.** `hidden:` and `order:` bend it without freezing it:

```yaml
dashboard:
  hidden:
  - git.overview
  order:
  - sys.overview
  - note.list
  columns: 3
```

**Or state it exactly.** `tiles:` replaces the automatic set outright — `hidden:` and `order:` are not consulted, because the list is already both:

```yaml
dashboard:
  tiles:
  - id: kube.overview
  - id: note.list
    span: 2
  - id: pg.overview
    with:
      profile: prod
```

`with:` fills the capability's inputs. `span:` widens a tile past what its own declared width works out to — for the one you actually read.

**Naming a tile is the only way to get a capability the automatic dashboard leaves out.** Anything that reaches off the box — every `kube`, `pg`, `s3` and `vault` capability — is kept off it deliberately, however cheap it looks: a dashboard runs its tiles on load and again on a timer, and nobody expects opening a TUI to spend an API quota or disclose anything to a third party. Writing one into `tiles:` is you asking for it, which is a decision the automatic path can't make for you.

Worth knowing what that costs before you do: a tile refreshes on a timer for as long as the TUI is open, so a cluster-wide `kube.overview` tile is that many `kubectl` calls an hour, every hour. `rta explain kube.overview` prints what a capability actually reads, which is not always only what its name suggests.

Two things the block will not do, whatever you write in it:

- **A tile that is not `Read` is dropped.** Otherwise `{id: kv.rm, with: {key: old-token}}` would delete that key on startup and keep deleting it — on a timer, with no form and no confirmation, since the destructive gate lives on the CLI and the browse path and a tile goes through neither.
- **The whole block is ignored unless the config is one you named** — your user config directory, or `RTA_CONFIG`. rta falls back to `./.rta.yaml` when there is no user config directory (ordinary under `env -i`, in a container, in CI), and a cloned repository does not get to arrange your screen: `{id: http.get, with: {url: …}}` there would be a beacon that starts the moment you open the TUI in that directory. `hidden:` is the same hazard pointed the other way — it can take the agent tile off the screen, and that tile is where you notice a parked consent request before its clock runs out.

## The catalogue

Every capability as a table grouped by plugin — one row each, with its ID, its safety class and its summary. The filter stays live, every pane is bounded by the terminal and scrolls inside it, and the mouse wheel works.

## Running something

A capability with inputs opens a form built from its declaration:

- Fields that declare `Options` become a picker.
- Fields that declare `Suggest` complete from what exists on your machine — your tags, your keys, your hosts file.
- `Path` fields complete directory by directory as you type.
- `ctrl+e` opens `$EDITOR` on a long body.
- `shift+enter` accepts every remaining field at its current value, for a form whose defaults are already right.

### Which environment the run goes to

A capability a profile can fill opens with the environment picker first, defaulted to whatever is switched on. Under an environment that reaches its service through a forward, the host and port boxes show the forward's own coordinate — `kube:homelab/databases/svc/postgres` in the host box, `5432` in the port box — and the picker's help line says the same: `runs through the kube forward to homelab/databases/svc/postgres:5432, which fills host, port`. Leave them and the forward answers per call. Type over one and the run connects directly to what you typed, without opening the forward — the way out of a coordinate that is wrong without leaving the form to fix the profile first. It is first because it changes what every other answer means — a host typed under one environment is not the same value under another — and moving it rebuilds the form on the environment it now names, rather than leaving one environment's values on screen under another one's name.

Boxes that environment fills open showing its values, and you can still type over them. A credential is the exception: it opens empty, because seeding a masked box paints your passphrase's length in dots. So the box says where the value comes from instead:

```
password
password for the role — staging fills it from kv:staging-db-password (secret)
>
```

**The reference, never the value.** `kv:staging-db-password` is the name of an entry — something you wrote, in a file you can read — and naming it answers the question an empty masked box could not: whether you have to type this at all. An exported `RTA_PROFILE_STAGING_PASSWORD` is named the same way, and named as the winner, because that is the one the run will actually use. A box under an environment that supplies nothing says nothing, and you type it.

### Tab means one thing on every field

**Take me forward.** What that is depends only on what the box under the cursor can still be completed to, never on which field it is:

| What the box holds | What tab does |
| --- | --- |
| something an offer extends | takes the offer, and stays — so a path, a cluster coordinate or a comma list is walked a segment at a time, exactly as in a shell |
| nothing yet | says what is on offer, because there is no ghost to accept until something is typed |
| everything there was to complete | moves to the next field |

`shift+tab` is the previous field and `enter` is the next one, whatever the box holds. A field that completes says so under itself, because the footer speaks for the screen rather than for the box under the cursor.

`↓` and `↑` browse the offer from an empty box: down puts the first candidate in the box, the next down its neighbour, up walks the other way, and both wrap. Type over what was placed and the box is yours again — the arrows then cycle the matches of what you typed, which is what they always did once a letter was in.

Destructive capabilities confirm before acting, the same as on the CLI.

## The plugin inventory

`p` opens what is installed, what each plugin puts on the dashboard, and — the part worth having a pane for — **any artifact rta found on `$PATH` and refused to run**. A trust gate's failure mode is silence: a plugin that is installed and doing nothing looks exactly like one that was never installed.

| Key | What it does |
| --- | --- |
| `p` | Open the inventory (and close it) |
| `space` | Show or hide its dashboard tile |
| `t` | Approve an artifact, or take an approval back |
| `a` | Choose which credential locations it may read |
| `c` | Configure it |
| `enter` | Its capabilities, in the search bar |

### Grouped by where the bytes came from

The pane bands its rows by provenance, because that is the fact that changes how every other fact on a row reads. "13 capabilities, one of them destructive" means one thing about code compiled into the binary you chose to run and something else about a file that appeared on your `$PATH`, and a list sorted by name buried the two or three you did not compile among a dozen you did.

| Band | What it means |
| --- | --- |
| **built in** | Compiled into the rta binary you are running, which is why these need no digest |
| **installed by rta** | rta placed these bytes from an index you attached; the row carries the version, the index and what the signature check found |
| **found on $PATH** | Binaries rta did not place and holds no record of |
| **not run** | Discovered and never launched, because nothing has approved them yet |

A stock install is entirely built in, so no bands are drawn at all — one band separates nothing.

**There is no "official" band, and that is a fact about rta rather than an omission.** rta attaches no index by default: `rta plugin index add <name> <repository>` is the whole story, and the name is yours to choose. So an index called `official` is only an index somebody called `official`, and a band drawn from that name would be rta vouching for provenance out of a string anyone can pick. What rta genuinely knows is whether it placed the bytes itself, and that is what the bands say. Trust here binds to a digest, never to a name — which is also why an `rta.lock` record is matched to a row by digest: an entry naming this plugin and describing different bytes belongs to a half-finished upgrade, not to what you are running.

`t` is the decision made where the evidence is: the digest and the path are on the screen while you take it, which the command line shows you only afterwards. Neither direction takes effect on the process you are in — trust is read once, before anything is launched — so approving says it loads when rta restarts, and withdrawing says the plugin already running stays running until rta exits.

`a` is the permission after that one. Approving says these bytes may run; allowing says what they may read — a kubeconfig, an SSH directory, whatever the plugin declares it needs. The row shows both sides: what it has been allowed, and what it is still asking for.

**`a` opens a form where `t` is a keypress, and the difference is deliberate.** Approving is one yes/no about one thing already named on the row. Allowing is plural — a plugin can declare several locations, and a bare key would hand over every one of them from a cursor position. The form is also what makes taking access back expressible: the list you submit *is* the whole grant, so clearing a box withdraws that location and there is no second command to learn. A plugin you have not approved yet cannot be allowed anything — running at all is the decision that comes first, and the pane says so rather than opening a form that could not succeed.

## Working with results

| Key | What it does |
| --- | --- |
| `enter` | Open the row |
| `e` | Edit inputs and run again |
| `r` | Re-run |
| `y` | Copy as JSON |
| `d` | Delete |
| `esc` | Leave a slow run |

A log — `agent log`, or any table that declares its newest row last — opens on that row, scrolled to the end, so what just happened is under the cursor and the past is a key up.

Views are actionable rather than static. In the notebook, `t` turns a note into a to-do or back, `d` checks one off and `x` removes; on the consent queue, `L` opens the lock form beside the call that made you want it, and on the lock list `x` lifts the lock under the cursor — from the list *and* from a record's own page, refreshing as it goes. Detail pages are composed from other capabilities' views rather than rebuilt, so a record page shows metadata, prose and relations as separate sections.

## Profiles

`f` opens the profiles pane — your configured environments, which one is on, and what each covers. `n` creates one and `c` edits it, which is the shortest way to define a profile: the form is generated from each plugin's declared inputs, and it knows which of them are secrets, so a credential lands in `secrets:` as a reference instead of in `set:` as a value.

| Key | What it does |
| --- | --- |
| `f` | Open profiles |
| `u` | Use this one |
| `enter` | The plugins inside it |
| `n` | New |
| `d` | Delete |
| `s` | Set a credential |
| `y` | Copy `export` lines for the credentials nothing has set — shown only when there are some |

**Adding a plugin to an environment is one form.** Press `n` in the pane and the editor opens on the plugin under your cursor, already pinned to its artifact, with that plugin's own configuration keys under it — `tab` completes the name, and naming a different one swaps the keys below. The form asks three things and says where each starts:

```
── how to reach it — one of these, or neither to connect directly ────
── what staging changes about it ────
```

If the plugin you added needs a credential and nothing supplies one, the credential editor is the next screen rather than somewhere to navigate back to. `esc` declines; the entry is already saved.

Switching a profile on here does the same thing `rta use` does, including the part worth remembering: while a profile is on, `rta mcp serve` refuses every other one. See [Profiles](./40-profiles.md).

## Charts

Some capabilities render as charts when there is a terminal to draw in:

```bash
rta sys cpu --cores
rta net ping example.com --graph
```

Markdown bodies — notes, `audit` findings, anything returning prose — are rendered rather than dumped.

## Untrusted plugins

If rta found an `rta-plugin-*` binary it has not been told to run, the TUI says so in a pane rather than a startup line. The line would be written to the primary buffer, and the TUI opens on the alternate one — so it would be covered before anyone could read it. The pane is the only place a person inside the TUI can learn a decision is pending.

See [Using plugins](../40-plugins/10-plugins.md#trust).

## Next

- [The CLI](./10-cli.md) — the same capabilities, scriptable
- [Profiles](./40-profiles.md) — what the `f` pane manages
