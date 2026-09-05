// Package grant is the human half of agent consent: the commands a person
// runs to allow, review and withdraw what an AI agent may do.
//
// The mechanism lives in internal/grant and is enforced in the MCP bridge,
// once, for every plugin. This package is only its face: four capabilities
// that read as a sentence — allow, list, renew, revoke.
package grant

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/this-is-tobi/rta/internal/config"
	core "github.com/this-is-tobi/rta/internal/grant"
	"github.com/this-is-tobi/rta/internal/guard"
	operatorid "github.com/this-is-tobi/rta/internal/operator"
	profiles "github.com/this-is-tobi/rta/internal/profile"
	"golang.org/x/term"

	"github.com/this-is-tobi/rta/internal/stdio"
	"github.com/this-is-tobi/rta/pkg/plugin"
	"github.com/this-is-tobi/rta/pkg/view"
)

// Plugin returns the grant plugin declaration.
//
// It takes the catalogue it governs, because this is the one plugin that is
// about the others: what may be granted is whatever the registry holds that
// needs a grant, and a hand-maintained list would be wrong the day a plugin
// is added. The accessor is lazy — the registry is still being filled when
// this is called.
func Plugin(catalog func() []plugin.Capability) plugin.Plugin {
	suggestGatedTargets := func(context.Context, plugin.Request) []string {
		var out []string
		seen := map[string]bool{}
		for _, c := range catalog() {
			if !core.Required(c, "") {
				continue
			}
			out = append(out, c.ID+"\t"+c.Summary)
			if ns := core.Namespace(c.ID); !seen[ns] {
				seen[ns] = true
				out = append(out, ns+"\tevery gated capability in "+ns)
			}
		}
		sort.Strings(out)
		return out
	}
	// The record a grant narrows to is whatever the target itself completes:
	// `rta grant allow kv.get <tab>` offers your key names because kv.get
	// says its scope is a key and how to complete one. Nothing here knows
	// what a key is.
	suggestTargetScope := func(ctx context.Context, req plugin.Request) []string {
		target := core.Normalize(req.String("target"))
		for _, c := range catalog() {
			if c.ID != target || c.Scope == "" {
				continue
			}
			for _, f := range c.Inputs {
				if f.Name == c.Scope {
					return f.Candidates(ctx, req)
				}
			}
		}
		return nil
	}
	return plugin.Plugin{
		Name:    "grant",
		Summary: "Time-boxed permissions for AI agents",
		Capabilities: []plugin.Capability{
			{
				ID: "grant.allow", Summary: "Allow AI agents to use one capability, temporarily",
				Safety: plugin.Write, Idempotent: true,
				Description: "Grants expire (15m by default, 24h maximum) and can only be issued by " +
					"a person at a terminal — an agent that could grant itself access would be no " +
					"gate at all. The target is a capability ID (kv.get) or a plugin name (kv), " +
					"which covers all of it. A second argument narrows the grant to one record: " +
					"`rta grant allow kv.get db-password` allows that key and no other. " +
					"--agent narrows it to one of your named agents, so consent given while " +
					"talking to one client does not follow every other client on this machine. " +
					"--max-uses expires the grant after that many successful calls, on top of " +
					"--ttl, whichever comes first — `--max-uses 1` for a value that should be " +
					"read exactly once. --rate bounds how fast instead of how much: " +
					"`--rate 10/1h` allows ten calls in any hour and tells the agent when to " +
					"come back, so a session that has gone wrong slows to something you can " +
					"notice rather than draining at machine speed.",
				Inputs: []plugin.Field{
					{Name: "target", Type: plugin.String, Positional: true, Required: true,
						Suggest: suggestGatedTargets,
						Help:    "capability to allow, e.g. kv.get — or a plugin name for all of it"},
					{Name: "scope", Type: plugin.String, Positional: true, Suggest: suggestTargetScope,
						Help: "narrow it to one record: a key, a task id, a hostname"},
					{Name: "profile", Type: plugin.String, Suggest: suggestConfiguredProfiles,
						Help: "narrow it to one configured connection — name/instance when an " +
							"environment holds several for this plugin"},
					{Name: "agent", Type: plugin.String, Suggest: suggestHeldAgents,
						Help: "narrow it to one named agent — the name `rta mcp serve --as` uses"},
					{Name: "ttl", Type: plugin.String, Default: "15m", Suggest: suggestTTL,
						Help: "how long it lasts: 30s, 15m, 2h"},
					{Name: "max-uses", Type: plugin.Int, Help: "expire after this many successful calls (0 = unlimited)"},
					{Name: "rate", Type: plugin.String, Suggest: suggestRate,
						Help: "how fast it may be used, as calls/window — e.g. 10/1h"},
					{Name: "note", Type: plugin.String, Help: "why — shown by grant list"},
					// One passphrase field serves both gates that can ask: the
					// local guard's, and — with --server — the operator key's.
					// Same name, same channels, same argv refusal.
					guard.PassphraseField,
					{Name: "server", Type: plugin.String, Local: true,
						Help: "issue on a remote server instead (a name from remotes.yaml): it prepares " +
							"the grant under its own policy, you sign it with your operator key"},
				},
				Run: func(ctx context.Context, req plugin.Request) (view.View, error) {
					return runAllow(ctx, req, catalog)
				},
			},
			{
				ID: "grant.renew", Summary: "Push out the deadline on grants you already have",
				Safety: plugin.Write, Idempotent: true,
				Description: "Renew extends time and nothing else. Scope, profile, use limit, uses " +
					"already spent and note are all carried forward from the stored grant — so a " +
					"renewal can never turn a one-time grant into an unlimited one, which is what " +
					"re-running `grant allow` without retyping --max-uses quietly did. The moment " +
					"of first consent is not moved either, so a chain of renewals is still capped " +
					"at 24h from when a person first said yes. With no arguments it renews every " +
					"active grant, which is the common case: the work is still going, the clock is " +
					"not.",
				Inputs: []plugin.Field{
					{Name: "target", Type: plugin.String, Positional: true, Suggest: suggestHeldTargets,
						Help: "only grants on this capability or plugin"},
					{Name: "scope", Type: plugin.String, Positional: true, Suggest: suggestHeldScopes,
						Help: "only the grant for this record"},
					{Name: "profile", Type: plugin.String, Suggest: suggestHeldProfiles,
						Help: "only grants on this connection"},
					{Name: "agent", Type: plugin.String, Suggest: suggestHeldAgents,
						Help: "only grants for this named agent"},
					{Name: "ttl", Type: plugin.String, Suggest: suggestTTL,
						Help: "how much longer — defaults to the window the grant was issued with"},
					guard.PassphraseField,
				},
				Run: runRenew,
			},
			{
				ID: "grant.list", Summary: "List what AI agents are currently allowed to do",
				Safety: plugin.Read, Idempotent: true,
				Detailed: true,
				Description: "Readable without unlocking anything, so the question stays answerable " +
					"in a hurry. Expired grants are dropped on read. With --detail: what is currently " +
					"allowed, then everything an agent can reach with no grant at all, and everything " +
					"that would need one — because \"what did I allow\" is only half of \"what can it do\". " +
					"With --server <name> (a server from remotes.yaml): the same roster read from a " +
					"remote rta server as a signed operator call, your operator key's passphrase asked " +
					"first. Can only be run by a person at a terminal, the same as grant.allow/renew/revoke: " +
					"the roster names every agent by name, which is exactly the cross-agent visibility an " +
					"agent asking about itself must not get.",
				Inputs: []plugin.Field{
					{Name: "server", Type: plugin.String, Local: true,
						Help: "read a remote server's roster instead of this machine's (a name from remotes.yaml)"},
					operatorid.PassphraseField,
				},
				Run: func(ctx context.Context, req plugin.Request) (view.View, error) {
					return runList(ctx, req, catalog)
				},
			},
			{
				ID: "grant.revoke", Summary: "Take an agent's access back", Safety: plugin.Write, Idempotent: true,
				Description: "Can only be run by a person at a terminal, the same as grant.allow and " +
					"for the same reason: consent state belongs to whoever is deciding it, not to " +
					"whoever is currently being granted or denied.",
				Inputs: []plugin.Field{
					{Name: "target", Type: plugin.String, Positional: true, Suggest: suggestHeldTargets,
						Help: "capability or plugin to revoke"},
					{Name: "scope", Type: plugin.String, Positional: true, Suggest: suggestHeldScopes,
						Help: "only the grant for this record"},
					{Name: "profile", Type: plugin.String, Suggest: suggestHeldProfiles,
						Help: "only the grant for this connection"},
					{Name: "agent", Type: plugin.String, Suggest: suggestHeldAgents,
						Help: "only the grant for this named agent"},
					{Name: "all", Type: plugin.Bool, Help: "revoke every grant"},
					{Name: "server", Type: plugin.String, Local: true,
						Help: "revoke on a remote server instead (a name from remotes.yaml), as a " +
							"signed operator call"},
					operatorid.PassphraseField,
				},
				Run: runRevoke,
			},
			{
				ID: "grant.guard.on", Summary: "Require a passphrase to issue or renew a grant",
				Safety: plugin.Write, Idempotent: true,
				Description: "Turns issuance from something any process running as you can do into " +
					"something that needs a secret only you hold: every grant is signed with a key " +
					"that exists only encrypted under the passphrase, and a grant without that " +
					"signature is not honoured. An agent that runs `rta grant allow` from a shell " +
					"is refused, however it invokes the binary — prevention for the ordinary " +
					"self-granting path, where the origin column could only detect it after the " +
					"fact. Enabling clears the grants currently held: they were issued without a " +
					"passphrase, and blessing them wholesale would launder exactly what the guard " +
					"exists to pin. Grants last a day at most, so re-issuing costs minutes. " +
					"Forgotten passphrase: remove the guard state and revoke everything — the " +
					"recovery is loud and loses at most a day of grants, never a secret.",
				Inputs: []plugin.Field{guard.PassphraseField},
				Run:    runGuardOn,
			},
			{
				ID: "grant.guard.off", Summary: "Stop requiring the guard passphrase",
				Safety: plugin.Destructive, Idempotent: true,
				Description: "Proves the passphrase first — turning the guard off is exactly what " +
					"an agent would want, so the legitimate way off costs what turning it on " +
					"promised. Clears the grants the guard signed, mirroring enable: signatures " +
					"without a guard beside them read as tampering, by design. Destructive " +
					"because it removes a protection: the confirmation is the point.",
				Inputs: []plugin.Field{guard.PassphraseField},
				Run:    runGuardOff,
			},
			{
				ID: "grant.guard.remote", Summary: "Trust remote operators to sign grants — and nothing on this machine",
				Safety: plugin.Write, Idempotent: true,
				Description: "The guard for a server whose humans are elsewhere: enrolls the public " +
					"keys from an operators roster file (the same file `rta mcp serve --operators` " +
					"reads), after which a grant is honoured only if signed by one of them — issued " +
					"from an enrolled operator's own machine over the operator channel, never from a " +
					"shell here. No key material lives on this machine at all: nothing to steal, " +
					"nothing to phish, and `rta grant allow` at this terminal is refused by " +
					"construction. Enabling clears the grants currently held, for guard-on's reason. " +
					"Run where the server runs, at provisioning time.",
				Inputs: []plugin.Field{
					{Name: "operators", Type: plugin.Path, Positional: true,
						Help: "the roster file whose keys to enroll"},
					{Name: "url", Type: plugin.String,
						Help: "this server's canonical URL, exactly as operators write it in remotes.yaml — " +
							"signed into every grant, so one issued for this server verifies on no other"},
				},
				Run: runGuardRemote,
			},
			{
				ID: "grant.guard.status", Summary: "Whether grant issuance requires the passphrase",
				Safety: plugin.Read, Idempotent: true,
				// Not on a dashboard tile redrawing on a timer: the status
				// names the verification key's fingerprint, which is worth a
				// deliberate look rather than ambient display.
				NoPreview: true,
				Description: "On or off, since when, the verification key's fingerprint, and how " +
					"many grants are held under it. Refused over MCP like every grant surface: " +
					"whether the guard stands is part of the map of what an agent could reach.",
				Run: runGuardStatus,
			},
		},
	}
}

// suggestHeldTargets completes from the grants that exist: revoking is
// something you do to a grant you already have.
func suggestHeldTargets(context.Context, plugin.Request) []string {
	grants, verr := core.Load()
	if verr != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range grants {
		if seen[g.Target] {
			continue
		}
		seen[g.Target] = true
		out = append(out, g.Target)
	}
	sort.Strings(out)
	return out
}

// suggestHeldScopes narrows to the records actually granted on that target.
//
// Filtered by profile as well as by target: a scope offered here is one the
// operator could act on, and a record granted on a connection this command is
// not about is not one of them.
func suggestHeldScopes(_ context.Context, req plugin.Request) []string {
	grants, verr := core.Load()
	if verr != nil {
		return nil
	}
	target := core.Normalize(req.String("target"))
	profile := strings.TrimSpace(req.String("profile"))
	var out []string
	for _, g := range grants {
		if g.Scope == "" || (target != "" && g.Target != target) {
			continue
		}
		if profile != "" && g.Profile != profile {
			continue
		}
		out = append(out, g.Scope)
	}
	sort.Strings(out)
	return out
}

// suggestHeldProfiles completes from the profiles that grants actually name —
// the set revoke and renew can act on.
func suggestHeldProfiles(context.Context, plugin.Request) []string {
	grants, verr := core.Load()
	if verr != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range grants {
		if g.Profile == "" || seen[g.Profile] {
			continue
		}
		seen[g.Profile] = true
		out = append(out, g.Profile)
	}
	sort.Strings(out)
	return out
}

// suggestHeldAgents completes from the grants that exist, and is used by allow
// as well as by revoke and renew.
//
// Deliberately not from a configured list, because there is no such list to
// read: an agent's name is written into whatever MCP client config the
// operator wired up — Claude's, Cursor's, a systemd unit — and rta never sees
// those files. The names it has seen are the ones it was told about, so this
// completes what has been used and never claims to enumerate what exists. The
// first grant for a new agent is typed in full, which is the honest behaviour
// for a name only the operator knows.
func suggestHeldAgents(context.Context, plugin.Request) []string {
	grants, verr := core.Load()
	if verr != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range grants {
		if g.Agent == "" || seen[g.Agent] {
			continue
		}
		seen[g.Agent] = true
		out = append(out, g.Agent)
	}
	sort.Strings(out)
	return out
}

// suggestConfiguredProfiles completes from the operator's own config, which is
// the set `grant allow` can issue against — unlike revoke and renew, which act
// on grants that already exist.
func suggestConfiguredProfiles(_ context.Context, req plugin.Request) []string {
	cfg, err := config.Load()
	if err != nil {
		return nil
	}
	target := core.Normalize(req.String("target"))
	if ns := core.Namespace(target); target != "" && ns != "" {
		// The refs a grant would accept, not just the names: an environment
		// holding several connections to this plugin completes as
		// staging/analytics beside staging, because that is the string
		// checkProfile requires — offering only the name would complete
		// straight into the instance-required refusal.
		var refs []string
		for _, name := range cfg.ProfilesFor(ns) {
			refs = append(refs, profiles.InstanceRefs(cfg.Profiles[name], name, ns)...)
		}
		if len(refs) > 0 {
			return refs
		}
	}
	return cfg.ProfileNames()
}

// checkProfile confirms a profile named on the command line exists and belongs
// to the plugin the target names.
//
// A grant that authorizes nothing is worse than an error — the same reasoning
// targetExists already applies to a mistyped capability. Here it is sharper: a
// grant naming a profile that does not exist looks identical in `grant list`
// to one that works, while every call it was meant to authorize is refused,
// and the refusal an agent reports says "needs a person's consent" for
// something the person believes they already consented to.
//
// This runs for a person at a terminal, so it names the profiles that would
// have worked. The MCP surface deliberately says nothing of the sort.
// It also returns the pin: the fingerprint of the connection being consented
// to, which is what the grant is bound to rather than the name. Taken here
// because this function has already loaded the config and already holds the
// profile, and because the pin has to describe the connection the operator is
// looking at when they decide.
func checkProfile(target, ref string) (string, string, *view.Error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", nil
	}
	cfg, err := config.Load()
	if err != nil {
		return "", "", view.AsError(err, "grant.config")
	}
	name, instance := config.SplitRef(ref)
	p, ok := cfg.Profiles[name]
	if !ok {
		return "", "", view.Errorf("grant.unknownprofile", "no profile named %q", name).
			WithHint(profileHint(cfg, core.Namespace(target)))
	}
	if !p.Trusted() {
		return "", "", view.Errorf("grant.untrustedprofile",
			"profile %q comes from a working-directory config file, so nothing honours it", name).
			WithHint("set $RTA_CONFIG to name that file deliberately, or move the profile to " +
				config.Path())
	}
	// A profile spans plugins now, so the question is whether this one says
	// anything about the target's — not whether the whole profile is that
	// plugin. Granting pg.query against an environment that has no pg entry
	// would issue a permission that can never be exercised.
	ns := core.Namespace(target)
	if ns != "" && !p.Covers(ns) {
		return "", "", view.Errorf("grant.profilemismatch",
			"profile %q says nothing about %s", name, ns).
			WithHint(profileCovers(p, name))
	}
	// One instance, exactly. Consent is a decision about a connection, and
	// "analytics, not the main database" is precisely the distinction the
	// operator minting a grant is making — so a bare name over several
	// labeled connections is refused with the refs a grant would use, never
	// resolved by sort order into a consent nobody gave.
	var (
		key  string
		conn config.Connection
	)
	switch {
	case instance != "":
		key, conn, ok = p.ForInstance(ns, instance)
		if !ok {
			return "", "", view.Errorf("grant.unknowninstance",
				"profile %q has no %s instance called %q", name, ns, instance).
				WithHint("it has: " + strings.Join(profiles.InstanceRefs(p, name, ns), ", "))
		}
	case p.Ambiguous(ns):
		return "", "", view.Errorf("grant.instancerequired",
			"profile %q holds several %s connections, and consent must name which one", name, ns).
			WithHint("one of: " + strings.Join(profiles.InstanceRefs(p, name, ns), ", "))
	default:
		key, conn, ok = p.For(ns)
	}
	if !ok {
		// Covers() just said otherwise, so this is a target with no namespace
		// at all — nothing a grant can name today, and a pin over the whole
		// profile would be the wrong answer rather than a safe one.
		return "", "", view.Errorf("grant.profilescope",
			"%q does not name a plugin, so there is no connection to grant against", target)
	}
	return ref, profiles.ConnStamp(key, conn), nil
}

func profileCovers(p config.Profile, name string) string {
	if ns := p.Namespaces(); len(ns) > 0 {
		return name + " covers " + strings.Join(ns, ", ")
	}
	return name + " covers nothing — it has no `plugins:` block"
}

func profileHint(cfg config.Config, ns string) string {
	if named := cfg.ProfilesFor(ns); ns != "" && len(named) > 0 {
		return "configured for " + ns + ": " + strings.Join(named, ", ")
	}
	if all := cfg.ProfileNames(); len(all) > 0 {
		return "configured: " + strings.Join(all, ", ")
	}
	return "no profiles are configured — see `rta profile list`"
}

func runAllow(_ context.Context, req plugin.Request, catalog func() []plugin.Capability) (view.View, error) {
	// An agent granting itself access would be no gate at all.
	if req.Surface() == plugin.SurfaceMCP {
		return nil, view.Refusef("grant.human", "grants can only be issued by a person").
			WithHint("ask the operator to run: rta grant allow <capability> --ttl 15m")
	}
	if server := req.String("server"); server != "" {
		return remoteAllow(req, server)
	}
	// Validation and construction live in buildGrant, shared with the
	// operator channel's prepare verb — the machine whose config, policy and
	// catalogue bind is the machine that builds the grant, whichever flow
	// asked. From is measured here because it is the one input the shared
	// builder must not guess: stdio.Real rather than os.Stdin, for the
	// reason builtin/kv records — after main takes fd 0 away from the
	// plugins it spawns, os.Stdin is /dev/null and every run would read as
	// unattended.
	g, notes, verr := buildGrant(catalog, operatorid.IssueSpec{
		Target:  req.String("target"),
		Scope:   req.String("scope"),
		Profile: req.String("profile"),
		Agent:   req.String("agent"),
		TTL:     req.String("ttl"),
		Note:    req.String("note"),
		MaxUses: req.Int("max-uses"),
		Rate:    req.String("rate"),
	}, core.Origin(req.Surface(), term.IsTerminal(int(stdio.Real().Fd()))))
	if verr != nil {
		return nil, verr
	}
	ttl := notes.ttl
	// The ceiling before the passphrase: a target the team policy forbids
	// is refused before anybody types anything, not after.
	if verr := core.CheckCeiling(g.Target, g.Scope, g.Profile); verr != nil {
		return nil, verr
	}
	// The guard, before anything is written: prove the passphrase, sign the
	// authority. After the Grant is fully built — the signature covers the
	// struct as issued, and signing a draft that a later field-set would
	// silently invalidate is the bug this ordering forbids.
	if !req.DryRun && guard.Enabled() {
		signer, verr := guard.UnlockPrompted(req)
		if verr != nil {
			return nil, verr
		}
		core.SignWith(signer, &g)
	}
	// Reading the file and replacing it used to be two unlocked steps here,
	// which is how a revoke issued in between got written back out. The
	// replace-equivalent rule itself now lives in core.Issue, shared with
	// the consent prompt that can also issue one.
	if verr := core.Issue(g, !req.DryRun); verr != nil {
		return nil, verr
	}
	if req.DryRun {
		note := ""
		if guard.Enabled() {
			note = " — the guard will ask for its passphrase"
		}
		return view.Text{Body: fmt.Sprintf("would allow agents to %s for %s%s%s%s",
			describe(g), ttl, usesSuffix(g.MaxUses), rateSuffix(g), note)}, nil
	}
	msg := fmt.Sprintf("agents may %s for %s (until %s)%s%s",
		describe(g), ttl, g.Expires.Format("15:04:05"), usesSuffix(g.MaxUses), rateSuffix(g))
	// Which ceiling bit, and whether the environment this names is even
	// switched on: worded by cappedNote and inactiveProfileNote, shared with
	// the operator channel's prepare verb so the remote flow warns in the
	// same sentences. Said here because the operator has just spent a
	// command — the clock is running, and a 15-minute grant issued and then
	// noticed is most of a grant wasted.
	if n := cappedNote(notes); n != "" {
		msg += "\n" + n
	}
	if n := inactiveProfileNote(g); n != "" {
		msg += "\n" + n
	}
	return view.Text{Body: msg}, nil
}

// usesSuffix renders the use-count half of a grant's lifetime, when there is
// one to mention — most grants have no limit, and saying nothing beats
// saying "unlimited" on every single one.
func usesSuffix(maxUses int) string {
	if maxUses <= 0 {
		return ""
	}
	if maxUses == 1 {
		return ", or once, whichever comes first"
	}
	return fmt.Sprintf(", or %d uses, whichever comes first", maxUses)
}

// parseRate reads "10/1h" — how many calls, over what window.
//
// One argument rather than two because the two halves are meaningless
// apart: "10" is not a rate and neither is "1h", and a pair of flags is a
// pair somebody sets one of.
func parseRate(raw string) (int, string, *view.Error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, "", nil
	}
	bad := func(why string) *view.Error {
		return view.Errorf("grant.badrate", "%q is not a rate: %s", raw, why).
			WithHint("write it as calls/window — 10/1h, 1/30s, 100/24h")
	}
	n, window, ok := strings.Cut(raw, "/")
	if !ok {
		return 0, "", bad("it needs a window, after a slash")
	}
	calls, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil || calls <= 0 {
		return 0, "", bad("the number of calls has to be a positive whole number")
	}
	if calls > core.MaxRate {
		return 0, "", bad(fmt.Sprintf("the most rta will pace is %d calls a window — "+
			"past that it is not slowing anything down", core.MaxRate))
	}
	window = strings.TrimSpace(window)
	d, err := time.ParseDuration(window)
	if err != nil || d <= 0 {
		return 0, "", bad("the window has to be a duration: 30s, 1h, 24h")
	}
	// A window longer than a grant can live is a limit that never refills,
	// which is --max-uses wearing a different hat and worth saying so.
	if d > core.MaxTTL {
		return 0, "", bad(fmt.Sprintf("a window longer than the %s a grant can live is "+
			"--max-uses %d in disguise", core.MaxTTL, calls))
	}
	return calls, window, nil
}

// rateSuffix says the pace, when there is one.
func rateSuffix(g core.Grant) string {
	if g.RateMax <= 0 || g.RateWindow == "" {
		return ""
	}
	return fmt.Sprintf(", no faster than %d %s per %s",
		g.RateMax, plural(g.RateMax, "call", "calls"), g.RateWindow)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// suggestRate offers the paces worth typing, rather than leaving somebody to
// discover the format from an error message.
func suggestRate(context.Context, plugin.Request) []string {
	return []string{
		"1/1m	one call a minute",
		"10/1h	ten calls an hour",
		"60/1h	a call a minute, averaged",
		"100/24h	a hundred calls a day",
	}
}

// targetExists reports whether target names a real capability ID or a
// plugin namespace with at least one capability registered under it — the
// two forms grant.allow's own target field accepts.
func targetExists(catalog func() []plugin.Capability, target string) bool {
	for _, c := range catalog() {
		if c.ID == target || core.Namespace(c.ID) == target {
			return true
		}
	}
	return false
}

// parseTTL reads the requested lifetime and caps it.
//
// byPolicy and where are core.ClampTTL's own verdict, computed here against
// the same min(parsed, core.MaxTTL) that decides ttl — not left for a caller
// to re-derive from the raw ask afterwards. A caller that re-asked the
// question against `asked` instead of reusing this answer could disagree
// with what was actually stored: rta's own day can already be the tighter of
// the two ceilings, in which case the policy ceiling never even applies, and
// checking the raw ask against it in isolation reports it as the cause
// anyway.
func parseTTL(raw, target string) (ttl, asked time.Duration, byPolicy bool, where string, verr *view.Error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return core.DefaultTTL, core.DefaultTTL, false, "", nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, 0, false, "", view.Errorf("grant.badttl", "%q is not a duration: %v", raw, err).
			WithHint("use a Go duration: 30s, 15m, 2h")
	}
	if parsed <= 0 {
		return 0, 0, false, "", view.Errorf("grant.badttl", "a grant must last longer than zero").
			WithHint("to take access away, use: rta grant revoke " + target)
	}
	// Two ceilings, and the tighter one wins: rta's own day, and whatever the
	// team's policy file says.
	capped, byPolicy, where := core.ClampTTL(min(parsed, core.MaxTTL))
	return capped, parsed, byPolicy, where, nil
}

// suggestTTL offers the windows a grant is usually given, up to the ceiling
// parseTTL enforces.
//
// Suggest rather than Options, because a duration stays free text: somebody
// who wants 90m should be able to type it. What this removes is the pause to
// work out what the spelling is and what the maximum is — on the surface where
// an operator is deciding how long an agent keeps something, which is the
// wrong moment to be guessing.
// Written as the strings somebody types, not as core.DefaultTTL.String(),
// which renders 15 minutes as "15m0s" and a day as "24h0m0s" — accepted by
// ParseDuration and typed by nobody. TestTheOfferedWindowsMatchTheRealBounds
// keeps them honest against the constants.
func suggestTTL(context.Context, plugin.Request) []string {
	return []string{
		"30s\tone call, more or less",
		"5m\ta quick job",
		"15m\tthe default",
		"1h\ta task",
		"4h\tan afternoon",
		"24h\tthe most a grant can last",
	}
}

// describe says what a grant allows, in the words the person used.
func describe(g core.Grant) string {
	s := "call " + g.Target
	switch {
	case core.IsFolderScope(g.Scope):
		// Said differently from an exact scope on purpose. "on prod/" reads
		// like one record with an odd name; this grant covers every record
		// under it, including ones that do not exist yet, and the operator is
		// agreeing to that rather than to what a listing shows today.
		s += " on any record under " + g.Scope
	case g.Scope != "":
		s += " on " + g.Scope
	}
	if g.Profile != "" {
		s += " via profile " + g.Profile
	}
	// Last, because it is the subject rather than the object: the sentence
	// reads "call kv.get on prod/ via profile staging, as agent ci". Said at
	// all because a grant that names an agent authorizes strictly less than
	// one that does not, and an operator re-reading their own consent has to
	// be able to see which they gave.
	if g.Agent != "" {
		s += ", as agent " + g.Agent
	}
	return s
}

// runRenew extends the deadline on grants that already exist, and changes
// nothing else about them.
//
// It exists because "renewing" was re-running `grant allow`, and that is not a
// renewal — it builds a fresh grant from the flags of *this* invocation. A
// person extending a `--max-uses 1` grant without retyping the flag converted
// it to unlimited and reset the uses already spent, so the grant that was
// meant to reveal one secret once could reveal it again, and again. Nothing
// said so; `grant list` showed a healthy row.
//
// Issued is deliberately not moved. Active() already tests
// now.Before(Issued.Add(MaxTTL)) on every read, so leaving it alone caps any
// chain of renewals at 24h from the moment a person first said yes — the
// ceiling survives for free, and consent cannot be made perpetual one quarter
// hour at a time.
func runRenew(_ context.Context, req plugin.Request) (view.View, error) {
	if req.Surface() == plugin.SurfaceMCP {
		return nil, view.Refusef("grant.human", "grants can only be renewed by a person").
			WithHint("ask the operator to run: rta grant renew")
	}
	target := core.Normalize(req.String("target"))
	scope := strings.TrimSpace(req.String("scope"))
	profile := strings.TrimSpace(req.String("profile"))
	agent := strings.TrimSpace(req.String("agent"))
	askedTTL := strings.TrimSpace(req.String("ttl"))

	var ttl time.Duration
	if askedTTL != "" {
		var verr *view.Error
		ttl, _, _, _, verr = parseTTL(askedTTL, target)
		if verr != nil {
			return nil, verr
		}
	}

	now := time.Now()
	var renewed []string
	var stale []string
	var capped bool
	teamCeiling, verr := core.Ceiling()
	if verr != nil {
		return nil, verr
	}
	// Read once, outside the lock, for the staleness note below. A config that
	// cannot be read costs the note and nothing else.
	cfg, cfgErr := config.Load()
	seenStale := map[string]bool{}
	// The guard: renewing extends authority, so it costs the passphrase
	// exactly as issuing does. Unlocked out here — prompting inside a locked
	// Mutate would hold the grant lock across a human's typing speed — and a
	// dry run declines the write below, so it asks for nothing.
	var signer *guard.Signer
	if !req.DryRun && guard.Enabled() {
		s, verr := guard.UnlockPrompted(req)
		if verr != nil {
			return nil, verr
		}
		signer = &s
	}
	if verr := core.Mutate(func(stored []core.Grant) ([]core.Grant, bool) {
		renewed = nil
		stale = nil
		clear(seenStale)
		capped = false
		for i := range stored {
			g := stored[i]
			// Only what is still standing. A spent or expired grant is a fresh
			// decision, not an extension of one — that is `grant allow`.
			if !g.Active(now) {
				continue
			}
			// The same selector as revoke: a plugin name takes every grant
			// inside it. `renew kv` used to match nothing while `revoke kv`
			// took them all.
			if target != "" && g.Target != target && core.Namespace(g.Target) != target {
				continue
			}
			if scope != "" && g.Scope != scope {
				continue
			}
			if profile != "" && g.Profile != profile {
				continue
			}
			if agent != "" && g.Agent != agent {
				continue
			}
			window := ttl
			if window == 0 {
				window = g.Window()
			}
			expires := now.Add(window)
			// The ceiling, applied here so the message can say it happened.
			// Active() would enforce it regardless; what it cannot do is
			// tell somebody why their grant died earlier than they asked.
			// The team's ceiling counts from first consent exactly as the
			// absolute one does, and Load drops the grant there: renew used
			// to print a deadline past it and never say the ceiling bit.
			limit := core.MaxTTL
			if teamCeiling.MaxTTL > 0 && teamCeiling.MaxTTL < limit {
				limit = teamCeiling.MaxTTL
			}
			if ceiling := g.Issued.Add(limit); expires.After(ceiling) {
				expires, capped = ceiling, true
			}
			// The deadline, and nothing else. **ProfilePin is deliberately not
			// touched**, and its absence here is load-bearing: a renewal that
			// adopted the current connection would let an operator extend a
			// grant straight onto an environment somebody repointed in the
			// meantime, without ever seeing the connection they were agreeing
			// to. Re-consenting to a changed connection is a fresh decision,
			// which is `rta grant allow`.
			stored[i].Expires = expires
			if askedTTL != "" {
				stored[i].TTL = askedTTL
			}
			// A renewal rewrites signed authority — the deadline — so the
			// extended grant is re-signed under the same locked write, or
			// loadAll would refuse the whole file as forged on the next read.
			if signer != nil {
				core.SignWith(*signer, &stored[i])
			}
			renewed = append(renewed, fmt.Sprintf("  %-24s until %s", describe(g), expires.Format("15:04:05")))
			// A renewal is the only person-facing surface that reports
			// per-grant success, and it was the only one silent about a grant
			// whose connection has been repointed: `grant list` marks it
			// (changed) and `doctor` warns, while this printed a fresh
			// deadline on a grant that authorizes nothing. The operator walks
			// away believing they re-confirmed consent and learns otherwise
			// from an agent's refusal — which is checkProfile's own named
			// failure, one command over.
			if cfgErr == nil && !seenStale[g.Profile] &&
				g.Stale(profiles.ConnStampFor(cfg, g.Profile, core.Namespace(g.Target))) {
				seenStale[g.Profile] = true
				stale = append(stale, g.Profile)
			}
		}
		return stored, len(renewed) > 0 && !req.DryRun
	}); verr != nil {
		return nil, verr
	}
	if len(renewed) == 0 {
		return view.Text{Body: "Nothing to renew — no matching grant is active."}, nil
	}
	verb := "renewed"
	if req.DryRun {
		verb = "would renew"
	}
	body := fmt.Sprintf("%s %d grant(s):\n%s", verb, len(renewed), strings.Join(renewed, "\n"))
	if len(stale) > 0 {
		body += fmt.Sprintf("\nnote: %d of these name a connection that has changed since it was "+
			"issued (%s), so the deadline moved and they still authorize nothing — "+
			"`rta grant allow` re-consents to the connection as it is now",
			len(stale), strings.Join(stale, ", "))
	}
	if capped {
		body += fmt.Sprintf("\ncapped at the %s maximum from first consent — "+
			"`rta grant allow` starts a new window, which is a fresh decision", core.MaxTTL)
	}
	return view.Text{Body: body}, nil
}

func runList(ctx context.Context, req plugin.Request, catalog func() []plugin.Capability) (view.View, error) {
	// The same rule grant.allow/renew/revoke already follow, for the reading
	// side of it: the roster names every agent's grants, by name, which is
	// exactly the cross-caller visibility an agent must not get from asking —
	// a capability handler has no notion of "which agent is calling" to
	// filter it down to (Request carries a Surface, not an identity), and
	// this is the file consent state belongs to whoever is deciding it, not
	// to whoever is currently allowed or denied.
	if req.Surface() == plugin.SurfaceMCP {
		return nil, view.Refusef("grant.human", "the grant roster is for the person deciding it, not the agents it is about").
			WithHint("ask the operator to run: rta grant list")
	}
	if server := req.String("server"); server != "" {
		return remoteList(req, server)
	}
	held, verr := heldTable()
	if verr != nil {
		return nil, verr
	}
	if !req.Bool("detail") {
		return held, nil
	}
	// "What did I allow" is only half of "what can an agent do here". The
	// other half is what needs no allowing, and the page is only useful if
	// both are derived from the catalogue rather than written down again —
	// a list maintained by hand goes stale exactly when a capability is
	// added, which is the moment somebody most wants to read it.
	p := plugin.NewPage(ctx, req)
	p.PutAs("granted", "granted", held)
	for _, tier := range reachTiers {
		p.PutAs(tier.id, tier.title, reachTable(catalog(), tier.holds))
	}
	return p.View(), nil
}

// reachTiers name the three ways an agent's access is decided, in widening
// order of what it takes to get there. They are distinct gates, not degrees
// of one: --allow-write is an operator's decision made once when the server
// is launched, a grant is a person's decision made per record and per
// quarter-hour. Folding them into one "not granted" bucket would read as if
// a write were as freely reachable as a read.
var reachTiers = []struct {
	// id is what a script or an agent addresses the section by; title is
	// what a person reads. One string doing both jobs made every wording
	// improvement a silent break for whoever had scripted the old one —
	// see view.Section.
	id, title string
	holds     func(plugin.Capability) bool
}{
	{"default", "reachable by default", func(c plugin.Capability) bool {
		return !core.Required(c, "") && c.Safety == plugin.Read
	}},
	{"allow-write", "needs --allow-write on the server", func(c plugin.Capability) bool {
		return !core.Required(c, "") && c.Safety != plugin.Read
	}},
	{"grant", "needs a grant a person issues", func(c plugin.Capability) bool {
		return core.Required(c, "")
	}},
}

// reachTable lists the capabilities in one tier.
func reachTable(caps []plugin.Capability, holds func(plugin.Capability) bool) view.View {
	t := view.Table{Columns: []view.Column{
		{Name: "Capability"},
		{Name: "Safety", Kind: view.KindStatus},
		{Name: "Per-record"},
		{Name: "Summary"},
	}}
	for _, c := range caps {
		if !holds(c) {
			continue
		}
		record := "no"
		if c.Scope != "" {
			record = c.Scope
		}
		t.Rows = append(t.Rows, []string{c.ID, string(c.Safety), record, c.Summary})
	}
	sort.Slice(t.Rows, func(i, j int) bool { return t.Rows[i][0] < t.Rows[j][0] })
	t.Total = len(t.Rows)
	return t
}

func heldTable() (view.View, *view.Error) {
	grants, verr := core.Load()
	if verr != nil {
		return nil, verr
	}
	if len(grants) == 0 {
		body := "No active grants — AI agents can only read.\n" +
			"Allow one with: rta grant allow <capability> --ttl 15m"
		// An empty list is the ordinary answer and a dropped file is not, so
		// the difference has to be visible here: this is the one screen where
		// somebody looking for a grant they issued will come looking for it.
		if core.Legacy() {
			body = "No active grants — AI agents can only read.\n\n" +
				"Grants are now sealed against tampering, and " + core.Path() + " predates\n" +
				"the seal, so nothing in it is honoured. Any grant it held is gone; re-issue\n" +
				"what you still need. Removing the file clears this notice:\n" +
				"  rm " + core.Path() + "\n\n" +
				"Allow one with: rta grant allow <capability> --ttl 15m"
		}
		// Same reasoning as the line above, one cause along: a grant that is
		// on disk and suppressed by the team's ceiling is not "no grant", and
		// somebody certain they issued one has to be told why it is not here.
		if n := core.Suppressed(); n > 0 {
			body += suppressedNote(n)
		}
		return view.Text{Body: body}, nil
	}
	cfg, cfgErr := config.Load()
	t := grantsTable(grants, func(g core.Grant) bool {
		// A grant whose connection has been repointed since it was issued is
		// still a row, and it is the row somebody most needs to see: it looks
		// live, it is listed, and every call it was issued for is refused.
		//
		// **This is where the remedy belongs.** The MCP refusal is deliberately
		// the same sentence an ungranted call gets — telling an agent "this
		// profile changed since you were granted" would disclose both that the
		// profile exists and that consent was once given for it — so the person
		// has to be able to find out here instead.
		return cfgErr == nil && g.Stale(profiles.ConnStampFor(cfg, g.Profile, core.Namespace(g.Target)))
	})
	// A partial suppression is the confusing one: some rows are here, the one
	// being looked for is not, and nothing on the screen accounts for it.
	if n := core.Suppressed(); n > 0 {
		return view.Sections{Items: []view.Section{
			{ID: "grants", Title: "Allowed", View: t},
			{ID: "policy", Title: "Your team's policy",
				View: view.Text{Body: strings.TrimPrefix(suppressedNote(n), "\n\n")}},
		}}, nil
	}
	return t, nil
}

// grantsTable renders grant rows, wherever they came from — this machine's
// store or a remote server's answer. stale reports whether a row's
// connection changed under it; the remote path passes nil, because
// staleness is judged against the server's config and the server already
// judged it by the same rule when it loaded the rows.
func grantsTable(grants []core.Grant, stale func(core.Grant) bool) view.Table {
	// The Agent column appears only once something has one, and that is the
	// point rather than a saving. An operator who has never named an agent has
	// exactly one principal, so a column of em dashes answers a question they
	// do not have — the failure budgetLeft below is written against. The
	// moment they name one, the column's arrival is itself the news: there is
	// now more than one caller, and which one a grant is for is the most
	// important thing on the row.
	named := false
	for _, g := range grants {
		if g.Agent != "" {
			named = true
			break
		}
	}
	// The Origin column follows the Agent column's rule and for a sharper
	// version of its reason: it appears only when a grant was issued with
	// nobody at the terminal, so the column's arrival *is* the finding. On a
	// machine where every grant was typed by the operator it never shows up,
	// and the day one was not, a column appears saying which.
	//
	// Not a warning, because all three of the things that issue one
	// unattended — a provisioning script, a CI job, an agent's shell tool —
	// are legitimate, and only the operator knows which of them ran.
	unwatched := false
	for _, g := range grants {
		if g.From == core.FromCommand || strings.HasPrefix(g.From, core.FromOperatorPrefix) {
			unwatched = true
			break
		}
	}
	t := view.Table{Columns: []view.Column{
		{Name: "Capability"},
		// Which connection this grant is about. Without it the operator cannot
		// see what they consented to: two grants on the same capability, one for
		// staging and one for production, render as identical rows — and the
		// screen whose entire job is "what is the agent allowed to do right
		// now?" answers a question narrower than the one it was asked.
		{Name: "Profile"},
		{Name: "Record"},
		{Name: "Expires In", Kind: view.KindDuration},
		{Name: "Budget Left"},
		{Name: "Note"},
	}}
	if unwatched {
		t.Columns = slices.Insert(t.Columns, 3, view.Column{Name: "Origin"})
	}
	if named {
		t.Columns = slices.Insert(t.Columns, 2, view.Column{Name: "Agent"})
	}
	now := time.Now()
	for _, g := range grants {
		record := g.Scope
		if record == "" {
			record = "any"
		}
		if core.IsFolderScope(g.Scope) {
			// The width has to be legible in the one screen whose job is
			// "what may the agent do right now?". A bare "prod/" in a column
			// headed Record reads as one record with a trailing slash, which
			// is the opposite of what it authorizes.
			record = g.Scope + " (all)"
		}
		// An em dash rather than the word "any", deliberately: the Record column
		// one place over already uses "any" for the opposite meaning, and an
		// empty profile is not a wildcard — it is the base connection and
		// nothing else.
		connection := g.Profile
		if connection == "" {
			connection = "—"
		}
		if stale != nil && stale(g) {
			connection += " (changed)"
		}
		row := []string{
			g.Target,
			connection,
			record,
			g.Expires.Sub(now).Round(time.Second).String(),
			budgetLeft(g, now),
			g.Note,
		}
		if unwatched {
			row = slices.Insert(row, 3, originLabel(g))
		}
		if named {
			// An em dash for the same reason the Profile column uses one: an
			// empty agent is not a wildcard. It is the server launched without
			// a name, and beside a row that names one the difference is
			// exactly what the operator needs to see.
			who := g.Agent
			if who == "" {
				who = "—"
			}
			row = slices.Insert(row, 2, who)
		}
		t.Rows = append(t.Rows, row)
	}

	t.Total = len(t.Rows)
	return t
}

// suppressedNote accounts for grants the ceiling is holding back, so that
// "where did my grant go" has an answer on the screen where it is asked.
func suppressedNote(n int) string {
	where := ""
	if c, verr := core.Ceiling(); verr == nil {
		where = " — " + c.Where()
	}
	return fmt.Sprintf("\n\n%d grant(s) on disk are suppressed by your team's policy%s\n"+
		"They are not deleted: relaxing the policy brings them back, and "+
		"`rta doctor` says what it forbids.", n, where)
}

// budgetLeft is the one cell that answers "how much of this is left", across
// both kinds of budget a grant can carry.
//
// One column rather than two: a grant almost never carries both, and a table
// with an "unlimited" in every row of a column nobody uses is a table people
// stop reading across. When it does carry both, they are separated by a
// comma and the reader can see which bites first.
func budgetLeft(g core.Grant, now time.Time) string {
	var parts []string
	if g.MaxUses > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d uses", g.MaxUses-g.Uses, g.MaxUses))
	}
	if room, next, limited := g.RateRoom(now); limited {
		switch {
		case room > 0:
			parts = append(parts, fmt.Sprintf("%d of %d per %s", room, g.RateMax, g.RateWindow))
		case next.IsZero():
			parts = append(parts, "paced, and the window will not parse")
		default:
			parts = append(parts, fmt.Sprintf("paced out, %s to go",
				time.Until(next).Truncate(time.Second)))
		}
	}
	if len(parts) == 0 {
		return "unlimited"
	}
	return strings.Join(parts, ", ")
}

func runRevoke(_ context.Context, req plugin.Request) (view.View, error) {
	// The same reasoning as runAllow's, the other direction: an agent that
	// can freely erase grants can silently take back its own restriction, or
	// somebody else's mid-task — and the operator's `grant list` is supposed
	// to be a reliable record of what they decided, not something an agent
	// can rewrite. Consent state belongs to the person at the terminal in
	// both directions, not to whoever is currently being granted or denied.
	if req.Surface() == plugin.SurfaceMCP {
		return nil, view.Refusef("grant.human", "grants can only be revoked by a person").
			WithHint("ask the operator to run: rta grant revoke <capability>")
	}
	if server := req.String("server"); server != "" {
		return remoteRevoke(req, server)
	}
	spec := operatorid.RevokeSpec{
		All:     req.Bool("all"),
		Target:  core.Normalize(req.String("target")),
		Scope:   strings.TrimSpace(req.String("scope")),
		Profile: strings.TrimSpace(req.String("profile")),
		Agent:   strings.TrimSpace(req.String("agent")),
	}
	if !spec.All && spec.Target == "" && spec.Profile == "" && spec.Agent == "" {
		return nil, view.Errorf("grant.notarget", "name a capability, or pass --all").
			WithHint("run `rta grant list` to see what is currently allowed")
	}
	// The matching rules and the locked-snapshot discipline live in
	// revokeOutcome, shared with the operator channel's revoke verb; the
	// sentences live in revokeBody, shared with the remote flow's rendering.
	out, verr := revokeOutcome(spec, !req.DryRun)
	if verr != nil {
		return nil, verr
	}
	return view.Text{Body: revokeBody(spec.Target, out, req.DryRun)}, nil
}

// originLabel is how a grant says where it came from.
//
// An em dash for a grant sealed before the field existed, and never the word
// "command": unknown and unattended are different facts, and a display that
// conflated them would accuse an old grant of something it did not do.
func originLabel(g core.Grant) string {
	switch g.From {
	case core.FromForm:
		return "form"
	case core.FromTerminal:
		return "terminal"
	case core.FromCommand:
		return "command"
	}
	// A remote operator's grant carries its issuer: "operator:tobi" is the
	// attribution the roster promised, shown whole because on a
	// multi-operator server *which* operator is the point of the column.
	if strings.HasPrefix(g.From, core.FromOperatorPrefix) {
		return g.From
	}
	return "—"
}
