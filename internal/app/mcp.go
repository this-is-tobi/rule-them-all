package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	agentcap "github.com/this-is-tobi/rta/builtin/agent"
	grantcap "github.com/this-is-tobi/rta/builtin/grant"
	"github.com/this-is-tobi/rta/builtin/kv"
	"github.com/this-is-tobi/rta/internal/agentlog"
	"github.com/this-is-tobi/rta/internal/config"
	"github.com/this-is-tobi/rta/internal/consent"
	"github.com/this-is-tobi/rta/internal/grant"
	grantguard "github.com/this-is-tobi/rta/internal/guard"
	"github.com/this-is-tobi/rta/internal/mcp"
	"github.com/this-is-tobi/rta/internal/notify"
	"github.com/this-is-tobi/rta/internal/operator"
	"github.com/this-is-tobi/rta/internal/pathguard"
	"github.com/this-is-tobi/rta/internal/registry"
	agentsession "github.com/this-is-tobi/rta/internal/session"
	"github.com/this-is-tobi/rta/internal/stdio"
	"github.com/this-is-tobi/rta/pkg/plugin"
)

// newMCPCommand wires the MCP surface: serve (stdio) and install helpers.
func newMCPCommand(reg *registry.Registry, version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "mcp",
		Short: "Expose capabilities to AI agents over the Model Context Protocol",
		RunE:  groupRunE,
	}
	root.AddCommand(newMCPServeCommand(reg, version))
	root.AddCommand(newMCPInstallCommand())
	return root
}

func newMCPServeCommand(reg *registry.Registry, version string) *cobra.Command {
	var (
		consentOn        bool
		consentWait      time.Duration
		consentNotify    bool
		consentPreview   bool
		allowWrite       []string
		allowDestructive []string
		agentName        string
		roots            []string
		httpAddr         string
		tokenFile        string
		oidcIssuer       string
		oidcAudience     string
		oidcSubjects     []string
		operatorsFile    string
		operatorsURL     string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve capabilities as MCP tools, over stdio or HTTP",
		Long: "Serve every registered capability as an MCP tool, over stdio by default\n" +
			"or over HTTP with --http.\n\n" +
			"Safety gate: only read capabilities are exposed by default.\n" +
			"Use --allow-write for write capabilities, and --allow-destructive\n" +
			"with explicit capability IDs for destructive ones.\n\n" +
			"Path gate: every path argument must be under a root, including a\n" +
			"capability's own declared default. The default root is the directory\n" +
			"the server was started in; widen it with --root, which is repeatable.\n" +
			"The gate governs path arguments only: a capability that opens a fixed\n" +
			"file of its own — `net hosts list` and /etc/hosts — is unaffected,\n" +
			"because that path is never an argument for anyone to send.\n\n" +
			"Locality gate, --http only: capabilities that describe the machine\n" +
			"this runs on (sys, fs, git, keys.list, net's host-identity and\n" +
			"host-mutation calls) are absent from tools/list — a remote caller is\n" +
			"never this machine. --http also requires --token-file or --oidc-issuer\n" +
			"(or both), since there is no stdio parent process left to trust instead.",
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Both of these are said once, at startup, on stderr — which under
			// a client is the server's log. A flag that silently does nothing
			// is worse than a missing feature: the operator believes they are
			// covered, and the way they find out is by not being asked.
			if consentNotify && !consentOn {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"rta: --consent-notify does nothing without --consent, since nothing parks to ring about")
			}
			if consentNotify && !notify.Available() {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"rta: no desktop notifier here, so parked calls will only appear in `rta agent pending`")
			}
			if len(roots) == 0 {
				// The directory the operator started the server in. It is what
				// an MCP client passes as cwd, so it is the project the agent
				// was pointed at — and choosing it by default means the gate
				// is on for everybody rather than for whoever read the flag.
				wd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("resolving the default root: %w", err)
				}
				roots = []string{wd}
			}
			guard, err := pathguard.New(roots...)
			if err != nil {
				return err
			}
			// The operator's connections, for the tool schema. Loaded through
			// config.Load — the same file every other surface reads — so a
			// profile an agent may name is one the operator wrote. The schema
			// is sent once, so this is a snapshot; what a call actually
			// resolves through is Reload, below.
			//
			// A config that will not parse is not fatal here. It costs the
			// agent every profile, which is the fail-closed direction: the
			// server still serves the base connection, and `rta doctor` is
			// where the operator finds out why nothing else worked.
			profileCfg, cfgErr := config.Load()
			if cfgErr != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "rta: no profiles are available:", cfgErr)
				profileCfg = config.Config{}
			}
			// Refused here, by the same function `rta grant allow --agent`
			// uses. A server that accepted a name the grant command rejects
			// could never be granted anything and would say so nowhere — the
			// operator would issue grants that silently never match.
			if verr := grant.CheckAgent(agentName); verr != nil {
				return verr
			}
			if httpAddr == "" && tokenFile != "" {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"rta: --token-file does nothing without --http, since nothing is listening for a bearer token to guard")
			}
			if httpAddr == "" && oidcIssuer != "" {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"rta: --oidc-issuer does nothing without --http, since nothing is listening for a bearer token to guard")
			}
			if httpAddr == "" && operatorsFile != "" {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"rta: --operators does nothing without --http — at this terminal you already are the operator")
			}
			if oidcIssuer == "" && (oidcAudience != "" || len(oidcSubjects) > 0) {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"rta: --oidc-audience/--oidc-subject do nothing without --oidc-issuer, since there is no token to verify them against")
			}
			// The HTTP transport's own gate, checked before anything else it
			// needs is built: a caller proves who it is over the wire here,
			// where stdio has only ever had "whoever the operator's shell
			// launched". There is no path through this command that opens the
			// listener without at least one verifier — refusing early says so
			// plainly instead of failing later inside net/http with a less
			// legible error.
			var (
				verifier        auth.TokenVerifier
				ln              net.Listener
				operatorHandler http.Handler
			)
			if httpAddr != "" {
				// A parked call needs a person positioned to answer it. Over
				// HTTP that person is an enrolled operator answering through
				// the channel — `rta agent allow <id> --server <name>` — so
				// --consent stands or falls with --operators: without a
				// roster there is still nobody to reach, and a control nobody
				// can exercise must not be allowed to pretend it works (the
				// same rule ConsentNotify follows one flag over).
				if consentOn && operatorsFile == "" {
					return fmt.Errorf("--consent over --http needs --operators: a parked call waits " +
						"for a person, and enrolled operators answering with `rta agent allow --server` " +
						"are the only people positioned to; see \"The operator channel\" in docs/30-boundary/20-mcp.md")
				}
				if tokenFile == "" && oidcIssuer == "" {
					return fmt.Errorf("--http needs a way to verify who is calling: pass --token-file or --oidc-issuer")
				}
				// Bound before anything else that follows does real I/O of its
				// own — reading the token file, an OIDC discovery round trip to
				// a remote issuer — so a taken port or a bad address is always
				// the first thing an operator sees, never a wait behind a slow
				// or unresponsive issuer. The banner below then reports the
				// address actually bound, which is the real one rather than the
				// ":0" an operator or a test asked for.
				var err error
				ln, err = net.Listen("tcp", httpAddr)
				if err != nil {
					return fmt.Errorf("--http: %w", err)
				}
				// net/http's Serve always closes the listener it is handed, so
				// this is a no-op on the path that reaches it below — it exists
				// for every path that returns before then, once the bind above
				// has already succeeded.
				defer func() { _ = ln.Close() }()
				var verifiers []auth.TokenVerifier
				if tokenFile != "" {
					tokens, groupReadable, err := mcp.LoadTokenFile(tokenFile)
					if err != nil {
						return fmt.Errorf("--token-file: %w", err)
					}
					if groupReadable {
						fmt.Fprintf(cmd.ErrOrStderr(),
							"rta: %s is group-readable — anyone in that group can authenticate as every label it holds\n",
							tokenFile)
					}
					if runtime.GOOS == "windows" {
						fmt.Fprintf(cmd.ErrOrStderr(),
							"rta: %s's permissions were not checked — rta cannot read NTFS ACLs on Windows; "+
								"make sure only you can read, write or execute it before relying on it as a trust anchor\n",
							tokenFile)
					}
					verifiers = append(verifiers, mcp.StaticTokenVerifier(tokens))
				}
				if oidcIssuer != "" {
					if oidcAudience == "" {
						return fmt.Errorf("--oidc-issuer needs --oidc-audience")
					}
					if len(oidcSubjects) == 0 {
						return fmt.Errorf("--oidc-issuer needs at least one --oidc-subject — " +
							"an issuer and audience alone identify an application, not a person")
					}
					oidcVerifier, err := mcp.OIDCVerifier(cmd.Context(), oidcIssuer, oidcAudience, oidcSubjects, cmd.ErrOrStderr())
					if err != nil {
						return fmt.Errorf("--oidc-issuer: %w", err)
					}
					verifiers = append(verifiers, oidcVerifier)
				}
				verifier = mcp.Compose(cmd.ErrOrStderr(), verifiers...)
				if operatorsFile != "" {
					// The canonical URL is required, not defaulted: it is the
					// identity every operator signature is checked against, and
					// nothing this process can observe — not the bind address,
					// not a Host header a relay would forge — is trustworthy to
					// derive it from. The operators' remotes.yaml and this flag
					// must carry the same string; that agreement is the
					// anti-relay binding.
					if operatorsURL == "" {
						return fmt.Errorf("--operators needs --operators-url: the exact URL operators " +
							"put in their remotes.yaml, signed into every operator request so a call " +
							"meant for this server verifies nowhere else")
					}
					canonical, verr := operator.CanonicalServerURL("--operators-url", operatorsURL)
					if verr != nil {
						return fmt.Errorf("--operators-url: %s", verr.Message)
					}
					// The guard's bound URL and this flag must agree, or every
					// remote issuance dies on a binding mismatch the operator
					// cannot see from their end. Checked here, where the person
					// who can fix it is watching the process start.
					if grantguard.Remote() {
						if bound := grantguard.BoundServer(); bound != canonical {
							return fmt.Errorf("--operators-url is %q but this machine's guard is bound to %q — "+
								"remote issuance would refuse every grant; re-enroll the guard with --url %s, "+
								"or fix the flag", canonical, bound, canonical)
						}
					}
					roster, groupReadable, err := operator.LoadRoster(operatorsFile)
					if err != nil {
						return fmt.Errorf("--operators: %w", err)
					}
					// A warning and not a refusal: adding an operator to the
					// roster without re-enrolling the guard leaves a server
					// worth starting (revocation and listing still work), but
					// a key the roster demoted or rotated keeps grant-signing
					// trust until the guard is re-enrolled, and this startup
					// line is the only place that drift can surface.
					if grantguard.Remote() && !grantguard.RemoteMatches(roster.Entries()) {
						fmt.Fprintf(cmd.ErrOrStderr(),
							"rta: the guard's signing set no longer matches %s's role=full keys — "+
								"re-run `rta grant guard remote` so demoted or rotated keys lose grant-signing trust\n",
							operatorsFile)
					}
					if groupReadable {
						fmt.Fprintf(cmd.ErrOrStderr(),
							"rta: %s is group-readable — it holds no secret, but anyone who can also write it can enroll themselves\n",
							operatorsFile)
					}
					if runtime.GOOS == "windows" {
						fmt.Fprintf(cmd.ErrOrStderr(),
							"rta: %s's permissions were not checked — rta cannot read NTFS ACLs on Windows; "+
								"make sure only you can write it before relying on it as a trust anchor\n",
							operatorsFile)
					}
					operatorHandler = mcp.NewOperatorHandler(mcp.OperatorConfig{
						Roster:  roster,
						URL:     canonical,
						Version: version,
						Agent:   agentName,
						Stderr:  cmd.ErrOrStderr(),
						// The mutation verbs, out of builtin/grant and
						// builtin/agent — wired here and not imported inside
						// internal/mcp, so that "this server prepares and
						// revokes grants, and answers consent, for its
						// operators" is a line somebody typed, the way
						// Secrets: kv.Reveal is below. Preparation
						// additionally requires the machine's guard in remote
						// mode, checked per call.
						Prepare: grantcap.PrepareRemote(reg.Capabilities),
						Revoke:  grantcap.RevokeRemote,
						Pending: agentcap.PendingRemote(agentName),
						Answer:  agentcap.AnswerRemote(agentName),
						Consent: consentOn,
					})
					rows := make([]string, 0, len(roster.Operators()))
					for _, o := range roster.Operators() {
						rows = append(rows, o.String())
					}
					fmt.Fprintf(cmd.ErrOrStderr(),
						"rta: operator channel at /operator/v1 as %s, enrolling %s\n",
						canonical, strings.Join(rows, ", "))
				}
			}
			sessionID := agentsession.NewID()
			// Presence is recorded at the handshake, not at start, and
			// removed on every exit path below: a server nobody ever spoke
			// to is not an agent, and a file left behind by a crash is
			// dropped by session.List the first time somebody looks.
			var connectedOnce sync.Once
			defer func() { _ = agentsession.End(sessionID) }()
			opts := mcp.Options{
				Agent:   agentName,
				Session: sessionID,
				Connected: func(client string) {
					connectedOnce.Do(func() {
						wd, _ := os.Getwd()
						if err := agentsession.Start(agentsession.Record{
							ID: sessionID, Agent: agentName, Client: client, Since: time.Now(),
							PID: os.Getpid(), Dir: wd, Ledger: agentlog.Path(),
						}); err != nil {
							fmt.Fprintln(cmd.ErrOrStderr(), "rta: could not record this session:", err)
						}
					})
				},
				AllowWrite:       allowWrite,
				AllowDestructive: allowDestructive,
				Consent:          consentOn,
				ConsentWait:      consentWait,
				ConsentNotify:    consentNotify,
				ConsentPreview:   consentPreview,
				Origin:           reg.Origin,
				Config:           pluginConfig.For,
				Profiles:         profileCfg,
				// The schema above is a snapshot; what a call resolves through
				// is the file as it is now, so an environment the operator
				// edits takes effect without a restart — and the grant they
				// issue against it is compared to the same connection it will
				// reach. A read that fails costs the agent every profile,
				// which is the fail-closed direction and the same call the
				// snapshot above makes.
				Reload: func() config.Config {
					live, err := config.Load()
					if err != nil {
						return config.Config{}
					}
					return live
				},
				// The store, opened from this server's own environment and
				// never by prompting. Wired here and not inside internal/mcp so
				// that "this server may read the operator's store" is a line
				// somebody typed rather than a transitive import.
				Secrets:   kv.Reveal,
				Untrusted: untrustedNames(),
				Paths:     guard,
				Remote:    httpAddr != "",
			}
			// A machine that requires a repository policy and finds none
			// refuses grants already (grant.Ceiling fails closed); the read
			// tier — the whole default surface — served anyway, with one
			// stderr line nobody reads. The documented behaviour is "a
			// server that refuses to start", and now it is.
			if _, verr := grant.Ceiling(); verr != nil {
				return verr
			}
			server := mcp.NewServer(reg, version, opts)
			// Logs must go to stderr: stdout is the protocol channel over
			// stdio, and a banner on the wire over HTTP would be a client
			// speaking to a server that has not accepted the connection yet.
			if httpAddr != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "rta mcp server listening on http://%s\n", ln.Addr())
				fmt.Fprintln(cmd.ErrOrStderr(),
					"rta: every request needs a bearer token; TLS is not this process's job — "+
						"put a reverse proxy, ingress or service mesh in front of it")
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "rta mcp server listening on stdio")
			}
			// Said out loud rather than left to be discovered from a refusal:
			// an operator who needs a wider root should learn it here, not
			// from an agent reporting that a file it can see does not exist.
			fmt.Fprintf(cmd.ErrOrStderr(), "path arguments confined to: %s\n",
				strings.Join(guard.Roots(), ", "))
			// The record and the session, named at the start: a server
			// writing to one data directory while the TUI reads another is
			// the first thing to rule out when nothing shows up, and it is
			// only visible if both sides say which file they mean.
			fmt.Fprintf(cmd.ErrOrStderr(), "record: %s (session %s)\n", agentlog.Path(), sessionID)
			// What Remote hides, named rather than left for an agent to notice
			// as a shorter tool list: see plugin.Capability.HostSpecific.
			if blocked := opts.RemoteBlocked(reg); len(blocked) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "rta: remote transport hides %d capabilities that describe this machine: %s\n",
					len(blocked), strings.Join(blocked, ", "))
			}
			// The ceiling, said out loud for the same reason the roots are.
			//
			// It matters more here than anywhere else, because this is the one
			// context where the operator did not choose the working directory:
			// a client launches rta from wherever it likes, and the repository
			// policy is found by walking up from there. A team can commit
			// .rta-policy.yaml, wire up a client that starts in $HOME, and get
			// no ceiling at all — with nothing anywhere saying so.
			fmt.Fprintln(cmd.ErrOrStderr(), "rta:", ceilingLine())
			// An allowlist entry that authorizes nothing is indistinguishable
			// from one the operator chose not to write: the capability is
			// simply absent, and the agent reports only that the tool does not
			// exist. Said here because the operator is present here, and is
			// the only one who can act on it.
			for _, p := range opts.Problems(reg) {
				fmt.Fprintln(cmd.ErrOrStderr(), "rta:", p)
			}
			if httpAddr != "" {
				// Bearer-authenticated and cross-origin-protected inside
				// Serve, unconditionally — see internal/mcp/remote.go.
				err = mcp.Serve(cmd.Context(), server, ln, mcp.RemoteOptions{
					Verifier: verifier, Stderr: cmd.ErrOrStderr(),
					Operator: operatorHandler,
				})
			} else {
				// fd 0 here is the agent's request stream. main() has already
				// taken it away from anything this process launches — it had
				// to, since plugins are spawned during startup, long before
				// this runs — so what is left to do is ask for it back.
				err = server.Run(cmd.Context(), &sdk.IOTransport{
					Reader: stdio.Real(),
					Writer: stdio.Writer(cmd.OutOrStdout()),
				})
			}
			// Client hang-up and ctrl-c are clean shutdowns, not failures.
			// The SDK does not expose a sentinel for the session-closing error
			// (it wraps EOF in a plain fmt error), hence the string match.
			// Serve already returns nil on its own clean shutdown path, so
			// this is stdio-specific in practice and harmless otherwise.
			if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) ||
				strings.Contains(err.Error(), "server is closing") {
				return nil
			}
			return err
		},
	}
	cmd.Flags().StringSliceVar(&allowWrite, "allow-write", nil,
		"plugins whose write capabilities are exposed (repeatable, e.g. note)")
	cmd.Flags().StringSliceVar(&allowDestructive, "allow-destructive", nil,
		"destructive capabilities to allow; external plugins must be pinned "+
			"to their digest (e.g. note.rm, hello.wipe@5dae737f8845)")
	// Named, because until it is there is exactly one principal on this
	// machine: every MCP client the operator wires up reads the same grant
	// file, so consent given while talking to one follows all the others.
	// The name is the operator's own word, written where they wire the client
	// up, and trusted exactly as much as --allow-write beside it.
	cmd.Flags().StringVar(&agentName, "as", "",
		"name this agent, so grants and the record can tell it from your other clients")
	cmd.Flags().StringSliceVar(&roots, "root", nil,
		"directory a caller may name in a path argument (repeatable; default: the working directory)")
	cmd.Flags().StringVar(&httpAddr, "http", "",
		"serve over HTTP instead of stdio, listening on this address (e.g. 127.0.0.1:8443) — "+
			"TLS and network exposure are the operator's job, not this flag's")
	cmd.Flags().StringVar(&tokenFile, "token-file", "",
		"bearer tokens allowed to connect, one \"label token\" pair per line; required with --http "+
			"unless --oidc-issuer is set")
	cmd.Flags().StringVar(&oidcIssuer, "oidc-issuer", "",
		"OpenID Connect issuer URL to verify bearer tokens against; required with --http "+
			"unless --token-file is set")
	cmd.Flags().StringVar(&oidcAudience, "oidc-audience", "",
		"required audience for tokens verified against --oidc-issuer")
	cmd.Flags().StringSliceVar(&oidcSubjects, "oidc-subject", nil,
		"subject (\"sub\" claim) allowed to authenticate (repeatable); required with --oidc-issuer, "+
			"since an issuer and audience alone name an application, not a person")
	cmd.Flags().StringVar(&operatorsFile, "operators", "",
		"operator public keys allowed to manage this server remotely, one \"label base64-pubkey\" "+
			"per line (`rta operator status` prints yours); mounts /operator/v1 beside the MCP endpoint")
	cmd.Flags().StringVar(&operatorsURL, "operators-url", "",
		"this server's canonical URL, exactly as operators write it in remotes.yaml; required with "+
			"--operators — it is signed into every operator request, so a call meant for this server "+
			"verifies nowhere else")
	// Off by default, and the default is the important half: a call parked
	// in a server nobody is watching is worse than a refusal.
	cmd.Flags().BoolVar(&consentOn, "consent", false,
		"ask instead of refusing when a call needs a grant nobody issued — you answer with `rta agent allow`")
	cmd.Flags().DurationVar(&consentWait, "consent-wait", consent.DefaultWait,
		"how long a parked call waits for your answer before it is refused")
	cmd.Flags().BoolVar(&consentNotify, "consent-notify", false,
		"also ring this machine's desktop notification when a call is parked")
	// On by default, unlike the two above: it costs one extra run of rta's
	// own handler in --dry-run and it changes the question from "may this
	// agent call note.rm" to "may it remove *this note*". The off switch is
	// for a capability whose dry run is expensive, which is a thing an
	// operator discovers rather than something rta can know.
	cmd.Flags().BoolVar(&consentPreview, "consent-preview", true,
		"show what a destructive call would do (its own --dry-run) on the parked request")
	// The two flags whose values nobody can be expected to type. A pinned
	// capability ID is a digest an operator would otherwise have to go and
	// look up, and a control that costs a lookup is one that gets left off.
	allowing := func(safety plugin.Safety) func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
		return func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
			return mcp.Options{Origin: reg.Origin}.AllowValues(reg, safety), cobra.ShellCompDirectiveNoFileComp
		}
	}
	_ = cmd.RegisterFlagCompletionFunc("allow-write", allowing(plugin.Write))
	_ = cmd.RegisterFlagCompletionFunc("allow-destructive", allowing(plugin.Destructive))
	// A root is a directory, and the shell has the list.
	_ = cmd.RegisterFlagCompletionFunc("root",
		func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveFilterDirs
		})
	return cmd
}

// ceilingLine describes the team ceiling in one line for the startup banner.
//
// A failure to load is reported rather than swallowed: a policy that cannot be
// parsed already stops every grant from loading, and an operator watching this
// server start is the person who can fix it.
func ceilingLine() string {
	ceiling, verr := grant.Ceiling()
	if verr != nil {
		return "team policy: " + verr.Message
	}
	if ceiling.Empty() {
		return "team policy: none in force (searched up from " + ceiling.SearchedFrom + ")"
	}
	return "team policy: " + ceiling.Where()
}
