# ipguard

A local HTTP proxy for [Claude Code](https://claude.com/claude-code) that lets traffic through only
when your machine's external IP is the one you expect.

You run it when your work depends on an exit address: a VPN, a fixed office line, a home router. The
guard answers one question at the moment a connection is opened — "is the external IP right now the
expected one?" — and closes the connection when the answer is no. A dropped VPN does not leave Claude
Code talking to the API from a different address, and you do not have to watch for it yourself.

## How it works

- The guard listens on loopback only and requires a secret: a local port is reachable by every process
  on the machine, so the proxy asks for Basic auth (`claude:<secret>`, the username is ignored).
- A connection gets its verdict **when it is established**: the guard asks `check_url` what the
  external IP is and compares the answer with `expected_ip`.
- **One check serves everyone.** At most one check is in flight at a time; connections and `/status`
  calls that arrive meanwhile subscribe to it and receive the same answer, pass or block. A burst of
  connections costs one request to the check host.
- **A completed verdict is never reused.** A connection joins a check that is already running or
  starts a new one for itself. A pass obtained a second ago is not handed to the next connection.
- `CONNECT` tunnels are forwarded as they are: no TLS interception, no certificates, no trusted-store
  changes. Plain HTTP with an absolute URL is proxied too.
- Established tunnels have no idle timeouts: model responses stream with pauses, and an idle timeout
  would cut a live answer.
- **Default closed.** No service — no traffic. Unknown verdict — no traffic. A panic in a handler
  kills the process instead of letting requests through.

## Requirements

- Go 1.25 or newer to build from source (or a binary you built elsewhere).
- macOS (launchd) or Windows (Task Scheduler) for the autostart. On Linux `install` refuses: there is
  no Linux autostart, and the guard will not pretend to have one. On Linux run `ipguard serve` under
  your own supervisor and call `ipguard enable` — the proxy part is platform-independent.

## Install

macOS:

```sh
git clone https://github.com/kerbyfc/ipguard.git
cd ipguard
./install.sh                              # asks whether to accept the detected external IP
./install.sh --yes                        # accept it without asking
./install.sh --expected-ip 203.0.113.9    # or name it yourself
./uninstall.sh                            # remove the autostart and stop the service
```

Windows (PowerShell):

```powershell
git clone https://github.com/kerbyfc/ipguard.git
cd ipguard
powershell -ExecutionPolicy Bypass -File .\install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1 --yes
powershell -ExecutionPolicy Bypass -File .\install.ps1 -- --expected-ip 203.0.113.9
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

If you already have a Go toolchain, the scripts only build and call the same command:

```sh
go install github.com/kerbyfc/ipguard/cmd/ipguard@latest
ipguard install
```

`install` is idempotent: every step compares what it wants with what is there and prints `=` when
nothing has to change.

```
$ ipguard install
ipguard install (+ done, = already done)
  + directory    created, /Users/you/.local/share/claude-ipguard
  + binary       installed, /Users/you/.local/bin/ipguard
  = hosts        there is no settings file yet, the whitelist comes from the template
  + settings     created, /Users/you/.local/share/claude-ipguard/ipguard.yaml (expected IP 203.0.113.9, new secret)
  + access       closed to the owner only, /Users/you/.local/share/claude-ipguard
  + autostart    unit updated and the service registered, /Users/you/Library/LaunchAgents/com.kerbyfc.ipguard.plist
  + service      started
  + probe        verdict ok, external IP 203.0.113.9, expected 203.0.113.9

proxy listens on http://claude:<secret>@127.0.0.1:8787
autostart         launchd (gui/501/com.kerbyfc.ipguard)
journal           /Users/you/.local/share/claude-ipguard/proxy.log

add the proxy to claude:  ipguard enable   (then restart claude)
drop the proxy:           ipguard disable
drop the autostart:       ipguard uninstall
settings:                 /Users/you/.local/share/claude-ipguard/ipguard.yaml
```

What the steps are:

1. **directory** — `~/.local/share/claude-ipguard`, mode 0700.
2. **binary** — `~/.local/bin/ipguard` (`ipguard.exe` on Windows). Built with `-trimpath`, so the same
   source gives the same bytes and the step stays idempotent. A file locked by the running service is
   moved aside and removed by the next install.
3. **hosts** — the settings file is brought to the current contract: the removed `guarded_hosts` key is
   dropped together with its own comment, and `unguarded_hosts` is added empty. A list you already
   wrote is not touched.
4. **settings** — `ipguard.yaml` with the expected IP and a fresh secret, mode 0600. **Your decisions
   are not rewritten:** an existing `expected_ip` and secret stay as they are, and an `--expected-ip`
   that disagrees with the file is a refusal naming both addresses.
5. **access** — the install directory and the settings file are closed to other accounts. On POSIX
   that is 0700/0600; on Windows there are no modes, so the ACL is narrowed to the owner.
6. **autostart** — a launchd agent on macOS, a Task Scheduler task on Windows.
7. **service** — the service is started every time, or restarted when the binary changed: a running
   service picks up a new file only that way. A live tunnel is not torn down by a start.
8. **probe** — the install waits for the listener, asks it `/status` and prints the current verdict. A
   service that does not answer is a failed install with a non-zero exit code; a `mismatch` verdict is
   not, because the guard is installed and the verdict depends on the network.

## Turn it on in Claude Code

The guard does not enable itself. Pointing Claude Code at it is a separate command you run:

```sh
ipguard enable      # write the proxy into the env block of ~/.claude/settings.json
ipguard status      # ask the running service for its verdict
ipguard disable     # remove the proxy variables that point at this guard
```

`enable` writes `HTTPS_PROXY` and `HTTP_PROXY` as `http://claude:<secret>@<listen address>` into the
`env` block of `~/.claude/settings.json`, taking the address, port and secret from the current
settings rather than from built-in values. What matters:

- **The `env` block covers background agents too.** Environment variables are read once at startup,
  and subagents inherit the environment of the shell that first started the supervisor; setting them
  in your shell does not reach those.
- **Restart Claude Code after `enable`.** Variables are read once at startup.
- Values already match — the file is not touched. Before any change a copy of the previous file stays
  next to it as `settings.json.ipguard-backup`.
- Lowercase `https_proxy`/`http_proxy` in the `env` block are a refusal: they take precedence, and
  removing them is your call.
- `disable` removes only its own variables: scheme `http`, user `claude`, and the address and port of
  the current settings (the secret is not compared, it may have changed since `enable`). A foreign
  `HTTPS_PROXY` stays and is named in the report without its password.

## Commands

| Command | What it does |
|---|---|
| `ipguard install` | Directory, binary, settings, autostart, service start and a live probe |
| `ipguard uninstall` | Removes the autostart and stops the service; settings, journal and binary stay |
| `ipguard enable [--settings <path>]` | Writes the proxy into Claude Code settings (default `~/.claude/settings.json`) |
| `ipguard disable` | Removes the guard's proxy variables from Claude Code settings |
| `ipguard serve [--config <path>]` | Runs the proxy in the foreground |
| `ipguard check` | One-off external IP check: exit 0 on a match, 3 on a block |
| `ipguard status` | Verdict, exceptions and guarded hosts from the running service: exit 0 on a pass, 3 on a block |
| `ipguard whitelist [pattern...]` | Prints the whitelist, or adds patterns and restarts the service |
| `ipguard logs [-n N]` | Last journal lines (10 by default, `-n 0` for only new ones), then follows the file |
| `ipguard version` | Prints the version |

Exit codes: `0` — pass, `3` — blocked, `2` — bad usage or settings, `1` — a failure of the command
itself.

## Settings

One YAML file in the install directory: `~/.local/share/claude-ipguard/ipguard.yaml`. Override the
path with `--config` or the `IPGUARD_CONFIG` environment variable.

```yaml
# Required: the only external IP at which traffic goes through.
expected_ip: 203.0.113.9

# Required by `serve`: the proxy password. The username in the URL is ignored, use `claude`.
# Can also come from the IPGUARD_SECRET environment variable; the file wins.
secret: change-me

check_url: https://icanhazip.com/     # the host that answers "what is my external IP"
unguarded_hosts: []                    # hosts out of guard; everything else waits for a verdict
attempt_timeout: 30s                  # timeout of one check attempt
retry_delays: [1s, 2s, 4s, 8s, 10s]   # pauses between attempts; the last one repeats
budget: 540s                          # how long a connection may wait for a verdict
listen_address: 127.0.0.1             # loopback only
listen_port: 8787
upstream_proxy: ""                    # an upstream proxy, http:// only
log_path: ~/.local/share/claude-ipguard/proxy.log
seen_hosts_path: ~/.local/share/claude-ipguard/hosts.tsv
log_max_bytes: 5242880                # rotate the journal after this size
log_keep: 3                           # how many rotated files to keep
```

- **A missing key keeps its built-in value; there is no built-in `expected_ip`.** The address is
  different for every machine, and a shipped default would guard traffic against the wrong one. Empty
  `expected_ip` is a refusal that tells you to run `ipguard install`.
- **No secret, no listener.** A built-in secret would be known to everyone, so `serve` refuses to
  start without `secret` or `IPGUARD_SECRET` (exit code 2). `check` does not need it.
- **A broken file or a value out of range is an error naming the field — exit code 2.** There is no
  silent fallback to defaults, and a typo in a key name is an error too, not a silently ignored field.
- A leading `~` is expanded in `log_path`, `seen_hosts_path` and the settings path itself: launchd and
  the Windows scheduler do not run in your home directory. `~user` is not supported.
- `listen_address` must be a loopback address: the guard never listens on a public interface.
- `upstream_proxy` accepts `http://` only: the guard does not speak TLS to an upstream proxy and will
  not silently bypass one.
- `attempt_timeout` and `budget` must be positive, and the budget cannot be shorter than one attempt.
- The removed keys `guarded_hosts` and `verdict_ttl` are errors while they are still in the file:
  the guard boundary is inverted, and a completed verdict is never reused.

## Guard boundary and the whitelist

**Every host waits for a verdict**, except three kinds of exceptions:

- the `check_url` host — otherwise the check would wait for its own verdict;
- local targets — `localhost`, names in `.local`, loopback, private and link-local addresses. A host
  whose name is not known stays under the verdict: the default is closed;
- patterns in `unguarded_hosts` — your whitelist, empty by default.

The first two live in code: they are an invariant of the guard, not a setting, and editing the file
cannot remove them.

Pattern rules:

- `*.anthropic.com` covers `anthropic.com` itself and any subdomain, including multi-level ones
  (`a.b.anthropic.com`);
- the star is allowed only at the start and only on a dot boundary: `*.anthropic.com` does not match
  `evilanthropic.com` or `anthropic.com.evil.net`;
- the name comes from the request (`CONNECT host:port` or an absolute URL), without DNS; case and a
  trailing dot do not change the decision;
- a scheme, port or path in a pattern is a refusal.

Add patterns with the command:

```sh
ipguard whitelist                                    # print the current list
ipguard whitelist '*.example.test' 'api.example.test'  # add both, restart the service once
```

Every argument is validated before the file is touched: one bad pattern refuses the whole call and
nothing is written. Patterns that are already set print `= already set: <pattern>`; new ones are
written in one edit of the settings file, verified by the same parser the service uses, and then the
service is restarted once. A settings file that does not exist is a refusal pointing at
`ipguard install`; the whitelist lives in the service file, which the install creates together with
the secret and the expected address.

```
$ ipguard whitelist '*.example.test' 'api.example.test' '*.example.test'
+ added to /Users/you/.local/share/claude-ipguard/ipguard.yaml: *.example.test
+ added to /Users/you/.local/share/claude-ipguard/ipguard.yaml: api.example.test
+ the service is restarted: the list is in force
```

With `--config <another file>` the edit goes to that file, but the service reads its own: the command
says so and does not restart it, because a restart would claim an effect the service will never see.

On a platform without autostart (Linux, for example) the edit is made and the command tells you to
restart the service yourself: it is your supervisor that keeps it running there, and the guard will
not pretend to have restarted something it does not own.

## Journal, status, and where the reason shows

| Channel | What you see |
|---|---|
| proxy response | `403` with the reason in the body — visible in `curl` and in client logs |
| **journal** | a line with the time, the reason and the target |
| **`GET /status`** | the verdict of a check it asked for or joined, and the last error |
| Claude Code itself | a generic network error ("Couldn't connect through your proxy"), no status and no body |

The last row matters: through the proxy answer alone you will not see the reason inside Claude Code.
The main channels are the journal and `/status`:

```sh
ipguard logs            # last 10 lines, then follow
ipguard logs -n 50      # start with the last 50
ipguard status          # verdict, exceptions and guarded hosts
curl -u "claude:$SECRET" http://127.0.0.1:8787/status
```

```json
{
  "verdict": "mismatch",
  "allowed": false,
  "ip": "198.51.100.7",
  "lastError": "",
  "checkedAt": "2026-01-15T11:34:04+03:00",
  "message": "claude-ipguard: blocked: external IP is '198.51.100.7', expected 203.0.113.9",
  "expectedIp": "203.0.113.9",
  "checkUrl": "https://icanhazip.com/",
  "budget": "9m0s"
}
```

The journal rotates by size and keeps `log_keep` previous files. **Every host under the verdict is
recorded** in `seen_hosts_path` (`hosts.tsv`): host, first and last seen, number of requests. Exceptions
are not recorded — the table answers "what does the guard protect", not "where did traffic go". The
table survives restarts; a host that later becomes an exception is dropped at the next start with a
line in the journal. At most 1000 entries: when the limit is reached the journal says so once and
`/status` reports `seenLimitReached`.

| File | What is in it | Limit |
|---|---|---|
| `proxy.log` (+ `.1`, `.2`, …) | journal lines: blocks, verdicts, tunnel failures | `log_max_bytes` × (`log_keep` + 1) |
| `hosts.tsv` | guarded hosts with counters | 1000 entries |
| `launchd.log` (macOS) | the service process output: panics and refusals before the journal opens | not rotated, so journal lines never go there |

## What it does not do

- **It does not reuse a completed verdict.** A connection waits for a check that is running or starts
  one, even if the previous check just passed. `/status` behaves the same way.
- **It does not re-check an established tunnel.** See the limitations below.
- **It does not cover all of Claude Code's traffic.** Documented as proxied: API requests, the startup
  connectivity check, fast-mode check, artifact reads, installs and updates, telemetry. WebSocket
  connections to `localhost`, `::1` and `127.0.0.0/8` always go direct, and subprocesses (Bash, hooks,
  stdio MCP) inherit the variables and decide for themselves. Anything that bypasses the proxy
  bypasses the guard.
- **It does not speak TLS to an upstream proxy:** `upstream_proxy` is `http://` only.
- **It does not enable itself:** `install` puts the service up, but the proxy is written into Claude
  Code only by `ipguard enable`, which you run.
- **It does not edit Claude Code settings silently:** `enable` keeps a backup next to the file, and
  lowercase proxy variables are refused rather than overwritten.

## Limitations

- **A tunnel outlives the verdict that opened it.** Once a TCP connection is established, its source
  address is fixed: when the VPN goes down, the interface and address disappear, the route is gone and
  the connection breaks or hangs until a timeout — it cannot move to another external address. Claude
  Code reopens the connection, which passes a new check and is refused.
- **A VPN that keeps its interface and address while switching exit points** (WireGuard, for example)
  is the residual case: the live connection continues from the new external address, and the verdict
  given at establishment is not revisited. There is deliberately no background VPN watcher: it would
  have to re-check an established TLS stream, not just the moment of connection.
- **Windows autostart is implemented but has not been exercised on a live Windows machine yet.** The
  scheduler task, the UTF-16 XML and the service restart are covered by unit tests with a fake
  runner; a real run is still pending. Please report what you see.
- **Linux has no autostart.** `install` refuses on purpose instead of installing something it cannot
  keep running.

## Development

```sh
go build ./...
go vet ./...
go test -race ./...
```

Cross-compile for Windows:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o ipguard.exe ./cmd/ipguard
```

The test suite runs without network, launchd or the Windows scheduler: the check host, OS commands and
the live port are substituted, so the tests exercise verdicts, retries, the single-flight check,
tunnels, the whitelist edit, settings parsing, journal rotation and the install steps without touching
the machine.

## License

[MIT](LICENSE)
