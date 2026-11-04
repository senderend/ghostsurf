# ghostsurf

NTLM HTTP relay tool with SOCKS proxy for browser session hijacking.

Capture NTLM auth, relay to HTTP/HTTPS targets, then browse as the victim through a SOCKS proxy. This works even when cookie replay doesn't.

Blog: [ghostsurf: From NTLM Relay to Browser Session Hijacking](https://specterops.io/blog/2026/04/02/ghostsurf-from-ntlm-relay-to-browser-session-hijacking/)

## Features

- **Browser Session Hijacking**: SOCKS5 proxy lets you browse as the relayed user
- **Auto Session Selection**: Single session auto-selects; multiple sessions show an HTML picker
- **Kernel-Mode Auth Workaround**: Probe-first strategy for IIS/HTTP.sys targets
- **Multi-User Relay**: Relay multiple captured users to the same target with `-r`
- **Thread-Safe**: Concurrent browser connections with socket locking
- **Header Preservation**: Passes User-Agent, cookies, and other headers the target app depends on

## Usage

```bash
# Basic - relay to target
./ghostsurf -t https://target.local/

# With kernel-mode auth workaround (for IIS/HTTP.sys)
./ghostsurf -t https://target.local/ -k

# Relay multiple users to the same target
./ghostsurf -t https://target.local/ -r

# Debug mode for verbose output and bug reports
./ghostsurf -t https://target.local/ -d
```

Dependencies are installed automatically on first run. To force-reinstall: `rm -rf venv && ./ghostsurf -h`

### CLI Options

```
Main:
  -t, --target TARGET      Target URL to relay to
  -d, --debug              Verbose output
  -s, --ts                 Timestamp logging

Relay:
  -k, --kernel-auth        Kernel-mode auth workaround (probe anonymously first)
  -r, --keep-relaying      Allow multiple users to be relayed to the same target.
                           Without this, the target is marked done after the first
                           successful relay and further captures are dropped.
  -i, --interface IP       Bind to specific interface

SOCKS:
  --socks-address IP       SOCKS5 bind address (default: 127.0.0.1)
  --socks-port PORT        SOCKS5 port (default: 1080)
  --api-port PORT          REST API port (default: 9090)

Servers:
  --no-smb-server          Disable SMB capture server
  --no-http-server         Disable HTTP capture server
  --no-wcf-server          Disable WCF capture server
  --no-raw-server          Disable RAW capture server
  --no-rpc-server          Disable RPC capture server
  --smb1                   Use SMB1 only (SMB2 is default)
```

### Listeners

All listeners relay into the HTTP(S) target, so SMB signing on the source host doesn't matter.

| Listener | Default port | Catches |
|----------|--------------|---------|
| SMB      | 445          | Coerced machine auth over SMB (wspcoerce, DFSCoerce, PrinterBug on older builds) and poisoned or phished users |
| HTTP     | 80           | Browsers and other HTTP clients authenticating to a name in the intranet zone |
| RPC      | 135          | PrinterBug callbacks from Windows 11 22H2+ and Server 2025, which only call back over raw DCERPC |
| WCF      | 9389         | net.tcp clients such as the AD PowerShell module talking to ADWS |
| RAW      | 6666         | NTLM forwarded by [lsarelayx](https://github.com/CCob/lsarelayx) |

Ports below 1024 need root.

### Attack Flow

1. Start ghostsurf:
   ```bash
   ./ghostsurf -t https://target.local/ -k -r
   ```

2. Set up browser proxy (Firefox + FoxyProxy recommended):
   - Install [FoxyProxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) in Firefox
   - Add proxy: SOCKS5, `127.0.0.1`, port `1080`
   - Enable the proxy profile before browsing

   Firefox is recommended over Chrome — Chrome makes extensive background
   telemetry and tracking requests that get routed through the proxy, polluting
   your output and logs with failed requests.

   When browsing HTTPS targets, Firefox will show a certificate warning for
   the local SOCKS TLS connection (self-signed cert, patched for Firefox's
   stricter certificate requirements). Accept it to proceed — this is expected
   and only applies to the local proxy, not the upstream target connection.

3. Trigger NTLM auth (coerced auth, phishing, responder, etc.)

4. Session captured → browse to target through proxy

5. Multiple sessions? Session picker UI appears, just click one. A cookie binds all
   subsequent requests to that relay session. To switch to a different session, close
   and reopen Firefox to clear the cookie.

### Shell Commands

```
ghostsurf> socks      # List active sessions
ghostsurf> targets    # List configured targets
ghostsurf> exit       # Shutdown
```

## Kernel-Mode Auth Workaround (`-k`)

IIS with kernel-mode authentication enabled (the default since IIS 7) binds NTLM auth
to TCP connections at the kernel level via HTTP.sys. If a request hits a path configured
for Anonymous authentication (static CSS, JS, images, fonts), HTTP.sys resets the
authenticated context on the connection. The relay session silently dies with no error.

ghostsurf's `-k` flag probes paths anonymously before using the relay socket:
1. Opens a fresh anonymous connection, sends the same request without NTLM
2. 401 response → path requires auth → forward through the authenticated relay socket
3. 200 response → path is public → return anonymous response directly, relay socket untouched
4. Results cached per path for negligible overhead after initial page load

Use `-k` for any IIS target. This includes CyberArk, Passwordstate, Delinea Secret Server,
IBM Verify Privilege Vault, Thycotic Secret Server, BeyondTrust Password Safe,
OneIdentity Password Manager, SCCM, and other software that preserves default IIS authentication
settings. If unsure, just use `-k` — the overhead is minimal and it prevents silent session death.

Without `-k`, all requests go directly through the relay socket, which works for targets that
don't use kernel-mode authentication (Windows Admin Center, Apache, nginx, non-IIS stacks, IIS 6 and below on default settings).

## Finding Targets

Use [ntlmscan](https://github.com/nyxgeek/ntlmscan/) by [nyxgeek](https://github.com/nyxgeek)
to discover NTLM-authenticated endpoints in the environment, and reference its
[path list](https://github.com/nyxgeek/ntlmscan/blob/master/paths.dict) for manual enumeration ideas.

## Why Not Just Steal Cookies?

For some NTLM-protected apps, you can — but not all.

When IIS has both Anonymous and Windows Authentication enabled, the app typically manages
its own session layer. A valid session cookie bypasses re-authentication entirely, so cookie
replay works fine (ghostsurf should also work!).

When Windows Authentication is the sole provider (Anonymous disabled), HTTP.sys handles
authentication at the kernel level on every request to protected paths. It challenges for
NTLM before the app ever sees the request — including the cookies. A browser presenting
harvested cookies gets a 401 from HTTP.sys before the app layer is even reached. Cookies may
still be used for state management, but they can't bypass the auth challenge.

In those configurations, the only option is to proxy a browser through the live authenticated
relay connection, which is what ghostsurf does. Common examples: Passwordstate, CyberArk PAM,
and other enterprise password managers configured for AD passthrough SSO; SCCM/MECM IIS roles;
and countless internal IIS sites with Windows Authentication enabled and Anonymous disabled.

## Beyond Browsing

Interactive browser access also helps with recon for further tooling. Many enterprise apps have
complex multi-step workflows, JavaScript-rendered interfaces, and stateful interactions that are
difficult to reverse from packet captures alone. Proxying a browser through the relay session
lets you interact with the application as the victim user and understand what's actually there,
which lowers the barrier for developing targeted attack modules against apps that would otherwise
be hard to reverse-engineer.

## Testing

`tests/smoke_test.py` runs ghostsurf against a fake IWA site on localhost, sends NTLM auth into
the HTTP, SMB, RAW and RPC listeners, and checks that each session relays and serves a page
through the SOCKS proxy. It needs no root or network:

```bash
venv/bin/python tests/smoke_test.py
```

## Caveats

ghostsurf funnels all browser requests through a single authenticated TCP connection. Performance
depends on the target: lightweight apps are snappy, heavier ones (like Windows Admin Center with
its large remoting requests) can be slower. Give pages a few seconds to load rather than clicking
repeatedly.

WebSocket connections are not supported. Apps that use WebSockets for real-time features will
still load and function for core browsing, just without live updates.

## Credits

Based on [ntlmrelayx](https://github.com/fortra/impacket) from Impacket by:
- Fortra, LLC
- Dirk-jan Mollema / Fox-IT
- Alberto Solino

Credit to [Craig Wright](https://github.com/werdhaihai) for leading the op that inspired this tool and the suggestion to research it rather than move on.
