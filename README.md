# Go Smart Proxy

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A local **HTTP/HTTPS and SOCKS5 proxy** with network-aware route selection, upstream
proxy chains, destination rules, and an optional **end-to-end encrypted relay**
that lets trusted contacts reach each other's networks without exposing services
to the internet.

The management UI is embedded in the binary and served on the proxy listener
(loopback only). The UI supports the 24 official languages of the European
Union, selected from the browser locale or manually from the header menu, with
English as fallback; code, comments and this README are in English.

> **Security first:** the configuration contains proxy credentials and can contain
> the relay private key. It is encrypted at rest with a master password
> (`config.yml.enc`). **The master password cannot be recovered.** Read
> [Security](#security) before using the relay.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Configuration](#configuration)
  - [Encrypted configuration and first run](#encrypted-configuration-and-first-run)
  - [Configuration reference](#configuration-reference)
  - [Routes and route selection](#routes-and-route-selection)
  - [Proxy chains](#proxy-chains)
  - [Destination rules](#destination-rules)
  - [Hosts overrides](#hosts-overrides)
- [Using the proxy](#using-the-proxy)
- [Web UI and HTTP API](#web-ui-and-http-api)
- [System integration](#system-integration)
- [Relay](#relay)
  - [Relay client](#relay-client)
  - [Devices](#devices)
  - [Contacts and route approvals](#contacts-and-route-approvals)
  - [Relay server](#relay-server)
  - [Manual certificate provisioning](#manual-certificate-provisioning)
  - [Enrollment over email](#enrollment-over-email)
  - [Kubernetes deployment](#kubernetes-deployment)
- [Security](#security)
- [Environment variables](#environment-variables)
- [Development](#development)
- [Repository layout](#repository-layout)
- [Troubleshooting](#troubleshooting)
- [Limitations and roadmap](#limitations-and-roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **HTTP proxy** with absolute-form requests and HTTPS `CONNECT` tunnels.
- **SOCKS5 proxy** (no authentication, `CONNECT` only) sharing the same routing
  configuration as the HTTP proxy.
- **Network-aware routes**: choose a route based on the current default gateway,
  network interface, local network, or a PAC file.
- **Proxy chains**: HTTP, HTTPS (via `CONNECT`) and SOCKS5 hops, with NTLM/Basic
  authentication support for HTTP proxies; PAC and dynamic rule-evaluation hops.
- **Destination rules** by domain, exact host, IP address, or CIDR block.
- **Rules-only routes and hops**: keep corporate/VPN/relay routes out of the
  automatic selection and out of the manual route selectors.
- **Relay**: mTLS-authenticated rendezvous relay, contact address book, explicit
  route approvals scoped per device, multiple devices per user (your own devices
  are listed and usable without an invitation), and desktop notifications.
- **Encrypted configuration** with a master password (PBKDF2 + AES-256-GCM).
  On macOS the derived key can be stored in the Keychain and unlocked with
  Touch ID; on Windows it is protected with DPAPI.
- **Complete web configuration**: listeners, SOCKS5, system integration, static
  hosts, routes and route ordering, rules, credentials, relay settings and
  certificates.
- **Internationalization**: the web UI (and the first-run setup page) support the
  24 official languages of the European Union, selected from the browser locale or
  manually from the header menu, with English as fallback.
- **System tray** with dynamic route selection and a web UI for configuration,
  rules, credentials, connections, and relay management.
- **macOS integration**: system proxy configuration (including VPN-overridden
  proxies) and Chrome policy enforcement.
- **PAC caching**: PAC files are fetched directly, cached, and never block
  request handling.
- **Connection registry**: live connection log, byte counters, and fail-fast
  recovery on network changes.
- **Single binary** with the web UI embedded (no external assets at runtime).

---

## Architecture

```mermaid
flowchart LR
    subgraph Clients
        B[Browser / app]
        C[curl / CLI]
    end

    B -->|HTTP proxy :3128| P[proxy]
    B -->|SOCKS5 :1080| P
    C -->|HTTP / SOCKS5| P

    P --> R{Route selection}
    R -->|Direct| I[Internet / intranet]
    R -->|PAC| PAC[Upstream proxy]
    R -->|Chain| H1[HTTP / SOCKS5 hop] --> H2[...] --> I
    R -->|Relay route| REL[Relay]
    REL -->|mTLS / yamux| RS[Relay server]
    RS -->|contact approved route| CONTACT[Contact's proxy]
    CONTACT --> T[Target host]

    P --- UI[Embedded web UI / API]
    P --- TRAY[System tray]
    P --- CFG[(config.yml.enc)]
```

The proxy listens on one HTTP address (also serving the web UI and API on
loopback) and optionally on a SOCKS5 address. Every outgoing connection is
resolved through the route/rules engine.

---

## Requirements

- **Go 1.24+**
- **Node.js 20+ / npm** to build the web UI (the built UI is embedded in the
  binary)
- A C compiler/toolchain for the system tray:
  - macOS: Xcode Command Line Tools
  - Windows: Go toolchain (`build.bat` builds `proxy.exe`)
  - Linux: the system tray library requires CGO plus GTK/AppIndicator
    development packages; without them the tray part does not build
- For the relay server: no CGO is required (`make relay` builds with
  `CGO_ENABLED=0`)

The project is primarily developed on macOS. Windows is supported for the core
proxy, SOCKS5, relay, encrypted configuration and tray. Linux supports the core
proxy, SOCKS5, relay, encrypted configuration, and tray when
the systray dependencies are installed. The macOS-only features are marked in
the relevant sections.

---

## Quick start

```bash
git clone https://github.com/apeironlab/go-smart-proxy.git
cd go-smart-proxy

# Build the web UI and the proxy binary
make build

# Start it: on first run it opens a browser setup page to choose the
# master password
./proxy
```

Then:

1. On first run, use the setup page that opens automatically at
   `http://127.0.0.1:3128/?token=...` (the URL is also printed in the terminal).
   Choose the master password. The proxy is created with:
   - HTTP proxy + web UI: `127.0.0.1:3128`
   - SOCKS5 proxy: `127.0.0.1:1080`
2. Click **Inizia a usare il proxy** in the welcome page.
3. Configure routes, rules, credentials, and relay from the web UI.
4. Point apps at the proxy:

```bash
# HTTP proxy
curl -x http://127.0.0.1:3128 https://example.com

# SOCKS5 (enabled by default on first run)
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

On macOS/Windows the same actions are available from the tray icon.

There is no configuration template to copy. On first start the proxy runs a
token-protected setup page on loopback: choose the master password there and the
proxy creates `config.yml.enc` with defaults (`127.0.0.1:3128` and SOCKS5
`127.0.0.1:1080`). If those ports are busy, the next free port is used and shown
on the page. From then on everything is managed from the web UI. For
headless/automatic first starts, set `PROXY_MASTER_PASSWORD` to skip the setup
page.

---

## Configuration

### Encrypted configuration and first run

The proxy stores its configuration in **`config.yml.enc`**, encrypted with a key
derived from a master password:

- KDF: **PBKDF2-HMAC-SHA256, 600,000 iterations**, random 16-byte salt
- Cipher: **AES-256-GCM**, random 12-byte nonce
- File format: `GSP1 | salt | nonce | ciphertext`
- File permissions: `0600` on Unix

At startup:

1. If `config.yml.enc` exists, the proxy unlocks it with the stored key.
   Without a stored key it asks for the master password in the terminal, or
   opens the **unlock page** on loopback when started from a desktop.
2. If only the legacy plaintext `config.yml` exists, the proxy:
   - asks for a new master password (twice) in a terminal, or opens a
     **migration page** in the browser,
   - embeds the relay certificate, private key and CA into the configuration,
   - writes and verifies `config.yml.enc`,
   - removes the plaintext configuration and the plaintext relay private key.
3. If neither file exists, the proxy starts a **token-protected setup page** on
   loopback (it opens the browser and prints the URL): choose the master
   password there. It writes `config.yml.enc` with defaults
   (`Address: 127.0.0.1:3128`, SOCKS5 `127.0.0.1:1080`). Set
   `PROXY_MASTER_PASSWORD` to skip the setup page on headless machines.
4. After setup, a one-click welcome page confirms the working defaults; the
   proxy is immediately usable.
5. Existing configurations are treated as already onboarded.

**Unlock sources**, in order:

1. The process already has the derived key (normal while running).
2. `PROXY_MASTER_PASSWORD` (useful for launchd/services/automation).
3. The system key store: Keychain on macOS (with Touch ID when available),
   DPAPI on Windows.
4. An interactive master password prompt in a terminal, or the token-protected
   unlock page in the browser when there is no terminal.

The browser setup page is used for a brand-new installation, the migration page
for a plaintext configuration, and the unlock page when the stored key is not
available; after that, the sources above unlock the existing configuration.

On macOS the **derived key** (not the password) is stored in the Keychain, under
the service `go-smart-proxy`, keyed by the configuration salt. The Keychain read
is gated by a `LocalAuthentication` Touch ID check when biometrics are
available. On Windows the derived key is stored in `config.key.dpapi` and
protected with `CryptProtectData` for the current user. Set
`PROXY_NO_KEYCHAIN=1` to disable both stores and always require the master
password.

> **Backups:** `config.yml.enc` is portable. On another machine the master
> password is enough; the Keychain/DPAPI entry is local. Keep an encrypted
> backup and the password in a password manager. **There is no password
> recovery.**

Saving from the web UI keeps the same salt and derived key, so the stored key
stays valid. The configuration is re-encrypted on every change.

**Data directory**: a portable run (archive extracted in a writable folder) keeps
`config.yml.enc`, `config.key.dpapi`, `relay_state.json` and `cache/` next to the
binary. When the binary is installed — a macOS app bundle, the Windows installer
(marked by `installed.marker` next to `proxy.exe`) or a Linux package — the
proxy uses the user configuration directory instead:
`~/Library/Application Support/go-smart-proxy` on macOS, `%AppData%\go-smart-proxy`
on Windows, `~/.config/go-smart-proxy` on Linux. On the first launch after an
upgrade, an existing configuration found in the old working directory is moved
to the new one. Set `PROXY_HOME` to force a specific directory.

### Configuration reference

The following is the *plaintext* schema. The encrypted file contains the same
YAML, plus embedded relay material.

```yaml
Address: 127.0.0.1:3128        # HTTP proxy + web UI/API listener
SocksAddress: 127.0.0.1:1080   # optional SOCKS5 listener; empty = disabled

Credentials:
  - Name: corp
    User: 'DOMAIN\alice'
    Password: 'secret'

Routes:
  - Name: office
    Gateway: ''                # optional: default gateway IP
    IFace: utun4               # optional: default interface name (globs allowed: utun*)
    Net: 10.0.0.0/8            # optional: local network/address
    IFaceUp: tun*              # optional: apply while a matching interface is in use
    VPN: up                    # optional: up = only with a VPN, down = only without
    RulesOnly: false           # never selected or forced manually
    Chain:                     # ordered upstream hops
      - ProxyUrl: http://proxy.corp:8080
        Credential: corp
        RulesOnly: false       # barrier for automatic/forced traffic
      - ProxyUrl: socks5://other:1080
        Credential: ''
    # A PAC route is a single-hop chain:
    # Chain:
    #   - PacUrl: http://config.corp/proxy.pac
    #     Credential: corp
    # A dynamic hop must be the last one: at connection time it evaluates the
    # destination rules and applies the selected route (or goes direct).
    # Chain:
    #   - ProxyUrl: http://proxy.corp:8080
    #   - Dynamic: true

Rules:
  - Name: intranet
    Domains: [corp.local]      # domain and all subdomains
    Hosts: [intranet.corp.local]
    Networks: [10.0.0.0/8, 192.168.1.5]
    Route: office

Relay:
  Address: 'relay.example.com:8443'
  # Manual certificate files (legacy) ...
  Cert: relay/client.pem
  Key: relay/client-key.pem
  CA: relay/ca.pem
  # ... or embedded PEMs (filled by the web UI enrollment)
  # CertPEM: |
  #   -----BEGIN CERTIFICATE-----
  # KeyPEM: |
  #   -----BEGIN PRIVATE KEY-----
  # CAPEM: |
  #   -----BEGIN CERTIFICATE-----
  Route: ''                    # optional route used to reach the relay
  Device: quiet-otter-7f3a     # auto-generated per installation
  EnrollURL: https://proxy.intra.example.com
  AllowLocal: false            # let contacts reach services on this machine
  NetworkLabel: office-vpn     # name of this network, shared with contacts (optional)
  ShareContext: true           # false = share nothing about the network

SystemProxy: false             # macOS only
SystemProxyExclude: [utun4]    # macOS network services to leave untouched
ForceChrome: false             # macOS only
AllowRemoteClients: false      # serve clients other than this machine (see Security)
Hosts:
  repo.intra.example.com: 192.0.2.40
```

#### Fields

| Field | Meaning |
|---|---|
| `Address` | HTTP proxy listener. The web UI/API are served on the same port, but only for loopback clients. |
| `SocksAddress` | SOCKS5 listener. Empty/omitted disables it. |
| `Credentials` | Named username/password pairs used by routes and hops. |
| `Routes` | Ordered route list. `Direct` is always appended last. |
| `Routes[].Gateway` | Match when the system default gateway is this IP. |
| `Routes[].IFace` | Match when the default interface has this name (comma-separated names or globs such as `utun*`). |
| `Routes[].IFaceUp` | Match while an interface with this name (or glob) is **in use**: up, with an IPv4 address and carrying routes. Unlike `IFace` it also sees split-tunnel VPNs that leave the default route alone. |
| `Routes[].VPN` | `up`: match only while a VPN is active; `down`: only while none is. |
| `Routes[].ExitVPN` | With a relay hop: match only while the contact's device at the exit is on a VPN (`up`) or not (`down`), as it shares it. |
| `Routes[].ExitLabel` | With a relay hop: match only while the exit shares a network label that matches (names or globs, comma-separated). |
| `Routes[].Net` | Match when the local network/address matches this IP or CIDR. |
| `Routes[].Chain` | Ordered upstream hops. An empty chain means a direct connection. |
| `Routes[].RulesOnly` | Route is never selected or forced manually; only a destination rule can use it. |
| `Chain[].ProxyUrl` | `http://`, `https://` (CONNECT), `socks5://`, or `relay://email[/device]`. |
| `Chain[].PacUrl` | PAC file evaluated for each request. A PAC hop must be the only hop of the chain. |
| `Chain[].Dynamic` | Routing point: evaluates the destination rules and applies the selected route. Must be the last hop. |
| `Chain[].Credential` | Credential for this proxy/PAC hop. |
| `Chain[].RulesOnly` | Chain barrier: unless a rule selects the route, the chain stops before this hop. |
| `Rules[].Domains` | Domain and subdomain matches (`example.com` matches `a.example.com`). |
| `Rules[].Hosts` | Exact hostname matches. |
| `Rules[].Networks` | IP/CIDR matches; hostnames are resolved for this check. |
| `Rules[].Route` | Route name to use. |
| `Rules[].ExitVPN`, `Rules[].ExitLabel` | Optional conditions on the exit of the route's relay hop, as for routes. When they do not hold the rule is skipped and the next one is tried. |
| `Hosts` | Fixed IP per hostname, bypassing DNS. |

`Address` is required. Credentials and relay material are never written in
plaintext once the configuration is encrypted.

Configurations written before upstreams became hops may still contain the
legacy route-level `PacUrl`, `ProxyUrl` and `Credential`: on startup they are
migrated into a single `Chain` hop and the legacy keys are removed. If both
`PacUrl` and `ProxyUrl` were present, the PAC wins (it already took precedence
at runtime).

### Routes and route selection

For each destination, the route is chosen in this order:

1. **Forced route**, if selected from the tray or the Config page.
2. **Destination rules**, in order, only while the selection is **Auto**. The
   first matching rule whose route is applicable on the current network wins.
3. **Automatic selection**: the first route in configuration order whose
   `Gateway`, `IFace`, `IFaceUp`, `VPN`, `Net` and PAC (if any) are available.
4. **`Direct`** (always last, always applicable).

#### Network and VPN detection

The automatic selection depends on what the proxy sees of the network, and it
reads the same things on every operating system:

- **Default route and gateway** come from the routing table (`/proc/net/route`
  on Linux, `netstat -rn -f inet` on macOS and the BSDs, `route print -4` on
  Windows; only numeric columns are parsed, so the system language does not
  matter). The real gateway is used, not the local address, so `Gateway`
  matches on all platforms. Interface-scoped defaults (BSD `I` flag) never
  decide the default.
- **An interface is "in use"** when it is up, has a usable IPv4 address (not
  loopback or link-local) and carries routes. Tunnel interfaces that VPN
  clients leave behind after disconnecting (typically macOS `utun*` with only
  an IPv6 link-local address) are therefore ignored.
- **A VPN is active** when an interface in use is a tunnel: it is point-to-point
  or its name is typical of VPNs (`utun`, `tun`, `tap`, `ppp`, `wg`, `gpd`,
  Pulse/Ivanti, AnyConnect, GlobalProtect, FortiClient, OpenVPN, WireGuard,
  Tailscale, ZeroTier...). Docker, VM, WSL, bridge and similar virtual
  interfaces are never counted. This works for full-tunnel VPNs (default route
  through the tunnel) and split-tunnel ones (default route unchanged).
  Anything the heuristics misjudge can be targeted explicitly with `IFaceUp`.
- A change in any of this (including a split-tunnel VPN connecting, which does
  not alter the default route) is treated as a network change: PACs and
  transports are reset, connections are closed and the system proxy is
  re-applied. Linux and macOS react to routing events immediately; all systems
  also poll every 3 seconds, which is the only mechanism on Windows.

The **Network and VPN detection** panel (Configuration → Network) shows the
interfaces, which one carries the default route, which are in use and which are
VPNs; the Routes table explains why a route is not applicable.

Limits: only IPv4 routes are considered, and a point-to-point interface that is
not a VPN (a mobile-modem `ppp0`, for instance) counts as one.

Routes marked `RulesOnly: true` are skipped by automatic selection and cannot be
forced: they can only be used by a matching destination rule, and do not appear
in the route selectors of the web UI or tray menu. A route can still be used by
more than one rule.

**Per-hop `RulesOnly`** is a barrier rather than a skip: when a route is used
without a matching rule (automatic or forced), the chain stops *before* the first
hop marked `RulesOnly`; only a rule-selected route traverses the whole chain.
This lets an expensive corporate proxy or a relay exit be reserved for specific
rules.

A **PAC hop** is not a proxy: the route evaluates the PAC file per request and
uses the returned upstream. The PAC file is fetched directly (never through the
proxy), cached under `cache/pac-<md5>`, and refreshed in the background; request
handling uses the cached copy when the network is unavailable. A PAC hop must be
the only hop of its chain.

A **dynamic hop** is a routing decision point inside a chain. It cannot be
combined with a proxy or a PAC, and it must be the last hop. When the connection
reaches it, the destination rules are evaluated: if one matches, the route it
points to is applied; if none matches, the connection continues directly to the
target from the hops already traversed. The dynamic hop is especially useful on
a forced route, where the outer selection intentionally ignores the rules.
Recursive expansions keep a set of visited routes and a maximum depth, so a
rule that points back to a route already in use stops with a direct connection
instead of looping.

Network changes (interface/gateway/address changes) invalidate PACs, reset
transports, and close active connections so clients reconnect through the new
route.

### Proxy chains

A chain is dialed left to right. Supported schemes:

- `http://host:port` — HTTP `CONNECT`, with Basic/NTLM authentication
- `https://host:port` — HTTP `CONNECT` over TLS
- `socks5://host:port` — SOCKS5
- `relay://email@example.com[/device]` — exit through a relay contact
- `PacUrl: http://host/pac` — evaluate a PAC (the only hop of the chain)
- `Dynamic: true` — evaluate the destination rules at this point (the last hop)

Only one relay hop is allowed per chain, and it may appear anywhere:

- `relay://alice@example.com` — traffic exits through Alice's network. The relay
  client reaches the relay server directly.
- `http://proxy:8080 → relay://alice@example.com` — the relay **control
  connection** goes through `http://proxy:8080`; traffic still exits through
  Alice. The hops before the relay are not re-dialed for each traffic connection.
- `relay://alice@example.com → http://proxy:8080` — traffic exits into Alice's
  network and then goes through the proxy.

When the relay client itself needs to reach the relay server, it cuts the chain
at the first `RulesOnly` hop and at the relay hop. If the relay hop is first, the
control connection is direct. This is what prevents the relay from trying to use
itself to connect.

### Destination rules

Rules are evaluated in order. A rule matches if any of its `Domains`, `Hosts` or
`Networks` matches. Domain matching includes subdomains; network matching
supports exact IPs and CIDR blocks. If a rule's route is not applicable on the
current network, evaluation continues with the next rule.

The web UI includes a “Verifica una destinazione” tool that shows which rule and
route would be used for a host or IP.

### Hosts overrides

`Hosts` maps a hostname to a fixed IP. It is used before DNS and applies to
direct connections, chain hops, PAC destinations, and relay targets. This is
useful when a VPN resolver does not know an internal name.

---

## Using the proxy

### HTTP proxy

```bash
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
```

- Plain HTTP requests use absolute-form proxy requests.
- HTTPS uses `CONNECT`.
- The local proxy does **not** require authentication.
- The web UI/API are served on the same address for loopback clients only.

### SOCKS5

Set `SocksAddress` to enable it:

```yaml
SocksAddress: 127.0.0.1:1080
```

Characteristics:

- SOCKS5, no authentication
- `CONNECT` only (no `BIND`/`UDP ASSOCIATE`)
- Same routes, rules, chains, relay, and connection logging as the HTTP proxy

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

Both listeners are unauthenticated. **Bind them to loopback** unless you have
another access-control layer.

---

## Web UI and HTTP API

The React web UI is embedded in the binary (`webui/dist`) and served at `/` on
the HTTP proxy address. It is available only to loopback clients.

Pages:

- **Configurazione** — listeners, SOCKS5, system proxy, Chrome
  policy, static hosts, relay connection settings, routes and chains, DNS cache.
- **Regole** — destination rules and a route test tool.
- **Credenziali** — named credentials; passwords are never returned by the API
  (an empty field keeps the current password).
- **Connessioni** — live/recent connections, routes, bytes, errors, events.
- **Relay** — connection status, contacts, approved routes, device code,
  enrollment/reconfiguration.

The **Configurazione** page is the single place for proxy-wide settings:
listeners, SOCKS5, system proxy, Chrome policy, static hosts, relay
address/route/`AllowLocal`, manual relay certificate PEMs (write-only; the API
never returns private keys), and route ordering. Relay certificate enrollment
and device renaming remain on the Relay page.

| Setting | Where in the web UI |
|---|---|
| HTTP listener and web UI | Configurazione → Rete |
| SOCKS5 listener | Configurazione → SOCKS5 |
| System proxy and excluded services | Configurazione → Rete |
| Chrome policy | Configurazione → Rete |
| Static host → IP mappings | Configurazione → Host fissi |
| Routes, chains, PAC/dynamic hops, per-hop `RulesOnly`, route priority | Configurazione → Route |
| Destination rules, rule order, destination test | Regole |
| Credentials | Credenziali |
| Forced route | Configurazione or tray |
| Relay address, route, `AllowLocal`, manual certificate | Configurazione → Relay |
| Relay enrollment, device name, contacts, approvals | Relay |
| Live connections and DNS cache | Connessioni / Configurazione |

The API is intentionally unauthenticated and **loopback-only**; do not expose
the listener to untrusted networks. A non-exhaustive endpoint list:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/state` | Network, listeners, routes, DNS cache |
| GET/POST | `/api/config` | Read/update settings |
| POST | `/api/onboarding` | Complete first-run onboarding |
| GET/POST | `/api/routes` | List/save routes |
| POST | `/api/routes/order` | Reorder routes |
| DELETE | `/api/routes/{name}` | Delete a route |
| GET/POST | `/api/rules` | List/save rules |
| GET | `/api/rules/test?host=...` | Which route would be used |
| GET/POST | `/api/credentials` | List/save credentials |
| POST | `/api/force-route` | Force a route or Auto |
| POST | `/api/pac/refresh` | Refresh a PAC |
| GET | `/api/connections` | Connection log |
| GET | `/api/relay` | Relay status, contacts, approvals |
| GET/POST | `/api/relay/config` | Relay address/route/AllowLocal and manual certificate |
| POST | `/api/relay/contacts` | Send a contact request |
| POST | `/api/relay/contacts/respond` | Accept/refuse a contact |
| POST | `/api/relay/approvals/{id}` | Approve/refuse a route |
| POST | `/api/relay/device` | Rename this device |
| POST | `/api/relay/enroll` | Start email enrollment |
| POST | `/api/relay/enroll/confirm` | Confirm the email code |

Credential passwords are never sent to the UI. The enrollment API may return a
certificate prompt when the TLS certificate of the enrollment endpoint is not
trusted (see [Security](#security)).

---

## System integration

### System tray

- **Routes** submenu: all routes plus **Auto**.
- **Open management page**: opens the embedded web UI.
- **Quit**.
- The menu updates immediately after route changes or force-route changes.

### System proxy (macOS only)

`SystemProxy: true` makes the proxy apply itself as the system HTTP/HTTPS proxy.
`SystemProxyExclude` lists network services/interfaces to leave untouched
(e.g. a VPN interface). The setting is re-applied periodically and after network
changes because VPN clients often overwrite it.

### Chrome policy (macOS only)

`ForceChrome: true` installs/removes a Chrome policy so Chrome uses the system
proxy configuration.

### Desktop notifications

On incoming **contact requests** and **route approval requests** the app shows a
desktop notification:

- macOS: Notification Center via `osascript`
- Linux: `notify-send`
- Windows: not implemented yet

Rapid notifications are throttled to avoid flooding.

---

## Relay

The relay is a **rendezvous server** with mutual TLS. It does not proxy traffic
itself: it keeps the address book and splices an encrypted stream between a
requesting proxy and the contact that agreed to open the connection.

- Identity is the **e-mail address** in the client certificate's SAN.
- The relay session is multiplexed with **yamux**; keepalive pings run every
  30 s (10 s timeout), so dead sessions are detected and reconnected.
- Each installation has a **device code**, so multiple computers of the same
  user can stay online simultaneously. Sessions are keyed by
  `(email, device)`.
- Contacts and explicit route approvals are required. The exit side can allow a
  destination once, always, or on any port; remembered rules are persisted.
- `AllowLocal` (off by default) controls whether contacts can reach services
  bound to the exit machine (loopback/link-local destinations are otherwise
  blocked).

### Relay client

**Recommended: enroll from the web UI**

1. Open the **Relay** page.
2. Enter the enrollment address (for example `proxy.intra.example.com` or
   `relay.example.com:8444`) and your e-mail.
3. Optionally paste the CA that signs the enrollment HTTPS endpoint if it is an
   internal CA.
4. Click **Invia richiesta**.
5. If the server certificate is not trusted, review the subject/issuer/SHA-256
   fingerprint and accept it only after verifying it with the relay
   administrator. The proxy pins that certificate for the enrollment.
6. Enter the code received by e-mail.
7. The proxy receives a client certificate, stores the certificate, private key
   and relay CA in the encrypted configuration, and starts the mTLS connection.

The relay's mTLS address is supplied by the enrollment response; it is never
hardcoded in the client. The certificate is signed from a CSR generated
locally; the private key never leaves the proxy.

**Manual / legacy**

You can also provision certificates with `proxyrelay` (see below) and set
`Relay.Address`, `Relay.Cert`, `Relay.Key`, `Relay.CA`. On the next start the
files are embedded into the encrypted configuration and the plaintext private
key is removed.

The Relay page shows connection status, route used, e-mail, device code,
contacts, incoming requests, pending approvals, and remembered rules. Use
**Riconfigura** to obtain a new certificate (for example after expiry).

### Devices

The first time a relay is configured, a device code is generated
(`adjective-animal-4hex`, e.g. `quiet-otter-7f3a`) and saved in the encrypted
configuration. It can be renamed from the Relay page; the client reconnects
under the new code.

Route syntax:

- `relay://alice@example.com` — use Alice's only online device. If Alice has more
  than one device online, the dial fails with a clear error instead of choosing
  one at random.
- `relay://alice@example.com/quiet-otter-7f3a` — use a specific device.

The Relay page lists **all your known devices** (online and offline), each with
its usable `relay://you@example.com/device` address. The relay remembers devices
across restarts. Your devices can be used directly, without sending a contact
request to yourself; the exit device still requires the normal route approval.
The page also lists the online devices of each contact; the route editor
autocompletes `relay://email/device` as you type and suggests hops already used
in other routes. Device codes are routing labels, not separate authentication:
devices sharing one certificate all authenticate as the same user.

### Contacts and route approvals

1. Add a contact by e-mail from the Relay page.
2. The contacted user accepts or refuses the request from their Relay page.
3. The first time traffic is sent through a contact, the exit side receives an
   approval request showing contact, **device**, host and port.
4. Approve once, remember the route (device + host/port), or remember it for any
   port.
5. Remembered rules are bound to the requesting device: another device of the
   same user must ask for approval again. Rules can be revoked from the Relay
   page.

### Network context of contacts

A contact device can tell its approved contacts where it is, so you can choose
an exit by its network and not only by whether it is online:

- **What is shared** (and nothing else): a **label** you choose for the network
  (`NetworkLabel`, at most 40 characters, for instance `office-vpn`) and
  whether a **VPN is active** on that device, detected as described above. No
  addresses, host names or domains leave the machine. `ShareContext: false`
  shares nothing at all. Both are set in Configuration → Relay.
- **Who sees it**: only your approved contacts and your own devices, never
  strangers. It is pushed again whenever the device's network changes, for
  instance when it connects to a VPN.
- **It is self-declared**: a contact can write any label. Use it to choose a
  route you trust, not as a security boundary. The exit still has to approve
  the connections it carries.
- **In routes and rules**: `ExitVPN` and `ExitLabel` (see the reference tables)
  restrict a route or a destination rule to exits that are on a VPN or not, or
  that carry a matching label. For example, a rule for `*.corp.example` can use
  the route through a colleague only while that colleague is on the office VPN,
  and fall through to the next rule otherwise. An exit that is offline or does
  not share its context never matches a condition: unknown is not treated as
  "no VPN". When the route has no device chosen and several are online, every
  one of them must satisfy the condition.
- Contacts running an older version share nothing and show as "network
  unknown". The relay (the `relay` package) must be updated for the context to
  be distributed.

### Contact status and link quality

The **Relay** page tells you whether a contact is worth using before you put it
in a route:

- **Status**: online or offline. For an offline contact the relay remembers when
  it was last online ("last seen 3 hours ago"); this is kept in the relay state
  file and survives restarts.
- **Latency**: every minute while the page is open (and on demand with *Test
  connections* or the per-device refresh button) the client sends a `ping`
  probe along the real path: this computer, the relay, the contact's computer
  and back. Nothing is opened on the other side, no destination is involved and
  no approval is requested, so probing never bothers the contact. The same
  probe without a contact measures the link to the relay itself.
- **Verdict**: *worth using* below 150 ms, *usable* below 400 ms, *slow* above.
  An online contact that does not answer is shown as *online, not reachable*
  (for instance when it runs a version that predates probes). The latency is
  that of the relay path; a real connection also pays the contact's own network.

Only your own devices and your contacts answer a probe, and a stranger cannot
use it to learn whether someone is online. `POST /api/relay/ping` with
`{"email": "", "device": ""}` returns `{"ok": true, "rttMs": 11.4}`; an empty
e-mail probes the relay.

### Relay server

Build and run the relay:

```bash
make relay
./proxyrelay ca init -dir ca
./proxyrelay ca server -dir ca -out server -host relay.example.com,proxy.intra.example.com
./proxyrelay ca client -dir ca -out alice -email alice@example.com

./proxyrelay serve \
  -listen :8443 \
  -cert server/server.pem \
  -key server/server-key.pem \
  -ca ca/ca.pem \
  -state relay-state.json
```

The CA private key (`ca/ca-key.pem`) is required only on the relay/server side
and should be protected. The example `ca client` command is for the legacy,
manual provisioning path; normal deployments use enrollment.

Main `serve` flags:

| Flag | Description |
|---|---|
| `-listen` | mTLS relay listen address (default `:8443`) |
| `-cert`, `-key` | Server certificate/key |
| `-ca` | CA that signs and verifies client certificates |
| `-state` | Address book/pending contact state file |
| `-enroll-listen` | HTTPS enrollment listen address (empty disables) |
| `-enroll-plain` | Serve enrollment over HTTP behind a trusted TLS proxy |
| `-public-relay` | mTLS address returned to clients (e.g. `relay.example.com:8443`) |
| `-public-url` | Enrollment URL shown in emails |
| `-download-url` | Proxy download URL shown in invitation emails |
| `-allow-domains` | Comma-separated exact e-mail domains allowed to enroll |
| `-ca-dir` | Directory with `ca.pem` and `ca-key.pem` (default: dir of `-ca`) |
| `-enroll-state` | Pending enrollment state file |
| `-cert-ttl` | Client certificate lifetime (default 90 days) |
| `-smtp-addr`, `-smtp-from` | SMTP server and From address |
| `-smtp-user`, `-smtp-pass` | SMTP credentials (password also via env) |
| `-smtp-tls` | `starttls` (default), `tls`, or `none` |
| `-smtp-auth` | `auto` (default), `plain`, `login`, or `none` |

The relay exits cleanly rather than serving a broken enrollment if SMTP is not
configured; it logs `enrollment disabled` and keeps the mTLS relay running.
This allows the SMTP secret to be created/filled separately from the relay
liveness.

### Manual certificate provisioning

The legacy workflow uses the CA CLI:

```bash
proxyrelay ca init -dir ca
proxyrelay ca server -dir ca -out server -host relay.example.com
proxyrelay ca client -dir ca -out alice -email alice@example.com
```

The client directory contains `client.pem`, `client-key.pem`, and `ca.pem`.
Copy them to the proxy machine and reference them from `Relay.Cert`,
`Relay.Key`, `Relay.CA`.

### Enrollment over email

The secure flow is:

1. The proxy generates a key pair locally and a CSR whose CN/SAN is the user's
   e-mail.
2. `POST /enroll` sends the CSR, e-mail and device code to the relay enrollment
   endpoint.
3. The relay validates the domain allowlist, the CSR signature and the CSR
   identity, applies rate limits, and creates a pending enrollment.
4. The relay sends a one-time **8-character code** by e-mail (15-minute TTL,
   maximum 5 attempts). Codes and poll tokens are stored only as hashes.
5. The proxy submits `POST /enroll/{id}/confirm` with the code and its poll
   token. The relay signs the CSR with the CA.
6. The certificate is returned and stored in the proxy's encrypted
   configuration; the proxy connects with mTLS.
7. The relay returns the CA that signs the mTLS server certificate separately
   (`relayCAPEM`), so the enrollment HTTPS endpoint can be protected by a
   different CA (for example an intranet wildcard).

Rate limits are 4 requests per e-mail and 12 per IP in a 10-minute window.
Allowed domains are **exact** matches; subdomains are not implicitly allowed.

If the enrollment endpoint's certificate is not trusted, the proxy never accepts
it silently: it shows subject, issuer and SHA-256 fingerprint and asks the user
to confirm. On confirmation the exact certificate is pinned (fingerprint +
hostname) for the enrollment and code confirmation. The pin is not persisted
after enrollment.

Invite a user who does not have the proxy yet:

```bash
proxyrelay invite \
  -email alice@example.com \
  -public-url https://proxy.intra.example.com \
  -download-url https://example.com/go-smart-proxy \
  -smtp-addr smtp.example.com:587 \
  -smtp-from relay@example.com
```

SMTP credentials can also come from `PROXYRELAY_SMTP_*` environment variables.

### Kubernetes deployment

[`deploy/relay-k8s.example.yaml`](deploy/relay-k8s.example.yaml) contains an
example deployment. Copy it to `deploy/relay-k8s.local.yaml` (ignored by git)
and adapt registry, domains, gateway name and storage class to your cluster:

- mTLS relay on `:2443`, exposed by a `LoadBalancer`;
- enrollment on `:2444`, exposed **only through an internal Istio gateway**
  (`proxy.intra.example.com` in the example);
- a `ClusterIP` service for the enrollment backend;
- TLS, CA-key, and SMTP secrets;
- a persistent volume for the address book and enrollment state.

Create the secrets first (names in the manifest), adapt domains/addresses, then:

```bash
cp deploy/relay-k8s.example.yaml deploy/relay-k8s.local.yaml
# edit deploy/relay-k8s.local.yaml for your environment
kubectl apply -f deploy/relay-k8s.local.yaml
```

The SMTP secret can start empty: the relay serves mTLS and logs
`enrollment disabled` until credentials are filled:

```bash
read -s SMTP_PASS
kubectl -n networking create secret generic proxy-relay-smtp \
  --from-literal=PROXYRELAY_SMTP_ADDR=smtp.example.com:587 \
  --from-literal=PROXYRELAY_SMTP_USER='user' \
  --from-literal=PROXYRELAY_SMTP_PASS="$SMTP_PASS" \
  --from-literal=PROXYRELAY_SMTP_FROM='relay@example.com' \
  --from-literal=PROXYRELAY_SMTP_TLS=starttls \
  --from-literal=PROXYRELAY_SMTP_AUTH=auto \
  --dry-run=client -o yaml | kubectl apply -f -
unset SMTP_PASS

kubectl -n networking rollout restart deploy/proxy-relay
```

The CA private key is mounted from `proxy-relay-ca`; restrict access to that
secret with RBAC. For a production CA, consider an offline signing service
rather than keeping the CA key in the cluster.

---

## Security

### Configuration and credentials

- `config.yml.enc` is encrypted with AES-256-GCM and a PBKDF2-derived key.
- The first-run setup page is served only on loopback and is protected by a
  random one-time token in the URL. No proxy service is exposed while setup is
  pending; the master password is sent only over loopback.
- The master password is the only universal recovery key. **Losing it means
  losing the configuration, credentials, relay certificate and private key.**
- On Unix the encrypted file is created with `0600`; the legacy plaintext file
  was also restricted before migration.
- The macOS Keychain stores the derived key (not the password) and gates reads
  with a Touch ID prompt when biometrics are available. This is an app-level
  check via `LocalAuthentication`; the Keychain item uses the login keychain.
  A same-user attacker can still target the running process or the Keychain.
  On Windows the derived key is stored in `config.key.dpapi`, protected with
  DPAPI for the current user. Like the Keychain, DPAPI protects the key from
  other users and offline disk access, not from processes running as the same
  user.
- `PROXY_NO_KEYCHAIN=1` disables the macOS Keychain and the Windows DPAPI store,
  forcing a master password prompt.
- The web API never returns credential passwords. An empty password on save
  keeps the existing one; send `"clearPassword": true` to remove it.
- The web UI/API are unauthenticated and loopback-only, and are protected
  against attacks from web pages open in your browser: the `Host` header must be
  a loopback name (this blocks DNS rebinding), cross-origin and cross-site
  requests are refused (`Origin`, `Sec-Fetch-Site`), and requests with a body
  must be `application/json`, so a page cannot reconfigure the proxy with a
  "simple" cross-site `POST`.
- The proxy refuses to connect to its own HTTP and SOCKS5 ports (and loopback
  addresses on them): a request forwarded to itself would arrive from loopback
  and bypass the checks above.
- The proxy/SOCKS listeners have no client authentication and forward with your
  upstream credentials, so by default **only clients on this machine are
  served**, even if the listener is bound to another address. Binding a
  non-loopback address is rejected by the API unless `AllowRemoteClients: true`
  (Configuration → "Allow other computers to use the proxy"). Configurations
  that already listened on a non-loopback address keep working after the
  upgrade (the option is turned on and a warning is logged): bind to
  `127.0.0.1` to turn it off.
- Listen addresses are validated before use, and values that reach `scutil` or
  Chrome's preferences are restricted to safe characters. Chrome's proxy policy
  is written with `defaults` and only touches `ProxyMode`, `ProxyServer` and
  `ProxyBypassList`; other Chrome preferences are preserved.
- Configuration, relay state and enrollment state files are written through a
  uniquely named temporary file created next to them, never a predictable
  `.tmp` name.
- `config.yml*`, `relay-pki`, `relay-certs`, `relay_state.json` and the built
  binaries are ignored by git. Never commit them.

### Relay

- Client identities are e-mail addresses from a CA-signed certificate.
- The private key is generated locally and never sent to the relay.
- Enrollment proves e-mail ownership with a one-time code; codes are hashed at
  rest, single-use, short-lived, attempt-limited and rate-limited.
- Allowed e-mail domains are exact-match allowlists.
- The CA private key is high-value: protect the file/secret with restrictive
  permissions and RBAC; ideally keep it offline and use a dedicated signing
  service.
- The relay exit side must approve routes; rules are per contact and
  destination. `AllowLocal` is off by default.
- Device codes are routing labels, not per-device credentials. Devices sharing a
  certificate authenticate as the same user.
- Enrollment TLS trust can be established by the system roots, an explicitly
  pasted CA, or the explicit fingerprint confirmation (TOFU). Always verify the
  fingerprint out-of-band when prompted.
- Certificate renewal is not automated. Certificates are short-lived (90 days
  by default); use **Riconfigura** to enroll again.
- Revocation: the server consults a deny-list file (`relay.NewRevocations`,
  assigned to `Server.Revoked`). Each line is an e-mail address (all its
  certificates) or `serial:<hex>`; the file is re-read when it changes, so
  revoked clients are refused at their next connection without restarting the
  relay. `relay.Revoke(path, entry)` appends an entry. There is no CRL/OCSP.
- The relay exit side caps the approval requests waiting for an answer (20 in
  total, 5 per contact), so a contact cannot flood you with prompts.
- E-mail addresses must contain exactly one `@`, which keeps the domain
  allow-list and the SMTP server from interpreting an address differently.
- Behind a reverse proxy, set `EnrollConfig.TrustForwardedFor` so the
  enrollment rate limit uses the client address from the proxy's
  `X-Forwarded-For` (last entry) instead of the proxy's own address. Leave it
  off when the endpoint is reachable directly. Expired enrollments and stale
  rate-limit entries are purged automatically.

### Email

- SMTP supports `starttls` (default), implicit TLS, and no TLS (trusted internal
  relays only).
- Authentication: `auto` (PLAIN, then LOGIN), `plain`, `login`, or `none`.
- Use `PROXYRELAY_SMTP_PASS`/the Kubernetes secret rather than a command-line
  password where possible (command-line arguments can appear in process lists).

---

## Environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `PROXY_MASTER_PASSWORD` | proxy | Master password for unattended startup |
| `PROXY_HOME` | proxy | Data directory for config, relay state and PAC cache |
| `PROXY_NO_KEYCHAIN` | proxy (macOS/Windows) | Disable the Keychain/DPAPI store; always prompt |
| `PROXY_TEST_KEYCHAIN` | tests | Run the opt-in Keychain bridge test |
| `PROXYRELAY_SMTP_ADDR` | relay | SMTP server `host:port` |
| `PROXYRELAY_SMTP_USER` | relay | SMTP username |
| `PROXYRELAY_SMTP_PASS` | relay | SMTP password |
| `PROXYRELAY_SMTP_FROM` | relay | From address |
| `PROXYRELAY_SMTP_TLS` | relay | `starttls`, `tls`, `none` |
| `PROXYRELAY_SMTP_AUTH` | relay | `auto`, `plain`, `login`, `none` |

Flags take precedence over environment variables when both are provided.

---

## Development

### Build

```bash
make build      # web UI + ./proxy
make relay      # CGO-free ./proxyrelay
make test       # go test ./...
make webui      # rebuild webui/dist only
```

The Go binary embeds `webui/dist`; a plain `go build .` fails if the UI has not
been built. Use `make build` (or `make webui` first).

Windows:

```bat
build.bat
```

macOS needs Xcode Command Line Tools for the CGO/system-tray/Keychain parts.

### Release packages

Local packaging:

```bash
./package.sh 0.1.0
```

The script rebuilds the web UI and writes versioned archives plus `SHA256SUMS`
to `dist/` (ignored by git):

- `go-smart-proxy_<version>_darwin_universal.tar.gz` — universal binary for
  Apple Silicon and Intel;
- `go-smart-proxy_<version>_darwin_universal.dmg` — `.app` bundle with drag to
  `/Applications`;
- `go-smart-proxy_<version>_windows_amd64.zip` — GUI binary without a console
  window;
- `go-smart-proxy_<version>_linux_amd64.tar.gz` — built in Docker so the GTK 3
  and Ayatana AppIndicator headers are available;
- `go-smart-proxy_<version>_linux_amd64.deb` and `.rpm` — when `nfpm` is
  installed locally (otherwise GitHub Actions builds them).

The Linux binary links GTK/AppIndicator dynamically and needs those libraries at
runtime; build other architectures with
`LINUX_ARCHS="amd64 arm64" ./package.sh <version>`. The archives contain the
binary, `README.md` and `LICENSE`; they do not contain configurations,
credentials or relay certificates.

### GitHub release

Pushing a `v*` tag runs `.github/workflows/release.yml`:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow builds the web UI once, then produces on native GitHub runners:

- macOS universal `.dmg` (with `.app` bundle) and `.tar.gz`;
- Windows amd64 `_setup.exe` (Inno Setup, per-user) and `.zip`;
- Linux amd64 `.deb`, `.rpm` and `.tar.gz`.

It also generates `SHA256SUMS` and publishes everything as assets of a GitHub
Release with generated notes. The release can be edited from the repository's
**Releases** page; no local Docker or cross-compiler is needed.

Install:

- **macOS**: open the `.dmg`, drag **Go Smart Proxy** to `/Applications`.
  The app is ad-hoc signed but **not notarized**; on first launch use
  right-click → **Open** (or remove the quarantine flag with
  `xattr -dr com.apple.quarantine "/Applications/Go Smart Proxy.app"`).
- **Windows**: run the `_setup.exe`. It is unsigned, so SmartScreen may show
  **More info → Run anyway**. The installer is per-user and can optionally
  create a startup entry.
- **Linux**:
  `sudo apt install ./go-smart-proxy_<version>_linux_amd64.deb` or
  `sudo dnf install ./go-smart-proxy_<version>_linux_amd64.rpm`.
  GTK 3 and Ayatana AppIndicator are runtime dependencies.

Installer signing/notarization is not configured: it requires an Apple Developer
ID certificate and a Windows code-signing certificate. The macOS bundle is
ad-hoc signed (`codesign -`), and `MACOS_SIGN_IDENTITY` can be set for a real
Developer ID signature in `installer/macos/build-dmg.sh`.

### Tests

```bash
go test ./...
go test -race ./...
```

The Keychain bridge test is opt-in and writes/deletes a test item in the real
login Keychain:

```bash
PROXY_TEST_KEYCHAIN=1 go test -run TestKeychainBridge
```

The test suite covers route selection, PAC caching, NTLM/CONNECT, HTTP/SOCKS5
tunnels, chains, relay contacts/approval, multi-device routing, encrypted
configuration/migration, enrollment (including certificate signing and TOFU),
and SMTP auth primitives.

### Web UI

- **Web UI**: React + TypeScript + Mantine + Vite, embedded in the binary. The UI
  language is selected from the browser locale (or manually) and supports the 24
  official languages of the European Union, with English as fallback.

If you change the UI, run `npm run build` in `webui/` or `make webui`; then
rebuild the Go binary so the new assets are embedded.

---

## Repository layout

| Path | Description |
|---|---|
| `main.go` | HTTP proxy, tunnels, listeners, tray, connection registry |
| `router.go` | Routes, PAC, transports, automatic route selection, DNS cache |
| `rules.go` | Destination rules and rules API |
| `chain.go` | Proxy chains, SOCKS5/HTTP hops, relay hop handling |
| `relay_client.go` | Relay client, address book, approvals, device identity |
| `relay_provision.go` | Proxy-side enrollment (CSR, code, certificate storage, TOFU) |
| `secret.go` | Config encryption, master password, Keychain/DPAPI integration |
| `setup.go` | First-run web setup (master password, defaults, onboarding flag) |
| `web.go`, `webui.go` | Web API, static UI embedding |
| `socks.go` | SOCKS5 listener and handler |
| `device.go` | Per-installation device code generation |
| `notify.go` | Desktop notifications |
| `relay/` | Relay protocol, server, store, CA, enrollment, SMTP |
| `cmd/proxyrelay/` | Relay server CLI |
| `webui/` | React management UI |
| `deploy/` | Kubernetes example |
| `Dockerfile.relay` | Relay image |

The Go module is named `proxy`; internal packages are imported as
`proxy/relay`.

---

## Troubleshooting

| Symptom | What to check |
|---|---|
| `PAC not available` | PAC URL reachable directly, cache in `cache/`, route's `Chain[].PacUrl`. |
| Route never selected | `Gateway`/`IFace`/`IFaceUp`/`VPN`/`Net` values against the "Network and VPN detection" panel on the Config page (the Routes table shows why a route is not applicable); `RulesOnly` flags. |
| Relay does not connect | `Relay.Address`, certificate/CA, `Relay.Route`, proxy logs; re-enroll from the Relay page. |
| `has multiple devices online: select one` | Use `relay://email/device`; see the device list on the Relay page. |
| Enrollment returns `403 dominio non abilitato` | The relay's `-allow-domains` must contain the **exact** domain. |
| Enrollment disabled / no email | SMTP secret/flags missing or wrong; relay logs `enrollment disabled`; restart after filling. |
| `x509: certificate signed by unknown authority` | Paste the enrollment CA, or accept the fingerprint prompt after verifying it. |
| Unlock page keeps asking for the password | `PROXY_NO_KEYCHAIN` set, DPAPI/Keychain entry missing or invalid, or the configuration was copied from another machine. Enter the master password once to store the key again. |
| Touch ID prompt does not appear | Keychain disabled (`PROXY_NO_KEYCHAIN`), no biometrics, or non-macOS; enter the master password. |
| `wrong master password or corrupted file` | The password is wrong or the file was modified. There is no recovery without the password. |
| Web UI returns `403` | UI/API are only available to loopback clients. |
| System proxy keeps being reset | A VPN client is rewriting it; use `SystemProxyExclude` or turn off the VPN's proxy enforcement. |
| Chrome ignores the proxy | Check PAC precedence and `ForceChrome` (macOS). |
| Relay server exits on startup | Missing `-cert/-key/-ca`; enrollment misconfiguration logs `enrollment disabled` but mTLS continues. |
| Relay clients all show device `default` | They are older clients that do not send a device code; update them. |
| `ld: warning: ignoring duplicate libraries: '-lobjc'` on macOS | Harmless linker warning from the combined systray/Keychain frameworks. |

---

## Limitations and roadmap

Current limitations:

- Master password rotation is not implemented (a new encrypted config must be
  created to change it).
- Certificate renewal is manual (Relay → Riconfigura); no revocation/CRL/OCSP.
- Enrollment invitations are initiated by the admin CLI; there is no admin web
  console or user database UI.
- The local API has no authentication; it is intended for loopback use.
- Windows lacks system proxy/PAC/Chrome policy/desktop notifications.
- Linux system tray requires the systray GTK/AppIndicator dependencies.
- The relay state file is single-instance; do not scale the relay horizontally.
- The macOS biometric gate is app-level `LocalAuthentication`; the Keychain item
  is not protected by a native biometric access-control ACL.

Possible future work:

- Rules/routes UX redesign: reusable upstream profiles, rule groups, a visual
  flow (`rule → profile → hop chain`), drag-and-drop ordering, and a richer
  destination tester.
- Per-device certificate identities (today device codes are routing labels and
  devices may share one certificate).
- Password rotation/rewrap tooling and recovery-key design.
- Automatic certificate renewal, revocation, and audit logs.
- Admin UI/API for invitations, users, and device management.
- Windows system proxy/PAC/Chrome/notifications.
- Signed macOS builds with native Keychain access control.
- Metrics/health endpoints, structured logs, and relay HA.

---

## Contributing

Issues and pull requests are welcome.

- Keep changes focused and consistent with the existing style.
- Run `gofmt`, `go vet ./...`, and `go test ./...` (and `-race` where possible).
- Rebuild the web UI when changing `webui/`.
- Never commit credentials, `config.yml*`, `relay-certs`, `relay-pki`, or relay
  state files.
- For security-sensitive changes (crypto, certificate handling, proxy
  authentication, relay), explain the threat model and add tests.

---

## License

Copyright the Go Smart Proxy contributors.

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).
