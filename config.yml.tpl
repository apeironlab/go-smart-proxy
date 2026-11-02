# Go Smart Proxy configuration.
#
# This is the initial/legacy plaintext format. At the first start the proxy asks
# for a master password, encrypts the whole configuration (including the relay
# certificate and private key) into config.yml.enc and removes this file.
# From then on only the encrypted file is read and written.
#
# The master password can decrypt the file anywhere (backup/restore). On macOS
# the derived key is also stored in the login Keychain and can be unlocked with
# Touch ID; set PROXY_NO_KEYCHAIN=1 to always ask for the master password.
Address: 127.0.0.1:3128
# Optional SOCKS5 listener; it uses the same routes and rules of the HTTP proxy.
# Leave empty/omitted to disable it.
# SocksAddress: 127.0.0.1:1080
Credentials:
- Name: CredentialName
  User: username or domain\username
  Password: *****
Routes:
- Name: Route name
  # Filters to apply the route
  Gateway: Gateway ip
  # Specify a PAC URL
  PacUrl: PAC url
  # Or an upstream Proxy URL (ignored if PAC is specified)
  ProxyUrl: upstream proxy URL
  # Optional: the credential name if authentication is required
  Credential: CredentialName
  # Or a chain of proxies (takes precedence over PacUrl/ProxyUrl): the first one is
  # dialed directly, each next one is reached through the previous ones.
  # Supported schemes: http:// (CONNECT, NTLM/Basic) and socks5://
  # Chain:
  # - ProxyUrl: http://corporate-proxy:8080
  #   Credential: CredentialName
  # - ProxyUrl: socks5://other-proxy:1080
  #   # The chain stops before this hop unless a destination rule selects the route.
  #   RulesOnly: true
  # Optional: use this route only when a destination rule names it. It is never
  # picked as the automatic (default) route; for the relay connection only the
  # hops before a relay:// hop are used.
  # RulesOnly: true
# Optional: connection to a relay (see cmd/proxyrelay) to exit through the network of your contacts.
# You can configure it by hand here, or leave it out and use the "Relay" page in
# the web UI: enter the enrollment address and your e-mail, confirm the code
# received by mail, and the proxy will obtain and store its certificate.
# The relay is reached through the currently applicable route (direct, proxy, chain...).
# Use "relay://their@email" in a route's Chain: the relay hop is where the proxy
# chain stops. For the connection to the relay server only the hops before it are
# used; the hops after it are reached through the contact's network.
# Relay:
#   Address: relay.example.com:8443
#   Cert: relay/client.pem
#   Key: relay/client-key.pem
#   CA: relay/ca.pem
#   # At the first start these files are embedded in config.yml.enc and the
#   # private key file is removed; only the encrypted file is then needed.
#   # Device identifies this computer; it is generated automatically when empty.
#   # Device: quiet-otter-7f3a
#   Route: ""          # optional: force a specific route to reach the relay
#   AllowLocal: false  # let contacts reach services on this machine (not recommended)
# Optional: hostnames dialed at a fixed IP address, whatever the system DNS says
Hosts:
  internal.example.com: 10.0.0.10
