Address: 127.0.0.1:3128
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
  # Optional: use this route only when a destination rule names it. It is never
  # picked as the automatic (default) route, nor to reach the relay.
  # RulesOnly: true
# Optional: connection to a relay (see cmd/proxyrelay) to exit through the network of your contacts.
# The relay is reached through the currently applicable route (direct, proxy, chain...).
# Use "relay://their@email" as the first hop of a route's Chain.
# Relay:
#   Address: relay.example.com:8443
#   Cert: relay/client.pem
#   Key: relay/client-key.pem
#   CA: relay/ca.pem
#   Route: ""          # optional: force a specific route to reach the relay
#   AllowLocal: false  # let contacts reach services on this machine (not recommended)
# Optional: hostnames dialed at a fixed IP address, whatever the system DNS says
Hosts:
  internal.example.com: 10.0.0.10
