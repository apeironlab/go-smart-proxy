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