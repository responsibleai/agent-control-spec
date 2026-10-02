# Destinations

**Purpose:** constrain HTTP requests to exact approved origins and methods.
The decision is runnable, but a trusted HTTP transport adapter is required.
It is not an SSRF firewall or a general network isolation layer.

**Point:** `pre_tool_call`, immediately before an actual HTTP dispatch.
**Target:** `$.target`, the request arguments. Register this control in the
HTTP operation's scope, not for unrelated local tools without destinations.

## Configure

`config.json` defaults to the illustrative origin
`https://api.example.com:443` and methods `GET`, `HEAD`. Replace the origin
with actual approved services. Matches are exact strings, not substrings
or wildcard suffixes. Lists must be nonempty strings.

The host parses the actual request URL and supplies:

```json
{
  "extensions": {
    "policy_packs": {
      "destination": {
        "origin": "https://api.example.com:443",
        "method": "GET",
        "has_credentials": false
      }
    }
  }
}
```

`origin` is the canonical `scheme://host:effective-port` derived by the
transport, with normalized scheme and host and an explicit port.
Use bracketed IPv6 hosts if applicable. `method` is the actual uppercase
HTTP method. `has_credentials` means the URL contains userinfo, not that
the host uses a legitimate authorization header.

Missing or malformed fields deny with `destination_data_invalid`.
Unlisted origins/methods or userinfo deny with `destination_denied`.

## Install and trust boundary

Use the [shared install](../README.md#install-and-run), then register
`AcsInterceptor("policy/packs/destinations/manifest.yaml")` in the HTTP
emitter. Only the trusted parser/transport may supply destination metadata.
An agent saying that its URL is approved must have no effect.

Disable automatic redirects or mediate every redirect hop with its actual
destination, method and credential handling. Bind the checked metadata to
the immutable request used for dispatch. Apply independent resolved-address
and network controls where private-address access is forbidden. ACS does
not resolve DNS, stop rebinding, constrain proxies, check URL paths, sanitize
headers or prevent another socket path from bypassing the gate.

## Cases

Tests allow exact GET/HEAD, deny POST by default, and reject lookalike
suffixes, userinfo-shaped origins, wrong ports/schemes and missing metadata.
These prove exact matching, not that a particular URL parser or transport
implements this contract. Composition tests cover legitimate requests and
credential disclosure. Application authorization must still constrain
resources and query/body contents within an allowed origin.
