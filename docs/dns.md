# DNS Resolution

Warden resolves DNS for all upstream connections. The agent never performs DNS resolution directly — it sends hostnames to Warden via the proxy protocol, and Warden resolves them.

## Why Warden controls DNS

- **DNS rebinding prevention** — An agent tricks DNS into resolving an allowed hostname to a private IP. Warden validates resolved IPs against a configurable denylist.
- **Policy bypass prevention** — An agent resolves a hostname and connects to the IP directly. Since Warden resolves, the agent never sees the IP.
- **Consistent resolution** — All DNS goes through the same resolver configuration, regardless of the agent's environment.

## Configuration

```yaml
dns:
  servers: ["8.8.8.8:53", "1.1.1.1:53"]     # Upstream DNS servers
  dot:
    enabled: false                             # DNS-over-TLS
    server: "1.1.1.1:853"                     # DoT server address
  cache:
    enabled: true
    max_ttl: 300                               # Cache TTL in seconds
  deny_resolved_ips:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "169.254.0.0/16"
    - "127.0.0.0/8"
    - "::1/128"
```

## Resolvers

### Standard DNS (default)

Plain DNS over UDP using Go's stdlib `net.Resolver`. If `dns.servers` is configured, queries go to the first listed server. Otherwise, the system resolver is used.

### DNS-over-TLS (DoT)

Encrypts DNS queries using TLS (port 853). Prevents DNS traffic inspection and tampering by intermediate networks.

```yaml
dns:
  dot:
    enabled: true
    server: "1.1.1.1:853"
```

When DoT is enabled, it replaces the standard resolver. The `dns.servers` list is ignored. TLS is configured with minimum version 1.2 and SNI verification against the server hostname.

If the port is omitted from `server`, it defaults to 853.

### Caching Resolver

Wraps either the standard or DoT resolver with a TTL-based cache. Cache entries expire at the configured `max_ttl` (default: 300 seconds). Reduces latency and upstream DNS load for repeated lookups.

```yaml
dns:
  cache:
    enabled: true
    max_ttl: 300
```

## IP Denylist

After resolving a hostname, Warden checks the resulting IP against `deny_resolved_ips`. If the IP falls within any denied CIDR range, the request is rejected — even if the hostname matched an allow policy.

This catches DNS rebinding attacks: an attacker configures `evil.example.com` to resolve to `169.254.169.254` (cloud metadata). The hostname might not match any deny policy, but the resolved IP will be blocked.

### Recommended denylists

```yaml
deny_resolved_ips:
  # RFC 1918 private ranges
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "192.168.0.0/16"

  # Link-local (includes cloud metadata 169.254.169.254)
  - "169.254.0.0/16"

  # Loopback
  - "127.0.0.0/8"

  # IPv6 loopback
  - "::1/128"

  # IPv6 link-local
  - "fe80::/10"
```

Both IPv4 and IPv6 CIDRs are supported.
