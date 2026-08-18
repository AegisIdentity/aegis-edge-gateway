# aegis-edge-gateway — working notes

**Maturity: functional.** Reactive Spring Cloud Gateway. Package `io.aegis.gateway`. Port 8080.

## Where things are
- `GatewayRoutesConfig` — programmatic `RouteLocator` (code, not YAML, for version stability).
- `TenantResolutionWebFilter` — resolves the tenant from the Host, **strips** any client-supplied
  `X-Aegis-Tenant` and injects the trusted one. Plain WebFlux `WebFilter` (framework-stable).
- `TenantResolver` / `TenantResolverConfig` — cached host->tenant lookup against tenant-service
  (`/api/v1/internal/domains/resolve`). Enable with `aegis.gateway.tenant-resolution.enabled=true`.

## Non-negotiables
- The edge must NEVER trust an inbound `X-Aegis-Tenant` header — always derive it (ARCHITECTURE.md §5.1).
- The gateway routes/resolves; it does not authorize. Downstream services validate tokens + scopes.
- **The gateway IS the public per-tenant issuer front-door**: `/{tenant}/oauth2/**`,
  `/{tenant}/.well-known/**`, `/{tenant}/userinfo`, hosted-login paths and the tenant-app endpoints
  route to the AS with `preserveHostHeader()`, so SAS reconstructs the issuer as
  `http://<gateway-host>/{tenant}`. Do not remove `preserveHostHeader` — issuer URLs in every tenant's
  integration (and the in-console docs) depend on it.
- CORS is path-split in application.yml: tenant-app + per-tenant OAuth paths are permissive
  (no-credentials, bearer/PKCE-based — CORS is not the auth boundary there); everything else stays
  locked to the console origin. Specific entries MUST precede the `[/**]` catch-all (first match wins).

## Tenant resolution
Custom sign-in domains (`login.acme.com`) CANNOT be resolved by the subdomain rule — nothing in that
hostname names the tenant, and the rule would answer `login`. `TenantResolver` asks tenant-service,
which is the only component that knows the mapping and answers only for DNS-verified domains.
Results are cached (positive 5m, negative 30s — negatives are cached so unknown hosts can't amplify
traffic to tenant-service, but briefly so a newly-verified domain starts working quickly). An
upstream failure is NOT cached, and degrades to the subdomain guess rather than a wrong tenant.

The gateway authenticates with a client whose ONLY scope is `tenant:resolve` — deliberately not
`tenant:platform-admin`, which also authorizes creating/modifying tenants. The gateway is the one
internet-facing component, so its credential must not be able to alter the control plane.

Off by default (`AEGIS_TENANT_RESOLUTION_ENABLED`) so the gateway boots with no dependency on
tenant-service or a client secret.

## Next steps
Add a Redis-backed `RequestRateLimiter` (implemented, enable via `AEGIS_RATELIMIT_ENABLED`); wire
TLS + WAF at the edge (see infra).

## Build / test
`mvn verify`.
