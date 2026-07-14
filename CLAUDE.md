# aegis-edge-gateway — working notes

**Maturity: functional.** Reactive Spring Cloud Gateway. Package `io.aegis.gateway`. Port 8080.

## Where things are
- `GatewayRoutesConfig` — programmatic `RouteLocator` (code, not YAML, for version stability).
- `TenantResolutionWebFilter` — derives tenant from Host subdomain, **strips** any client-supplied
  `X-Aegis-Tenant` and injects the trusted one. Plain WebFlux `WebFilter` (framework-stable).

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

## Next steps
Replace subdomain derivation with a cached `tenant-service` `/api/v1/tenants:resolve` lookup; add a
Redis-backed `RequestRateLimiter`; wire TLS + WAF at the edge (see infra).

## Build / test
`mvn verify`.
