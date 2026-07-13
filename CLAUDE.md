# aegis-edge-gateway — working notes

**Maturity: functional.** Reactive Spring Cloud Gateway. Package `io.aegis.gateway`. Port 8080.

## Where things are
- `GatewayRoutesConfig` — programmatic `RouteLocator` (code, not YAML, for version stability).
- `TenantResolutionWebFilter` — derives tenant from Host subdomain, **strips** any client-supplied
  `X-Aegis-Tenant` and injects the trusted one. Plain WebFlux `WebFilter` (framework-stable).

## Non-negotiables
- The edge must NEVER trust an inbound `X-Aegis-Tenant` header — always derive it (ARCHITECTURE.md §5.1).
- The gateway routes/resolves; it does not authorize. Downstream services validate tokens + scopes.

## Next steps
Replace subdomain derivation with a cached `tenant-service` `/api/v1/tenants:resolve` lookup; add a
Redis-backed `RequestRateLimiter`; wire TLS + WAF at the edge (see infra).

## Build / test
`mvn verify`.
