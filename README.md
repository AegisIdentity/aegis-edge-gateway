# aegis-edge-gateway

The single public entry point (Spring Cloud Gateway 2025.1.2, **reactive**). Routes to services,
resolves the tenant from the request host, and is where TLS, rate limiting, and WAF hooks live.
Port `8080`.

## Build
```bash
mvn verify   # 9 tests: tenant derivation + context load
```
