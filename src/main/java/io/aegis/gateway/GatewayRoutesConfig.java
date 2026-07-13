package io.aegis.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Programmatic routes to the backend services. Defined in code (rather than YAML) so they are
 * version-stable across gateway config-namespace changes. Downstream services enforce token
 * validation and scopes; the gateway routes and resolves tenant, it does not itself authorize.
 *
 * <p>Rate limiting (Redis-backed {@code RequestRateLimiter}) and per-tenant routing overrides are
 * documented enhancements — see ARCHITECTURE.md §8.
 */
@Configuration(proxyBeanMethods = false)
public class GatewayRoutesConfig {

    @Bean
    public RouteLocator aegisRoutes(RouteLocatorBuilder builder,
                                    @Value("${aegis.routes.authorization-server:http://localhost:9000}") String authz,
                                    @Value("${aegis.routes.identity-service:http://localhost:9102}") String identity,
                                    @Value("${aegis.routes.tenant-service:http://localhost:9101}") String tenant) {
        return builder.routes()
                .route("authorization-server", r -> r
                        .path("/oauth2/**", "/.well-known/**", "/login", "/connect/**", "/userinfo")
                        .uri(authz))
                .route("identity-service", r -> r
                        .path("/api/v1/users/**", "/api/v1/users:authenticate")
                        .uri(identity))
                .route("tenant-service", r -> r
                        .path("/api/v1/tenants/**", "/api/v1/tenants:resolve")
                        .uri(tenant))
                .build();
    }
}
