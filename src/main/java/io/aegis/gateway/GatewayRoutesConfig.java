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
                                    @Value("${aegis.routes.tenant-service:http://localhost:9101}") String tenant,
                                    @Value("${aegis.routes.social-broker:http://localhost:9105}") String social,
                                    @Value("${aegis.routes.mfa:http://localhost:9103}") String mfa) {
        // Strip Origin before forwarding: the edge owns CORS (globalcors), so downstream services
        // must not add their own Access-Control-Allow-Origin (that would duplicate the header and the
        // browser would reject it).
        return builder.routes()
                .route("authorization-server", r -> r
                        .path("/oauth2/**", "/.well-known/**", "/login", "/connect/**", "/userinfo",
                                "/api/v1/applications/**", "/api/v1/applications")
                        .filters(f -> f.removeRequestHeader("Origin"))
                        .uri(authz))
                .route("identity-service", r -> r
                        .path("/api/v1/users/**", "/api/v1/users:authenticate", "/api/v1/groups/**",
                                "/api/v1/onboarding", "/api/v1/signup", "/api/v1/signup-policy",
                                "/api/v1/auth-policy", "/api/v1/branding", "/api/v1/branding/**",
                                "/api/v1/system-log")
                        .filters(f -> f.removeRequestHeader("Origin"))
                        .uri(identity))
                .route("mfa-webauthn-service", r -> r
                        .path("/api/v1/mfa/**")
                        .filters(f -> f.removeRequestHeader("Origin"))
                        .uri(mfa))
                .route("tenant-service", r -> r
                        .path("/api/v1/tenants/**", "/api/v1/tenants:resolve")
                        .filters(f -> f.removeRequestHeader("Origin"))
                        .uri(tenant))
                .route("social-broker-service", r -> r
                        .path("/api/v1/identity-providers/**", "/api/v1/identity-providers")
                        .filters(f -> f.removeRequestHeader("Origin"))
                        .uri(social))
                .build();
    }
}
