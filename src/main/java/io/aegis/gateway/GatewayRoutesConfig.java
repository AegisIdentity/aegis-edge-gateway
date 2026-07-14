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
                                    @Value("${aegis.routes.mfa:http://localhost:9103}") String mfa,
                                    @Value("${aegis.routes.admin-api:http://localhost:9107}") String adminApi,
                                    @Value("${aegis.routes.scim:http://localhost:9106}") String scim) {
        // Strip Origin before forwarding: the edge owns CORS (globalcors), so downstream services
        // must not add their own Access-Control-Allow-Origin (that would duplicate the header and the
        // browser would reject it).
        return builder.routes()
                // The AS reconstructs the issuer from the request Host (multipleIssuersAllowed), so
                // preserveHostHeader makes tokens minted through the gateway carry the GATEWAY host as
                // issuer (http://localhost:8080[/tenant]) — the gateway is the public issuer front-door.
                // Direct :9000 traffic keeps the AS host as issuer; both are on the services' allowlist.
                .route("authorization-server", r -> r
                        .path("/oauth2/**", "/.well-known/**", "/login", "/login/**", "/connect/**",
                                "/userinfo", "/logout", "/mfa", "/error", "/webjars/**", "/assets/**",
                                "/favicon.ico", "/saml2/**",
                                "/api/v1/applications/**", "/api/v1/applications")
                        .filters(f -> f.removeRequestHeader("Origin").preserveHostHeader())
                        .uri(authz))
                // Per-tenant issuer paths: /{tenant}/oauth2/*, /{tenant}/.well-known/*, /{tenant}/userinfo.
                // This is what makes http://localhost:8080/{tenant} a fully working OIDC issuer.
                .route("authorization-server-tenant-issuer", r -> r
                        .path("/*/oauth2/**", "/*/.well-known/**", "/*/userinfo", "/*/connect/**")
                        .filters(f -> f.removeRequestHeader("Origin").preserveHostHeader())
                        .uri(authz))
                // Tenant-app embedded auth (passkeys, native social, interaction-code exchange) — called
                // from tenants' own web/mobile apps; CORS for these paths is permissive at the edge
                // (bearer/PKCE-code based, no cookies — see application.yml globalcors).
                .route("authorization-server-tenant-app", r -> r
                        .path("/api/v1/webauthn/**", "/api/v1/social/**", "/api/v1/oauth/interaction/**")
                        .filters(f -> f.removeRequestHeader("Origin").preserveHostHeader())
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
                        .path("/api/v1/tenants/**", "/api/v1/tenants:resolve",
                                "/api/v1/domains/**", "/api/v1/domains")
                        .filters(f -> f.removeRequestHeader("Origin"))
                        .uri(tenant))
                .route("social-broker-service", r -> r
                        .path("/api/v1/identity-providers/**", "/api/v1/identity-providers")
                        .filters(f -> f.removeRequestHeader("Origin"))
                        .uri(social))
                .route("admin-api-service", r -> r
                        .path("/api/v1/admin/**")
                        .filters(f -> f.removeRequestHeader("Origin"))
                        .uri(adminApi))
                .route("scim-provisioning-service", r -> r
                        .path("/scim/v2/**", "/api/v1/provisioning/**")
                        .filters(f -> f.removeRequestHeader("Origin"))
                        .uri(scim))
                .build();
    }
}
