package io.aegis.gateway;

import java.util.function.Consumer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RateLimiter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Programmatic routes to the backend services. Defined in code (rather than YAML) so they are
 * version-stable across gateway config-namespace changes. Downstream services enforce token
 * validation and scopes; the gateway routes and resolves tenant, it does not itself authorize.
 *
 * <p>M-edge-3: when {@code aegis.ratelimit.enabled=true}, the credential-facing routes (auth/token/
 * login, per-tenant issuer, tenant-app embedded auth, MFA/WebAuthn) carry a Redis-backed
 * {@code RequestRateLimiter} keyed per-tenant+IP (see {@link RateLimitConfig}). Disabled by default so
 * local dev / tests boot without Redis. Per-tenant routing overrides remain a documented enhancement
 * (ARCHITECTURE.md §8).
 *
 * <p>L-edge-3: downstream URIs come from {@code aegis.routes.*} (env-overridable), so the scheme is
 * configurable — default to {@code https://} and rely on service-mesh mTLS in prod; the plaintext
 * {@code http://localhost} fallbacks are for local dev only.
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
                                    @Value("${aegis.routes.scim:http://localhost:9106}") String scim,
                                    @Value("${aegis.ratelimit.enabled:false}") boolean rateLimitEnabled,
                                    ObjectProvider<RateLimiter> rateLimiters,
                                    ObjectProvider<KeyResolver> keyResolvers) {
        // M-edge-3: build the rate-limit filter once (no-op when disabled or beans absent), then apply
        // it only to the credential-facing routes below.
        RateLimiter<?> rateLimiter = rateLimitEnabled ? rateLimiters.getIfAvailable() : null;
        KeyResolver keyResolver = rateLimitEnabled ? keyResolvers.getIfAvailable() : null;
        Consumer<GatewayFilterSpec> rateLimit = (rateLimiter != null && keyResolver != null)
                ? f -> f.requestRateLimiter(c -> c.setRateLimiter(rateLimiter).setKeyResolver(keyResolver))
                : f -> { };
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
                        .filters(f -> { f.removeRequestHeader("Origin").preserveHostHeader(); rateLimit.accept(f); return f; })
                        .uri(authz))
                // Per-tenant issuer paths: /{tenant}/oauth2/*, /{tenant}/.well-known/*, /{tenant}/userinfo.
                // This is what makes http://localhost:8080/{tenant} a fully working OIDC issuer.
                .route("authorization-server-tenant-issuer", r -> r
                        .path("/*/oauth2/**", "/*/.well-known/**", "/*/userinfo", "/*/connect/**")
                        .filters(f -> { f.removeRequestHeader("Origin").preserveHostHeader(); rateLimit.accept(f); return f; })
                        .uri(authz))
                // Tenant-app embedded auth (passkeys, native social, interaction-code exchange) — called
                // from tenants' own web/mobile apps; CORS for these paths is permissive at the edge
                // (bearer/PKCE-code based, no cookies — see application.yml globalcors).
                .route("authorization-server-tenant-app", r -> r
                        .path("/api/v1/webauthn/**", "/api/v1/social/**", "/api/v1/oauth/interaction/**")
                        .filters(f -> { f.removeRequestHeader("Origin").preserveHostHeader(); rateLimit.accept(f); return f; })
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
                        .filters(f -> { f.removeRequestHeader("Origin"); rateLimit.accept(f); return f; })
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
