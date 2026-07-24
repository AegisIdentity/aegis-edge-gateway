package io.aegis.gateway;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Derives the tenant from the request host and injects the trusted internal {@code X-Aegis-Tenant}
 * header, after <em>stripping</em> any client-supplied value (the edge must never trust an inbound
 * tenant header — see ARCHITECTURE.md §5.1 / §8).
 *
 * <p>v1 uses a simple subdomain rule ({@code acme.aegis.io -> acme}). Production resolves the host via
 * {@code tenant-service} ({@code /api/v1/tenants:resolve}) with a cached lookup; that call is the
 * documented next step. Implemented as a plain WebFlux {@link WebFilter} (framework-stable) rather
 * than a gateway-specific filter.
 *
 * <p>M-edge-4: because the client-controlled {@code Host} drives tenant resolution AND the AS's issuer
 * reconstruction (via {@code preserveHostHeader}), a forged Host is a real threat. When
 * {@code aegis.gateway.allowed-hosts} is configured, requests whose Host is neither an exact match nor
 * a subdomain of a listed base domain are rejected with 404 — so only known gateway/tenant hostnames
 * ever reach the routes and get their Host preserved. Empty list = no enforcement (local dev / tests).
 *
 * <p>M-edge-5: inbound {@code X-Forwarded-*}/{@code Forwarded} headers are stripped here (the gateway
 * is the first trusted hop / single public entry point), so the gateway regenerates them from the real
 * connection and a client cannot spoof downstream host/redirect/issuer construction or the audit
 * source IP. Disable via {@code aegis.gateway.strip-forwarded-headers=false} only if a trusted,
 * header-setting proxy sits in front of the gateway.
 */
@Component
@Order(-1)
public class TenantResolutionWebFilter implements WebFilter {

    static final String TENANT_HEADER = "X-Aegis-Tenant";

    private static final List<String> FORWARDED_HEADERS = List.of(
            "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
            "X-Forwarded-Port", "X-Forwarded-Prefix", "X-Forwarded-Ssl");

    private final List<String> allowedHosts;
    private final boolean stripForwardedHeaders;

    public TenantResolutionWebFilter(
            @Value("${aegis.gateway.allowed-hosts:}") List<String> allowedHosts,
            @Value("${aegis.gateway.strip-forwarded-headers:true}") boolean stripForwardedHeaders) {
        this.allowedHosts = allowedHosts == null ? List.of() : allowedHosts;
        this.stripForwardedHeaders = stripForwardedHeaders;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String host = exchange.getRequest().getHeaders().getFirst("Host");

        // M-edge-4: reject forged/unknown hosts (actuator probes are exempt — they hit the pod IP with
        // a Host the allowlist won't contain).
        if (!isActuator(exchange) && !hostAllowed(host)) {
            exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
            return exchange.getResponse().setComplete();
        }

        String tenant = deriveTenant(host);

        ServerHttpRequest.Builder mutated = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove(TENANT_HEADER); // never trust client-supplied
                    if (stripForwardedHeaders) {
                        FORWARDED_HEADERS.forEach(headers::remove); // M-edge-5
                    }
                });
        if (tenant != null) {
            mutated.header(TENANT_HEADER, tenant);
        }
        return chain.filter(exchange.mutate().request(mutated.build()).build());
    }

    private boolean isActuator(ServerWebExchange exchange) {
        return exchange.getRequest().getPath().value().startsWith("/actuator");
    }

    /** True if no allowlist is configured, or the host exactly matches or is a subdomain of an entry. */
    private boolean hostAllowed(String host) {
        if (allowedHosts.isEmpty()) {
            return true;
        }
        if (host == null || host.isBlank()) {
            return false;
        }
        String hostname = host.split(":", 2)[0].toLowerCase();
        for (String allowed : allowedHosts) {
            String a = allowed.trim().toLowerCase();
            if (!a.isEmpty() && (hostname.equals(a) || hostname.endsWith("." + a))) {
                return true;
            }
        }
        return false;
    }

    /** Simple subdomain-based derivation; returns null when no tenant can be derived. */
    static String deriveTenant(String host) {
        if (host == null || host.isBlank()) {
            return null;
        }
        String hostname = host.split(":", 2)[0];
        String[] labels = hostname.split("\\.");
        if (labels.length < 3) {
            return null; // bare apex or localhost -> no tenant subdomain
        }
        String candidate = labels[0].toLowerCase();
        return candidate.matches("[a-z0-9][a-z0-9-]{0,62}") ? candidate : null;
    }
}
