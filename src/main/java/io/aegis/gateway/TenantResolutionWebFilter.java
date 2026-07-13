package io.aegis.gateway;

import org.springframework.core.annotation.Order;
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
 */
@Component
@Order(-1)
public class TenantResolutionWebFilter implements WebFilter {

    static final String TENANT_HEADER = "X-Aegis-Tenant";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String host = exchange.getRequest().getHeaders().getFirst("Host");
        String tenant = deriveTenant(host);

        ServerHttpRequest.Builder mutated = exchange.getRequest().mutate()
                .headers(headers -> headers.remove(TENANT_HEADER)); // never trust client-supplied
        if (tenant != null) {
            mutated.header(TENANT_HEADER, tenant);
        }
        return chain.filter(exchange.mutate().request(mutated.build()).build());
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
