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
 * <p><b>Resolution order.</b> When {@code aegis.gateway.tenant-resolution.enabled} is set, the host is
 * resolved against {@code tenant-service} via {@link TenantResolver} (cached), which is the only way
 * a white-label custom domain can work: nothing in {@code login.acme.com} identifies the tenant, and
 * the subdomain rule would confidently answer {@code login} — the wrong tenant. The subdomain rule
 * ({@code acme.aegis.io -> acme}) remains the fallback when resolution is disabled or returns
 * nothing. Implemented as a plain WebFlux {@link WebFilter} (framework-stable) rather than a
 * gateway-specific filter.
 *
 * <p>The tenant header is a routing/context hint only — every downstream service re-derives the
 * acting tenant from the JWT rather than trusting it — so a failed lookup degrades routing but
 * cannot grant cross-tenant access. The control that stops a forged {@code Host} is the allowlist
 * below.
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
    private final org.springframework.beans.factory.ObjectProvider<TenantResolver> tenantResolver;
    private final io.aegis.commons.audit.AuditEventPublisher auditPublisher;

    /**
     * Subdomain-derivation only — no tenant-service lookup, no audit. Used by tests and by any
     * deployment that has not enabled {@code aegis.gateway.tenant-resolution}.
     */
    TenantResolutionWebFilter(List<String> allowedHosts, boolean stripForwardedHeaders) {
        this(allowedHosts, stripForwardedHeaders, noResolver());
    }

    private static org.springframework.beans.factory.ObjectProvider<TenantResolver> noResolver() {
        return new org.springframework.beans.factory.ObjectProvider<>() {
            @Override
            public TenantResolver getObject() {
                throw new IllegalStateException("no TenantResolver configured");
            }

            @Override
            public TenantResolver getObject(Object... args) {
                return getObject();
            }

            @Override
            public TenantResolver getIfAvailable() {
                return null;
            }

            @Override
            public TenantResolver getIfUnique() {
                return null;
            }
        };
    }

    /** Resolver but no audit — used by tests that exercise the resolver path without Kafka. */
    TenantResolutionWebFilter(List<String> allowedHosts, boolean stripForwardedHeaders,
            org.springframework.beans.factory.ObjectProvider<TenantResolver> tenantResolver) {
        this(allowedHosts, stripForwardedHeaders, tenantResolver, (io.aegis.commons.audit.AuditEventPublisher) null);
    }

    /** Test/direct constructor — resolver provider + a resolved audit publisher (may be null). */
    TenantResolutionWebFilter(List<String> allowedHosts, boolean stripForwardedHeaders,
            org.springframework.beans.factory.ObjectProvider<TenantResolver> tenantResolver,
            io.aegis.commons.audit.AuditEventPublisher auditPublisher) {
        this.allowedHosts = allowedHosts == null ? List.of() : allowedHosts;
        this.stripForwardedHeaders = stripForwardedHeaders;
        this.tenantResolver = tenantResolver;
        this.auditPublisher = auditPublisher;
    }

    // Spring injects this one. It takes ObjectProviders so both collaborators are optional; the
    // (List, boolean, ObjectProvider, AuditEventPublisher) test constructor above is a distinct
    // signature (a resolved publisher, not a provider), so there is no overload ambiguity except for
    // a bare null — which the delegating constructors always cast.
    @org.springframework.beans.factory.annotation.Autowired
    public TenantResolutionWebFilter(
            @Value("${aegis.gateway.allowed-hosts:}") List<String> allowedHosts,
            @Value("${aegis.gateway.strip-forwarded-headers:true}") boolean stripForwardedHeaders,
            org.springframework.beans.factory.ObjectProvider<TenantResolver> tenantResolver,
            org.springframework.beans.factory.ObjectProvider<
                    io.aegis.commons.audit.AuditEventPublisher> auditPublisher) {
        this(allowedHosts, stripForwardedHeaders, tenantResolver,
                auditPublisher == null ? null : auditPublisher.getIfAvailable());
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String host = exchange.getRequest().getHeaders().getFirst("Host");

        // M-edge-4: reject forged/unknown hosts (actuator probes are exempt — they hit the pod IP with
        // a Host the allowlist won't contain).
        if (!isActuator(exchange) && !hostAllowed(host)) {
            auditForgedHost(exchange, host);
            exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
            return exchange.getResponse().setComplete();
        }

        // Ask tenant-service which tenant owns this host (the only component that knows, and the
        // only way custom domains like login.acme.com can resolve at all). Fall back to the
        // subdomain guess when no resolver is configured or the lookup yields nothing.
        TenantResolver resolver = this.tenantResolver.getIfAvailable();
        Mono<String> resolved = (resolver == null)
                ? Mono.justOrEmpty(deriveTenant(host))
                // flatMap + justOrEmpty, NOT map: the fallback legitimately yields null for hosts
                // with no derivable tenant (localhost, an apex domain), and Reactor treats a null
                // from map() as a fatal NullPointerException rather than an empty signal — which
                // took down every request including the health probe.
                : resolver.resolve(host)
                        .flatMap(maybe -> Mono.justOrEmpty(maybe.orElseGet(() -> deriveTenant(host))));

        return resolved
                .defaultIfEmpty("")
                .flatMap(tenant -> chain.filter(exchange.mutate()
                        .request(withTenantHeader(exchange, tenant.isBlank() ? null : tenant)).build()));
    }

    /** Strip anything client-supplied, then inject the tenant we derived ourselves. */
    private ServerHttpRequest withTenantHeader(ServerWebExchange exchange, String tenant) {
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
        return mutated.build();
    }

    private boolean isActuator(ServerWebExchange exchange) {
        return exchange.getRequest().getPath().value().startsWith("/actuator");
    }

    /**
     * Emit an edge-security event when a forged/unknown Host is rejected — a genuine attack signal
     * (someone trying to drive tenant/issuer resolution with a Host they don't own). Built explicitly
     * (not via {@code AuditEvent.of}) because that reads a {@code ThreadLocal} tenant/MDC that is not
     * meaningful on the reactive edge. Best-effort and null-safe; never affects the response.
     */
    private void auditForgedHost(ServerWebExchange exchange, String host) {
        if (auditPublisher == null) {
            return;
        }
        try {
            String remote = exchange.getRequest().getRemoteAddress() == null ? null
                    : String.valueOf(exchange.getRequest().getRemoteAddress().getAddress());
            auditPublisher.publish(new io.aegis.commons.audit.AuditEvent(
                    "edge", "edge.host.rejected", io.aegis.commons.audit.AuditOutcome.DENIED,
                    null, "anonymous", host, null, java.time.Instant.now(),
                    remote == null ? java.util.Map.of() : java.util.Map.of("remoteAddr", remote)));
        } catch (RuntimeException ignored) {
            // audit must never break request handling
        }
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
