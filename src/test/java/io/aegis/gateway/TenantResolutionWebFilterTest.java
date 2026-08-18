package io.aegis.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

class TenantResolutionWebFilterTest {

    @ParameterizedTest
    @CsvSource({
            "acme.aegis.io,acme",
            "login.acme.aegis.io,login",
            "ACME.aegis.io,acme",
            "acme.aegis.io:8443,acme"
    })
    void derives_tenant_from_subdomain(String host, String expected) {
        assertThat(TenantResolutionWebFilter.deriveTenant(host)).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource({"aegis.io", "localhost", "localhost:8080"})
    void no_tenant_for_apex_or_localhost(String host) {
        assertThat(TenantResolutionWebFilter.deriveTenant(host)).isNull();
    }

    @Test
    void null_or_blank_host_yields_no_tenant() {
        assertThat(TenantResolutionWebFilter.deriveTenant(null)).isNull();
        assertThat(TenantResolutionWebFilter.deriveTenant("  ")).isNull();
    }

    // ---- M-edge-4 / M-edge-5 behavioral coverage (filter is actually invoked here) ----

    @Test
    void allowed_host_injects_trusted_tenant_and_strips_client_headers() {
        // allowlist permits the aegis.io base domain; acme.aegis.io is an allowed subdomain.
        var filter = new TenantResolutionWebFilter(List.of("aegis.io"), true);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/users")
                        .header("Host", "acme.aegis.io")
                        .header(TenantResolutionWebFilter.TENANT_HEADER, "victim")   // forged -> stripped
                        .header("X-Forwarded-For", "1.2.3.4")                        // spoofed -> stripped
                        .header("X-Forwarded-Host", "evil.example"));

        ServerHttpRequest[] seen = new ServerHttpRequest[1];
        filter.filter(exchange, ex -> {
            seen[0] = ex.getRequest();
            return reactor.core.publisher.Mono.empty();
        }).block();

        var headers = seen[0].getHeaders();
        assertThat(headers.getFirst(TenantResolutionWebFilter.TENANT_HEADER)).isEqualTo("acme");
        assertThat(headers.headerNames()).doesNotContain("X-Forwarded-For", "X-Forwarded-Host");
    }

    @Test
    void disallowed_host_is_rejected_with_404_when_allowlist_configured() {
        var filter = new TenantResolutionWebFilter(List.of("aegis.io"), true);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/oauth2/token").header("Host", "evil.example"));

        boolean[] chainCalled = {false};
        filter.filter(exchange, ex -> {
            chainCalled[0] = true;
            return reactor.core.publisher.Mono.empty();
        }).block();

        assertThat(chainCalled[0]).isFalse(); // short-circuited, never routed
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void actuator_health_is_exempt_from_host_allowlist() {
        var filter = new TenantResolutionWebFilter(List.of("aegis.io"), true);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/actuator/health").header("Host", "10.0.0.5:8080"));

        boolean[] chainCalled = {false};
        filter.filter(exchange, ex -> {
            chainCalled[0] = true;
            return reactor.core.publisher.Mono.empty();
        }).block();

        assertThat(chainCalled[0]).isTrue();
    }

    @Test
    void empty_allowlist_allows_any_host() {
        var filter = new TenantResolutionWebFilter(List.of(), true);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/users").header("Host", "anything.example"));

        ServerWebExchange[] downstream = new ServerWebExchange[1];
        filter.filter(exchange, ex -> {
            downstream[0] = ex;
            return reactor.core.publisher.Mono.empty();
        }).block();

        assertThat(downstream[0]).isNotNull();
    }

    // ---- filter driven WITH a resolver (the branch the stack actually runs) ----

    /**
     * A host with no derivable tenant must pass through cleanly. The resolver path returned null
     * into {@code Mono.map}, which Reactor treats as a fatal NullPointerException — so EVERY request
     * failed, including the actuator health probe, and the gateway never became healthy. The
     * no-resolver tests could not see it because they never enter this branch.
     */
    @Test
    void a_host_with_no_tenant_passes_through_when_a_resolver_is_configured() {
        var resolver = new TenantResolver(
                org.springframework.web.reactive.function.client.WebClient.create("http://unused"),
                org.springframework.web.reactive.function.client.WebClient.create("http://unused"),
                "id", "secret", java.time.Duration.ofMinutes(5), java.time.Duration.ofSeconds(30)) {
            @Override
            public reactor.core.publisher.Mono<java.util.Optional<String>> resolve(String host) {
                return reactor.core.publisher.Mono.just(java.util.Optional.empty());
            }
        };
        var filter = new TenantResolutionWebFilter(List.of(), true, providerOf(resolver));
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/actuator/health").header("Host", "localhost:8080"));

        var captured = new java.util.concurrent.atomic.AtomicReference<ServerHttpRequest>();
        filter.filter(exchange, ex -> {
            captured.set(ex.getRequest());
            return reactor.core.publisher.Mono.empty();
        }).block();

        assertThat(captured.get()).isNotNull();
        assertThat(captured.get().getHeaders().getFirst(TenantResolutionWebFilter.TENANT_HEADER)).isNull();
    }

    /** A resolver answer wins over the subdomain guess — that is the point of resolution. */
    @Test
    void a_resolved_tenant_overrides_the_subdomain_guess() {
        var resolver = new TenantResolver(
                org.springframework.web.reactive.function.client.WebClient.create("http://unused"),
                org.springframework.web.reactive.function.client.WebClient.create("http://unused"),
                "id", "secret", java.time.Duration.ofMinutes(5), java.time.Duration.ofSeconds(30)) {
            @Override
            public reactor.core.publisher.Mono<java.util.Optional<String>> resolve(String host) {
                return reactor.core.publisher.Mono.just(java.util.Optional.of("acme"));
            }
        };
        var filter = new TenantResolutionWebFilter(List.of(), true, providerOf(resolver));
        // Subdomain derivation would say "login"; tenant-service says "acme".
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/x").header("Host", "login.acme.com"));

        var captured = new java.util.concurrent.atomic.AtomicReference<ServerHttpRequest>();
        filter.filter(exchange, ex -> {
            captured.set(ex.getRequest());
            return reactor.core.publisher.Mono.empty();
        }).block();

        assertThat(captured.get().getHeaders().getFirst(TenantResolutionWebFilter.TENANT_HEADER))
                .isEqualTo("acme");
    }

    @Test
    void a_forged_host_rejection_emits_an_edge_audit_event() {
        var captured = new java.util.concurrent.atomic.AtomicReference<io.aegis.commons.audit.AuditEvent>();
        io.aegis.commons.audit.AuditEventPublisher publisher = captured::set;
        // allowlist set to a known base domain -> "evil.example" is rejected
        var filter = new TenantResolutionWebFilter(List.of("aegis.io"), true, noResolver(), publisher);

        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/x").header("Host", "evil.example"));
        filter.filter(exchange, ex -> reactor.core.publisher.Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode())
                .isEqualTo(org.springframework.http.HttpStatus.NOT_FOUND);
        io.aegis.commons.audit.AuditEvent event = captured.get();
        assertThat(event).isNotNull();
        assertThat(event.type()).isEqualTo("edge");
        assertThat(event.action()).isEqualTo("edge.host.rejected");
        assertThat(event.outcome()).isEqualTo(io.aegis.commons.audit.AuditOutcome.DENIED);
        assertThat(event.target()).isEqualTo("evil.example");
    }

    @Test
    void an_allowed_host_emits_no_rejection_event() {
        var captured = new java.util.concurrent.atomic.AtomicReference<io.aegis.commons.audit.AuditEvent>();
        var filter = new TenantResolutionWebFilter(List.of("aegis.io"), true, noResolver(),
                (io.aegis.commons.audit.AuditEventPublisher) captured::set);

        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/x").header("Host", "acme.aegis.io"));
        filter.filter(exchange, ex -> reactor.core.publisher.Mono.empty()).block();

        assertThat(captured.get()).isNull(); // allowed host -> no rejection event
    }

    private static org.springframework.beans.factory.ObjectProvider<TenantResolver> noResolver() {
        return providerOf(null);
    }

    private static org.springframework.beans.factory.ObjectProvider<TenantResolver> providerOf(
            TenantResolver resolver) {
        return new org.springframework.beans.factory.ObjectProvider<>() {
            @Override
            public TenantResolver getObject() {
                return resolver;
            }

            @Override
            public TenantResolver getObject(Object... args) {
                return resolver;
            }

            @Override
            public TenantResolver getIfAvailable() {
                return resolver;
            }

            @Override
            public TenantResolver getIfUnique() {
                return resolver;
            }
        };
    }
}
