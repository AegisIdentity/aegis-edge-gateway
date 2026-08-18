package io.aegis.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

/**
 * Host-to-tenant resolution against a stub tenant-service.
 *
 * <p>The behaviours asserted here are the ones that decide whether this is safe to put on the
 * critical path of every public request: custom domains must resolve (the reason it exists),
 * results must be cached (or tenant-service is called once per request), and an outage must degrade
 * rather than misroute.
 */
class TenantResolverTest {

    private com.sun.net.httpserver.HttpServer server;
    private final AtomicInteger resolveCalls = new AtomicInteger();
    private final AtomicInteger tokenCalls = new AtomicInteger();
    private volatile int resolveStatus = 200;
    private volatile String resolveBody = "{\"tenant\":\"acme\"}";

    @BeforeEach
    void startStub() throws IOException {
        server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        server.createContext("/oauth2/token", exchange -> {
            tokenCalls.incrementAndGet();
            byte[] body = "{\"access_token\":\"stub-token\",\"expires_in\":600}".getBytes();
            exchange.getResponseHeaders().add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/api/v1/internal/domains/resolve", exchange -> {
            resolveCalls.incrementAndGet();
            byte[] body = resolveBody.getBytes();
            exchange.getResponseHeaders().add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
            exchange.sendResponseHeaders(resolveStatus, resolveStatus == 404 ? -1 : body.length);
            if (resolveStatus != 404) {
                exchange.getResponseBody().write(body);
            }
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stopStub() {
        server.stop(0);
    }

    private TenantResolver resolver(Duration positiveTtl, Duration negativeTtl) {
        String base = "http://localhost:" + server.getAddress().getPort();
        WebClient.Builder builder = WebClient.builder();
        return new TenantResolver(builder.baseUrl(base).build(), builder.baseUrl(base).build(),
                "aegis-gateway", "secret", positiveTtl, negativeTtl);
    }

    /** The whole point: a white-label host that contains no tenant slug still resolves. */
    @Test
    void resolves_a_custom_domain_that_subdomain_derivation_cannot() {
        // Subdomain derivation would answer "login" — the wrong tenant entirely.
        assertThat(TenantResolutionWebFilter.deriveTenant("login.acme.com")).isEqualTo("login");

        StepVerifier.create(resolver(Duration.ofMinutes(5), Duration.ofSeconds(30)).resolve("login.acme.com"))
                .expectNext(Optional.of("acme"))
                .verifyComplete();
    }

    @Test
    void a_repeated_lookup_is_served_from_cache_not_from_tenant_service() {
        TenantResolver resolver = resolver(Duration.ofMinutes(5), Duration.ofSeconds(30));

        StepVerifier.create(resolver.resolve("login.acme.com")).expectNextCount(1).verifyComplete();
        StepVerifier.create(resolver.resolve("login.acme.com")).expectNextCount(1).verifyComplete();
        StepVerifier.create(resolver.resolve("login.acme.com")).expectNextCount(1).verifyComplete();

        // One upstream call for three resolutions — otherwise tenant-service is on the hot path of
        // every single public request.
        assertThat(resolveCalls.get()).isEqualTo(1);
    }

    @Test
    void the_access_token_is_reused_across_lookups() {
        TenantResolver resolver = resolver(Duration.ZERO, Duration.ZERO); // force upstream each time

        StepVerifier.create(resolver.resolve("a.example.com")).expectNextCount(1).verifyComplete();
        StepVerifier.create(resolver.resolve("b.example.com")).expectNextCount(1).verifyComplete();

        assertThat(resolveCalls.get()).isEqualTo(2);
        assertThat(tokenCalls.get()).isEqualTo(1); // token cached until near expiry
    }

    /** 404 means "nobody owns this host" — a legitimate answer, not a failure. */
    @Test
    void an_unowned_host_resolves_to_empty() {
        resolveStatus = 404;

        StepVerifier.create(resolver(Duration.ofMinutes(5), Duration.ofSeconds(30)).resolve("nobody.example.com"))
                .expectNext(Optional.empty())
                .verifyComplete();
    }

    /** Negative results are cached too, so unknown hosts cannot amplify traffic to tenant-service. */
    @Test
    void negative_results_are_cached() {
        resolveStatus = 404;
        TenantResolver resolver = resolver(Duration.ofMinutes(5), Duration.ofMinutes(5));

        StepVerifier.create(resolver.resolve("nobody.example.com")).expectNextCount(1).verifyComplete();
        StepVerifier.create(resolver.resolve("nobody.example.com")).expectNextCount(1).verifyComplete();

        assertThat(resolveCalls.get()).isEqualTo(1);
    }

    /** An outage must degrade to "unknown", never to a guessed or stale-wrong tenant. */
    @Test
    void an_upstream_failure_yields_empty_rather_than_a_wrong_tenant() {
        resolveStatus = 500;

        StepVerifier.create(resolver(Duration.ofMinutes(5), Duration.ofSeconds(30)).resolve("acme.example.com"))
                .expectNext(Optional.empty())
                .verifyComplete();
    }

    /**
     * A failure must not be cached as a negative result: a brief outage would otherwise become a
     * lasting misroute for every host looked up during it.
     */
    @Test
    void a_failure_is_not_cached_so_recovery_is_immediate() {
        TenantResolver resolver = resolver(Duration.ofMinutes(5), Duration.ofMinutes(5));

        resolveStatus = 500;
        StepVerifier.create(resolver.resolve("acme.example.com")).expectNext(Optional.empty()).verifyComplete();

        resolveStatus = 200; // tenant-service recovers
        StepVerifier.create(resolver.resolve("acme.example.com")).expectNext(Optional.of("acme")).verifyComplete();
    }

    @Test
    void the_port_is_ignored_and_the_host_is_matched_case_insensitively() {
        TenantResolver resolver = resolver(Duration.ofMinutes(5), Duration.ofSeconds(30));

        StepVerifier.create(resolver.resolve("Login.ACME.com:8443")).expectNext(Optional.of("acme")).verifyComplete();
        StepVerifier.create(resolver.resolve("login.acme.com")).expectNext(Optional.of("acme")).verifyComplete();

        assertThat(resolveCalls.get()).isEqualTo(1); // same cache entry
    }

    @Test
    void a_blank_host_never_reaches_tenant_service() {
        StepVerifier.create(resolver(Duration.ofMinutes(5), Duration.ofSeconds(30)).resolve("  "))
                .expectNext(Optional.empty())
                .verifyComplete();

        assertThat(resolveCalls.get()).isZero();
    }
}
