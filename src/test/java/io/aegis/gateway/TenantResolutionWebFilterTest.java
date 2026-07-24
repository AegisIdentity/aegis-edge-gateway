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
}
