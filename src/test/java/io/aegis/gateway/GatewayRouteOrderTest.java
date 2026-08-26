package io.aegis.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

/**
 * Route <b>order</b>, pinned.
 *
 * <p>Spring Cloud Gateway takes the first matching route, which makes ordering a correctness concern
 * rather than a stylistic one. The Vault broker lives at {@code /api/v1/tenants/{id}/vault/**} on
 * admin-api — a sub-path of the tenant-service route. Put them the wrong way round and every
 * Key/Secrets-Management call is proxied to tenant-service, which has no such endpoint, so the
 * feature 404s in a way that looks like a bug in admin-api rather than a routing problem.
 */
@SpringBootTest
class GatewayRouteOrderTest {

    @Autowired
    RouteLocator routeLocator;

    /** The id of the first route that matches, i.e. the one that would actually serve the request. */
    private String firstMatch(String path) {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get(path).header("Host", "localhost"));
        List<Route> routes = routeLocator.getRoutes().collectList().block();
        for (Route route : routes) {
            if (Boolean.TRUE.equals(reactor.core.publisher.Mono.from(
                    route.getPredicate().apply(exchange)).block())) {
                return route.getId();
            }
        }
        return null;
    }

    @Test
    void the_vault_broker_wins_over_the_generic_tenant_route() {
        assertThat(firstMatch("/api/v1/tenants/acme/vault/transit/keys"))
                .isEqualTo("admin-api-vault-broker");
    }

    @Test
    void ordinary_tenant_paths_still_reach_tenant_service() {
        assertThat(firstMatch("/api/v1/tenants/acme")).isEqualTo("tenant-service");
        assertThat(firstMatch("/api/v1/tenants/acme/agent-policy")).isEqualTo("tenant-service");
    }

    @Test
    void agent_principals_route_to_identity_service() {
        assertThat(firstMatch("/api/v1/agents")).isEqualTo("identity-service");
        assertThat(firstMatch("/api/v1/agents/agent:planner")).isEqualTo("identity-service");
    }

    @Test
    void the_tool_registry_routes_to_the_registry_service() {
        assertThat(firstMatch("/api/v1/registry/tools")).isEqualTo("agent-registry-service");
    }

    @Test
    void risk_routes_to_threat_analysis() {
        assertThat(firstMatch("/api/v1/risk/agents")).isEqualTo("threat-analysis-service");
    }

    @Test
    void per_tool_consent_routes_to_admin_api_not_the_registry() {
        // Consent is a PDP decision; the registry only observes. Routing it to the registry would
        // put the grant and the observation in the same service, which ADR-0013 separates on purpose.
        assertThat(firstMatch("/api/v1/agent-consents")).isEqualTo("admin-api-service");
    }

    @Test
    void the_oidc_endpoints_still_reach_the_authorization_server() {
        assertThat(firstMatch("/oauth2/token")).isEqualTo("authorization-server");
        assertThat(firstMatch("/.well-known/openid-configuration")).isEqualTo("authorization-server");
    }

    @Test
    void every_route_has_a_distinct_id() {
        List<Route> routes = routeLocator.getRoutes().collectList().block();
        assertThat(routes).extracting(Route::getId).doesNotHaveDuplicates();
    }
}
