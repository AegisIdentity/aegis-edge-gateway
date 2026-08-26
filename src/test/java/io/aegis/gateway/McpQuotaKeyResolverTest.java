package io.aegis.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

/**
 * Per-agent quotas. A runaway agent loop is the agent-native denial-of-service: it is not malicious
 * traffic and does not look like an attack, it is one agent stuck in a cycle burning a tenant's
 * budget.
 */
class McpQuotaKeyResolverTest {

    private final McpQuotaKeyResolver resolver = new McpQuotaKeyResolver();

    private String keyFor(MockServerHttpRequest.BaseBuilder<?> builder) {
        return resolver.resolve(MockServerWebExchange.from(builder)).block();
    }

    @Test
    void buckets_by_tenant_and_tool_so_one_tool_cannot_starve_another() {
        String read = keyFor(MockServerHttpRequest.post("/mcp")
                .header(TenantResolutionWebFilter.TENANT_HEADER, "acme")
                .header(McpRequestFilter.INTERNAL_TOOL_HEADER, "tools/call:files/read"));
        String write = keyFor(MockServerHttpRequest.post("/mcp")
                .header(TenantResolutionWebFilter.TENANT_HEADER, "acme")
                .header(McpRequestFilter.INTERNAL_TOOL_HEADER, "tools/call:files/write"));

        assertThat(read).isNotEqualTo(write);
    }

    @Test
    void two_tenants_never_share_a_bucket() {
        String acme = keyFor(MockServerHttpRequest.post("/mcp")
                .header(TenantResolutionWebFilter.TENANT_HEADER, "acme")
                .header(McpRequestFilter.INTERNAL_TOOL_HEADER, "tools/call:files/read"));
        String globex = keyFor(MockServerHttpRequest.post("/mcp")
                .header(TenantResolutionWebFilter.TENANT_HEADER, "globex")
                .header(McpRequestFilter.INTERNAL_TOOL_HEADER, "tools/call:files/read"));

        assertThat(acme).isNotEqualTo(globex);
    }

    @Test
    void an_agent_identity_narrows_the_bucket_further_when_present() {
        String withAgent = keyFor(MockServerHttpRequest.post("/mcp")
                .header(TenantResolutionWebFilter.TENANT_HEADER, "acme")
                .header(McpRequestFilter.INTERNAL_AGENT_HEADER, "agent:planner")
                .header(McpRequestFilter.INTERNAL_TOOL_HEADER, "tools/call:files/read"));
        String withoutAgent = keyFor(MockServerHttpRequest.post("/mcp")
                .header(TenantResolutionWebFilter.TENANT_HEADER, "acme")
                .header(McpRequestFilter.INTERNAL_TOOL_HEADER, "tools/call:files/read"));

        assertThat(withAgent).contains("agent:planner");
        assertThat(withAgent).isNotEqualTo(withoutAgent);
    }

    @Test
    void a_non_mcp_request_still_yields_a_stable_tenant_scoped_key() {
        assertThat(keyFor(MockServerHttpRequest.get("/api/v1/users")
                .header(TenantResolutionWebFilter.TENANT_HEADER, "acme")))
                .startsWith("acme|");
    }

    @Test
    void a_missing_tenant_does_not_collapse_every_caller_into_one_shared_bucket() {
        // If an unresolved tenant produced a constant key, one anonymous caller could exhaust the
        // budget for all of them. The remote address keeps the buckets separate.
        String a = keyFor(MockServerHttpRequest.get("/api/v1/users")
                .remoteAddress(new java.net.InetSocketAddress("10.0.0.1", 1234)));
        String b = keyFor(MockServerHttpRequest.get("/api/v1/users")
                .remoteAddress(new java.net.InetSocketAddress("10.0.0.2", 1234)));

        assertThat(a).isNotEqualTo(b);
    }
}
