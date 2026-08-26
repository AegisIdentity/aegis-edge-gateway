package io.aegis.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * MCP revision {@code 2026-07-28} moved method and tool names into the {@code Mcp-Method} and
 * {@code Mcp-Name} HTTP headers <b>specifically so gatekeepers can route and authorize without
 * parsing JSON bodies</b>. That is a large win for an edge gateway: per-tool policy becomes header
 * inspection instead of body buffering, which is both cheaper and far less attack-prone.
 *
 * <p>The headers are attacker-controlled, and they flow into logs and rate-limit keys, so they are
 * validated strictly before anything downstream sees them.
 */
class McpRequestFilterTest {

    private final McpRequestFilter filter = new McpRequestFilter();

    private ServerHttpRequest run(MockServerHttpRequest.BaseBuilder<?> builder) {
        MockServerWebExchange exchange = MockServerWebExchange.from(builder);
        ServerHttpRequest[] seen = new ServerHttpRequest[1];
        filter.filter(exchange, ex -> {
            seen[0] = ex.getRequest();
            return Mono.empty();
        }).block();
        return seen[0];
    }

    @Test
    void normalizes_mcp_headers_into_a_trusted_internal_tool_header() {
        ServerHttpRequest request = run(MockServerHttpRequest.post("/mcp")
                .header(McpRequestFilter.MCP_METHOD_HEADER, "tools/call")
                .header(McpRequestFilter.MCP_NAME_HEADER, "files/read"));

        assertThat(request.getHeaders().getFirst(McpRequestFilter.INTERNAL_TOOL_HEADER))
                .isEqualTo("tools/call:files/read");
    }

    @Test
    void strips_a_client_supplied_internal_tool_header() {
        // Same rule as X-Aegis-Tenant: an internal header is DERIVED at the edge, never accepted
        // from the client. Otherwise a caller simply asserts the tool it wishes it were calling.
        ServerHttpRequest request = run(MockServerHttpRequest.post("/mcp")
                .header(McpRequestFilter.INTERNAL_TOOL_HEADER, "tools/call:admin/everything")
                .header(McpRequestFilter.MCP_METHOD_HEADER, "tools/call")
                .header(McpRequestFilter.MCP_NAME_HEADER, "files/read"));

        assertThat(request.getHeaders().getFirst(McpRequestFilter.INTERNAL_TOOL_HEADER))
                .isEqualTo("tools/call:files/read");
    }

    @Test
    void strips_the_internal_header_entirely_when_the_request_is_not_mcp() {
        ServerHttpRequest request = run(MockServerHttpRequest.get("/api/v1/users")
                .header(McpRequestFilter.INTERNAL_TOOL_HEADER, "tools/call:admin/everything"));

        assertThat(request.getHeaders().getFirst(McpRequestFilter.INTERNAL_TOOL_HEADER)).isNull();
    }

    @Test
    void a_non_mcp_request_passes_through_untouched() {
        ServerHttpRequest request = run(MockServerHttpRequest.get("/api/v1/users"));
        assertThat(request.getHeaders().getFirst(McpRequestFilter.INTERNAL_TOOL_HEADER)).isNull();
    }

    // --- hostile header values ------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {
            "files/read\nX-Injected: yes",   // CRLF -> log and header injection
            "files/read\rSet-Cookie: x=1",
            "files/../../admin",             // traversal in a tool name
            "files/read|other",              // rate-limit key separator injection
            "",
            "   ",
    })
    void a_hostile_tool_name_is_rejected_with_400(String hostile) {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/mcp")
                .header(McpRequestFilter.MCP_METHOD_HEADER, "tools/call")
                .header(McpRequestFilter.MCP_NAME_HEADER, hostile));

        filter.filter(exchange, ex -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void an_over_long_tool_name_is_rejected() {
        String tooLong = "a".repeat(McpRequestFilter.MAX_NAME_LENGTH + 1);
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/mcp")
                .header(McpRequestFilter.MCP_METHOD_HEADER, "tools/call")
                .header(McpRequestFilter.MCP_NAME_HEADER, tooLong));

        filter.filter(exchange, ex -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void a_method_without_a_name_is_still_normalized() {
        // Not every MCP method names a tool (initialize, tools/list). These must not be rejected.
        ServerHttpRequest request = run(MockServerHttpRequest.post("/mcp")
                .header(McpRequestFilter.MCP_METHOD_HEADER, "tools/list"));

        assertThat(request.getHeaders().getFirst(McpRequestFilter.INTERNAL_TOOL_HEADER))
                .isEqualTo("tools/list");
    }
}
