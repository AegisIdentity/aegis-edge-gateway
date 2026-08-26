package io.aegis.gateway;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Rate-limit bucket key for agent traffic.
 *
 * <p>A runaway agent loop is the agent-native denial of service: it is not malicious traffic and
 * does not look like an attack — it is one agent stuck in a cycle burning a tenant's budget. Keying
 * by <b>tenant + agent + tool</b> means that loop exhausts its own bucket and nobody else's.
 *
 * <p>The agent identity is taken from the trusted internal header, which
 * {@link McpRequestFilter} strips from clients and an authenticated upstream hop injects. It is
 * deliberately <em>not</em> read from an unvalidated bearer token: an attacker who could set their
 * own bucket key could rotate it to escape their own limit, which is worse than not bucketing by
 * agent at all.
 *
 * <p>When no tenant resolves, the key falls back to the remote address rather than a constant, so
 * one anonymous caller cannot exhaust the budget for every other anonymous caller.
 */
public class McpQuotaKeyResolver implements KeyResolver {

    @Override
    public Mono<String> resolve(ServerWebExchange exchange) {
        var headers = exchange.getRequest().getHeaders();
        String tenant = headers.getFirst(TenantResolutionWebFilter.TENANT_HEADER);
        String agent = headers.getFirst(McpRequestFilter.INTERNAL_AGENT_HEADER);
        String tool = headers.getFirst(McpRequestFilter.INTERNAL_TOOL_HEADER);

        StringBuilder key = new StringBuilder();
        key.append(tenant == null || tenant.isBlank() ? "-" : tenant).append('|');

        if (agent != null && !agent.isBlank()) {
            key.append(agent).append('|');
        }
        if (tool != null && !tool.isBlank()) {
            key.append(tool);
        } else {
            var remote = exchange.getRequest().getRemoteAddress();
            key.append(remote == null || remote.getAddress() == null
                    ? "unknown" : remote.getAddress().getHostAddress());
        }
        return Mono.just(key.toString());
    }
}
