package io.aegis.gateway;

import java.util.regex.Pattern;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Normalizes MCP request metadata at the edge.
 *
 * <p>MCP revision {@code 2026-07-28} moved the method and tool names into the {@code Mcp-Method} and
 * {@code Mcp-Name} HTTP headers <b>specifically so gatekeepers can route and authorize without
 * parsing JSON bodies</b>. For a gateway that is a significant win: per-tool policy and per-tool
 * quotas become header inspection rather than body buffering — cheaper, and far less attack-prone
 * than parsing attacker-supplied JSON before the request is authorized.
 *
 * <p>Two rules, both mirroring how {@link TenantResolutionWebFilter} treats the tenant header:
 * <ul>
 *   <li>the internal header is <b>derived here and stripped from the client</b>, because otherwise a
 *       caller simply asserts whichever tool it wishes it were calling;</li>
 *   <li>the inbound values are <b>strictly validated</b>. They are attacker-controlled and flow into
 *       logs and rate-limit keys, so CRLF (log/header injection), path traversal, the {@code |} key
 *       separator, and over-long values are all rejected outright rather than sanitized — a rejected
 *       request is unambiguous, a silently rewritten one is not.</li>
 * </ul>
 *
 * <p>Runs after {@link TenantResolutionWebFilter} (order -1) so the trusted tenant header is already
 * present for the quota key.
 */
@Component
@Order(0)
public class McpRequestFilter implements WebFilter {

    /** Method name, per MCP 2026-07-28 (e.g. {@code tools/call}, {@code tools/list}). */
    public static final String MCP_METHOD_HEADER = "Mcp-Method";

    /** Tool name, per MCP 2026-07-28. Absent for methods that do not name a tool. */
    public static final String MCP_NAME_HEADER = "Mcp-Name";

    /** Trusted internal header: {@code method:name}. Derived here; never accepted from a client. */
    public static final String INTERNAL_TOOL_HEADER = "X-Aegis-Mcp-Tool";

    /** Trusted internal agent identity, injected by an authenticated upstream hop. */
    public static final String INTERNAL_AGENT_HEADER = "X-Aegis-Agent";

    public static final int MAX_NAME_LENGTH = 128;

    /**
     * Deliberately narrow: letters, digits and {@code . _ - /} only. This excludes CRLF, whitespace,
     * the {@code |} used as the rate-limit key separator, and anything percent-encoded.
     */
    private static final Pattern SAFE = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._/-]*$");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String method = exchange.getRequest().getHeaders().getFirst(MCP_METHOD_HEADER);

        if (method == null || method.isBlank()) {
            // Not an MCP request. Still strip the internal headers so a client cannot smuggle them
            // in on an ordinary route.
            return chain.filter(exchange.mutate().request(
                    exchange.getRequest().mutate()
                            .headers(headers -> {
                                headers.remove(INTERNAL_TOOL_HEADER);
                                headers.remove(INTERNAL_AGENT_HEADER);
                            })
                            .build()).build());
        }

        if (!valid(method)) {
            return reject(exchange);
        }

        String name = exchange.getRequest().getHeaders().getFirst(MCP_NAME_HEADER);
        boolean namePresent = name != null;
        if (namePresent && !valid(name)) {
            return reject(exchange);
        }

        String toolId = namePresent ? method + ":" + name : method;

        ServerHttpRequest mutated = exchange.getRequest().mutate()
                .headers(headers -> {
                    // Client-supplied value discarded before the derived one is written.
                    headers.remove(INTERNAL_TOOL_HEADER);
                    headers.remove(INTERNAL_AGENT_HEADER);
                    headers.set(INTERNAL_TOOL_HEADER, toolId);
                })
                .build();

        return chain.filter(exchange.mutate().request(mutated).build());
    }

    private static boolean valid(String value) {
        return value != null
                && !value.isBlank()
                && value.length() <= MAX_NAME_LENGTH
                && !value.contains("..")
                && SAFE.matcher(value).matches();
    }

    private static Mono<Void> reject(ServerWebExchange exchange) {
        // No detail echoed back: the rejected value is attacker-controlled, and reflecting it would
        // hand back a response-splitting primitive for the sake of a friendlier error.
        exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
        return exchange.getResponse().setComplete();
    }
}
