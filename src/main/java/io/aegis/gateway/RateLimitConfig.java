package io.aegis.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

/**
 * M-edge-3: edge rate limiting for the credential-facing routes (auth/token/login, MFA/WebAuthn), to
 * blunt credential-stuffing and OTP brute force platform-wide.
 *
 * <p>Active only when {@code aegis.ratelimit.enabled=true} (prod). When disabled — the default, and
 * how local dev / tests run — none of these beans exist and no route carries the limiter filter, so
 * the gateway boots with no Redis reachable. When enabled, defining our own {@link RedisRateLimiter}
 * makes Spring Cloud's auto-configured one back off ({@code @ConditionalOnMissingBean}); it still
 * reuses the auto-configured Lua script and {@code ReactiveStringRedisTemplate}. The {@link KeyResolver}
 * likewise replaces the default {@code PrincipalNameKeyResolver}.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "aegis.ratelimit.enabled", havingValue = "true")
public class RateLimitConfig {

    /** Token-bucket limiter: {@code replenishRate} tokens/sec, up to {@code burstCapacity}. */
    @Bean
    public RedisRateLimiter aegisRedisRateLimiter(
            @Value("${aegis.ratelimit.replenish-rate:10}") int replenishRate,
            @Value("${aegis.ratelimit.burst-capacity:20}") int burstCapacity,
            @Value("${aegis.ratelimit.requested-tokens:1}") int requestedTokens) {
        return new RedisRateLimiter(replenishRate, burstCapacity, requestedTokens);
    }

    /**
     * Bucket key = resolved tenant + client IP, so one abusive IP (or one tenant) cannot exhaust the
     * budget for others. The tenant is the trusted {@code X-Aegis-Tenant} header injected upstream by
     * {@link TenantResolutionWebFilter} (client-supplied values are stripped there); the IP is the
     * gateway's own remote-address view after inbound {@code X-Forwarded-*} is sanitized.
     */
    @Bean
    public KeyResolver tenantIpKeyResolver() {
        return exchange -> {
            String tenant = exchange.getRequest().getHeaders()
                    .getFirst(TenantResolutionWebFilter.TENANT_HEADER);
            var remote = exchange.getRequest().getRemoteAddress();
            String ip = (remote == null || remote.getAddress() == null) ? "unknown"
                    : remote.getAddress().getHostAddress();
            return Mono.just((tenant == null ? "-" : tenant) + "|" + ip);
        };
    }
}
