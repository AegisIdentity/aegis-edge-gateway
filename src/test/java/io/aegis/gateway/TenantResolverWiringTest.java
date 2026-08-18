package io.aegis.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Boots the gateway with tenant resolution ENABLED.
 *
 * <p>The other resolver tests construct {@link TenantResolver} directly, so they prove its
 * behaviour but say nothing about whether Spring can actually build it. That gap was real: the
 * config originally injected a {@code WebClient.Builder}, which Boot 4 does not auto-configure in
 * this application, so the container failed to start at runtime while everything compiled and every
 * unit test passed. This test is the one that fails if the wiring breaks again.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "aegis.gateway.tenant-resolution.enabled=true",
        "aegis.gateway.tenant-resolution.client-secret=test-secret"
})
class TenantResolverWiringTest {

    @Autowired(required = false)
    TenantResolver tenantResolver;

    @Test
    void the_resolver_bean_is_constructible_when_resolution_is_enabled() {
        assertThat(tenantResolver)
                .as("tenant resolution is enabled, so the gateway must be able to build the resolver")
                .isNotNull();
    }
}
