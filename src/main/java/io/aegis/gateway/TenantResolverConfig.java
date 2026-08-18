package io.aegis.gateway;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires host-to-tenant resolution against tenant-service.
 *
 * <p>Opt-in via {@code aegis.gateway.tenant-resolution.enabled}. When it is off — local dev, the
 * context-load test — {@link TenantResolutionWebFilter} keeps using subdomain derivation, so the
 * gateway starts with no dependency on tenant-service or a client secret. When it is on, custom
 * sign-in domains resolve correctly, which subdomain derivation can never do.
 *
 * <p>The credentials here belong to a client whose only scope is {@code tenant:resolve}. That is
 * deliberate: the gateway is the platform's internet-facing component, so the blast radius of a
 * compromise there is bounded to "can look up which tenant owns an already-verified hostname".
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "aegis.gateway.tenant-resolution.enabled", havingValue = "true")
public class TenantResolverConfig {

    /**
     * Builds its {@link WebClient}s directly rather than injecting a {@code WebClient.Builder}.
     * Boot 4 does not auto-configure that builder in this application — the gateway starter does not
     * bring the module that provides it — so injecting one fails context startup at runtime while
     * compiling perfectly happily. Verified by {@code TenantResolverWiringTest}.
     */
    @Bean
    public TenantResolver tenantResolver(
            @Value("${aegis.routes.tenant-service}") String tenantServiceUri,
            @Value("${aegis.routes.authorization-server}") String authorizationServerUri,
            @Value("${aegis.gateway.tenant-resolution.client-id:aegis-gateway}") String clientId,
            @Value("${aegis.gateway.tenant-resolution.client-secret}") String clientSecret,
            @Value("${aegis.gateway.tenant-resolution.positive-ttl:PT5M}") Duration positiveTtl,
            @Value("${aegis.gateway.tenant-resolution.negative-ttl:PT30S}") Duration negativeTtl) {
        return new TenantResolver(
                WebClient.create(tenantServiceUri),
                WebClient.create(authorizationServerUri),
                clientId, clientSecret, positiveTtl, negativeTtl);
    }
}
