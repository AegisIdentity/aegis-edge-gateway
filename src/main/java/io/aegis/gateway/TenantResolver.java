package io.aegis.gateway;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Maps a request {@code Host} to the tenant that owns it, by asking tenant-service.
 *
 * <p>Replaces guessing the tenant from the first DNS label. That guess only ever worked for
 * {@code <tenant>.aegis.io} and silently produced the wrong answer — or none — for the white-label
 * custom domains the platform sells ({@code login.acme.com}), because nothing about that hostname
 * contains the tenant slug. tenant-service is the only component that knows the mapping, and it
 * answers only for domains whose ownership has been DNS-verified.
 *
 * <p><b>Caching.</b> This sits on the critical path of every public request, so results are cached
 * with a short TTL. Negative results are cached too, and deliberately for a shorter period: without
 * that, a flood of requests for unknown hostnames becomes a free amplifier against tenant-service.
 *
 * <p><b>Failure posture.</b> If tenant-service is unavailable the resolver returns empty rather than
 * inventing a tenant, and the caller falls back to subdomain derivation. That is a considered
 * trade-off: the tenant header is a routing/context hint, and every downstream service independently
 * re-derives the acting tenant from the JWT rather than trusting the header, so a wrong or missing
 * hint cannot grant cross-tenant access. The control that actually stops a forged {@code Host} is
 * the allowlist in {@link TenantResolutionWebFilter}.
 */
public class TenantResolver {

    private static final Logger log = LoggerFactory.getLogger(TenantResolver.class);

    private record CacheEntry(Optional<String> tenant, Instant expiresAt) {
    }

    private final WebClient tenantServiceClient;
    private final WebClient tokenClient;
    private final String clientId;
    private final String clientSecret;
    private final Duration positiveTtl;
    private final Duration negativeTtl;

    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private volatile String cachedToken;
    private volatile Instant tokenExpiresAt = Instant.EPOCH;

    public TenantResolver(WebClient tenantServiceClient, WebClient tokenClient,
                          String clientId, String clientSecret,
                          Duration positiveTtl, Duration negativeTtl) {
        this.tenantServiceClient = tenantServiceClient;
        this.tokenClient = tokenClient;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.positiveTtl = positiveTtl;
        this.negativeTtl = negativeTtl;
    }

    /** The tenant owning {@code host}, or empty if none is registered or the lookup failed. */
    public Mono<Optional<String>> resolve(String host) {
        if (host == null || host.isBlank()) {
            return Mono.just(Optional.empty());
        }
        String hostname = host.split(":", 2)[0].toLowerCase();

        CacheEntry cached = cache.get(hostname);
        if (cached != null && Instant.now().isBefore(cached.expiresAt())) {
            return Mono.just(cached.tenant());
        }
        return lookup(hostname)
                .doOnNext(result -> cache.put(hostname, new CacheEntry(
                        result, Instant.now().plus(result.isPresent() ? positiveTtl : negativeTtl))))
                .onErrorResume(error -> {
                    // Do not cache infrastructure failures as "no such tenant" — that would turn a
                    // brief tenant-service outage into a lasting misroute for every affected host.
                    log.warn("tenant resolution failed for host={} — falling back", hostname);
                    return Mono.just(Optional.empty());
                });
    }

    private Mono<Optional<String>> lookup(String hostname) {
        return accessToken().flatMap(token -> tenantServiceClient.get()
                .uri(uriBuilder -> uriBuilder.path("/api/v1/internal/domains/resolve")
                        .queryParam("host", hostname).build())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                // A 404 is a legitimate answer ("nobody owns this host"), not an error.
                .onStatus(status -> status.value() == 404, response -> Mono.empty())
                .bodyToMono(ResolveResponse.class)
                .map(body -> Optional.ofNullable(body.tenant()))
                .defaultIfEmpty(Optional.empty()));
    }

    /** Client-credentials token, cached until shortly before it expires. */
    private Mono<String> accessToken() {
        String token = cachedToken;
        if (token != null && Instant.now().isBefore(tokenExpiresAt)) {
            return Mono.just(token);
        }
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", "tenant:resolve");
        return tokenClient.post()
                .uri("/oauth2/token")
                .headers(headers -> headers.setBasicAuth(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .map(response -> {
                    this.cachedToken = response.access_token();
                    // Refresh a minute early so a request is never made with a token that expires
                    // in flight.
                    long lifetime = Math.max(response.expires_in() - 60, 30);
                    this.tokenExpiresAt = Instant.now().plusSeconds(lifetime);
                    return response.access_token();
                });
    }

    /** tenant-service's resolve response. */
    record ResolveResponse(String tenant) {
    }

    /** Token endpoint response (only the fields needed). */
    record TokenResponse(String access_token, long expires_in) {
    }
}
