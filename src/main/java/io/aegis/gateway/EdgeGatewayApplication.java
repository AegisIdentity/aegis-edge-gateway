package io.aegis.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Aegis Edge Gateway — the single public entry point. Routes to services, resolves the tenant,
 * and is where TLS, rate limiting, and WAF hooks live. Reactive (Spring Cloud Gateway / WebFlux). */
@SpringBootApplication
public class EdgeGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(EdgeGatewayApplication.class, args);
    }
}
