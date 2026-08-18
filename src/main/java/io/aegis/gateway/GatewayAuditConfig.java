package io.aegis.gateway;

import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.KafkaAuditEventPublisher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaTemplate;

/**
 * Wires an audit publisher for the reactive edge so its security-relevant decisions (a forged/unknown
 * {@code Host} rejected at the door) reach the same platform audit stream as the services.
 *
 * <p>The gateway does not use {@code aegis-security-commons} (that is servlet security), so it does
 * not get the shared audit autoconfiguration; the Kafka publisher is created here directly, and only
 * when a broker is configured. When Kafka is absent (local dev without the flag), a no-op publisher
 * keeps the filter code unconditional.
 */
@Configuration(proxyBeanMethods = false)
public class GatewayAuditConfig {

    @Bean
    @ConditionalOnProperty(name = "spring.kafka.bootstrap-servers")
    public AuditEventPublisher edgeAuditPublisher(
            KafkaTemplate<String, String> kafkaTemplate,
            @Value("${aegis.audit.kafka.topic:aegis.audit.events}") String topic) {
        return new KafkaAuditEventPublisher(kafkaTemplate, topic);
    }

    /** No-op when Kafka is not configured, so the filter never has to null-check. */
    @Bean
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(AuditEventPublisher.class)
    public AuditEventPublisher noopEdgeAuditPublisher() {
        return event -> {
        };
    }
}
