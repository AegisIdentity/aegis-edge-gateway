package io.aegis.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class TenantResolutionWebFilterTest {

    @ParameterizedTest
    @CsvSource({
            "acme.aegis.io,acme",
            "login.acme.aegis.io,login",
            "ACME.aegis.io,acme",
            "acme.aegis.io:8443,acme"
    })
    void derives_tenant_from_subdomain(String host, String expected) {
        assertThat(TenantResolutionWebFilter.deriveTenant(host)).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource({"aegis.io", "localhost", "localhost:8080"})
    void no_tenant_for_apex_or_localhost(String host) {
        assertThat(TenantResolutionWebFilter.deriveTenant(host)).isNull();
    }

    @Test
    void null_or_blank_host_yields_no_tenant() {
        assertThat(TenantResolutionWebFilter.deriveTenant(null)).isNull();
        assertThat(TenantResolutionWebFilter.deriveTenant("  ")).isNull();
    }
}
