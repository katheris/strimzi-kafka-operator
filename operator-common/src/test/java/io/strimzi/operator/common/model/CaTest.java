/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.strimzi.api.kafka.model.common.CertificateAuthority;
import io.strimzi.certs.CertManager;
import io.strimzi.certs.OpenSslCertManager;
import io.strimzi.operator.common.Reconciliation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CaTest {

    /**
     * Mock implementation of the CA class which does not generate the CA certificate
     */
    private static class MockCa extends Ca {

        /**
         * Constructs the CA object
         *
         * @param reconciliation    Reconciliation marker
         * @param certManager       Certificate manager instance
         * @param passwordGenerator Password generator instance
         * @param caCertData        CA public cert data
         * @param caCertGeneration  Generation of the CA public cert
         * @param caKeyData         CA private key data
         * @param caKeyGeneration   Generation of the CA private key
         */
        public MockCa(Reconciliation reconciliation, CertManager certManager, PasswordGenerator passwordGenerator, Map<String, String> caCertData, int caCertGeneration, Map<String, String> caKeyData, int caKeyGeneration) {
            super(reconciliation, certManager, passwordGenerator, "mock", caCertData, caCertGeneration, caKeyData, caKeyGeneration, CertificateAuthority.DEFAULT_CERTS_VALIDITY_DAYS, CertificateAuthority.DEFAULT_CERTS_RENEWAL_DAYS, true, null);
        }

        @Override
        protected String caCertGenerationAnnotation() {
            return "mock";
        }

        @Override
        protected String caName() {
            return "Mock CA";
        }
    }

    private Ca ca;
    private Duration oneYear;
    private Clock now;

    @BeforeEach
    public void setup() {
        now = Clock.fixed(new Date().toInstant(), Clock.systemUTC().getZone());
        oneYear = Duration.ofDays(CertificateAuthority.DEFAULT_CERTS_VALIDITY_DAYS);
        ca = new MockCa(Reconciliation.DUMMY_RECONCILIATION, new OpenSslCertManager(now), new PasswordGenerator(10, "a", "a"), null, 0, null, 0);
    }

    @Test
    @DisplayName("Should return certificate expiration date as epoch when certificate is present")
    void shouldReturnCertificateExpirationDateEpoch() {
        ca.createRenewOrReplace(true, false, false);

        Instant inOneYear = Clock.offset(now, oneYear).instant();
        long expectedEpoch = inOneYear.truncatedTo(ChronoUnit.SECONDS).toEpochMilli();
        long actualEpoch = ca.getCertificateExpirationDateEpoch();
        assertEquals(expectedEpoch, actualEpoch, "Expected and actual certificate expiration epochs should match");
    }

    @Test
    @DisplayName("Should raise RuntimeException when certificate is not present")
    void shouldReturnZeroWhenCertificateNotPresent() {
        Exception exception = assertThrows(RuntimeException.class, () -> ca.getCertificateExpirationDateEpoch());
        assertEquals("ca.crt does not exist for CA Mock CA", exception.getMessage());
    }
}