/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.strimzi.api.kafka.model.kafka.KafkaResources;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.strimzi.test.TestUtils.map;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PemTrustSetTest {
    public static final String NAMESPACE = "testns";
    public static final String CLUSTER = "testcluster";

    @Test
    public void testSecretCorrupted() {
        Secret secretWithBadCertificate = new SecretBuilder()
                .withNewMetadata()
                .withName(KafkaResources.secretName(CLUSTER))
                .withNamespace(NAMESPACE)
                .endMetadata()
                .withData(map("ca.crt", "notacert"))
                .build();
        PemTrustSet pemTrustSet = new PemTrustSet(secretWithBadCertificate);
        Exception e = assertThrows(RuntimeException.class, pemTrustSet::trustedCertificates);
        assertThat(e.getMessage(), is("Bad/corrupt certificate found in data.ca.crt of Secret testcluster-cluster-operator-certs in namespace testns"));
    }

    @Test
    public void testMissingSecret() {
        Exception e = assertThrows(RuntimeException.class, () -> new PemTrustSet(null));
        assertThat(e.getMessage(), is("Cannot extract trust set from null secret"));
    }

    @Test
    public void testMissingSecretData() {
        Secret secretWithMissingData = new SecretBuilder()
                .withNewMetadata()
                .withName(KafkaResources.secretName(CLUSTER))
                .withNamespace(NAMESPACE)
                .endMetadata()
                .withData(null)
                .build();
        Exception e = assertThrows(RuntimeException.class, () -> new PemTrustSet(secretWithMissingData));
        assertThat(e.getMessage(), is("Cannot extract trust set from null secret"));
    }

    @Test
    public void testHandlesEmptySecretData() {
        Secret secretWithEmptyData = new SecretBuilder()
                .withNewMetadata()
                .withName(KafkaResources.secretName(CLUSTER))
                .withNamespace(NAMESPACE)
                .endMetadata()
                .withData(Map.of())
                .build();
        PemTrustSet pemTrustSet = new PemTrustSet(secretWithEmptyData);
        assertThat(pemTrustSet.trustedCertificates(), hasSize(0));
    }
}