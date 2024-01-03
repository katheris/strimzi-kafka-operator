/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.Secret;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Collectors;

/**
 * Provides the default TrustStore supplier for the Cluster CA certificate
 */
public class ClusterCaTrustStoreSupplier implements PemTrustStoreSupplier {

    private final String pemTrustedCertificates;

    /**
     * @param clusterCaCertSecret Kubernetes Secret with the Cluster CA
     */
    public ClusterCaTrustStoreSupplier(Secret clusterCaCertSecret) {
        pemTrustedCertificates = certsToPemString(clusterCaCertSecret);
    }
    @Override
    public String pemTrustedCertificates() {
        return pemTrustedCertificates;
    }

    /**
     * Returns concatenated string of all public keys (all .crt records) from a secret
     *
     * @param secret    Kubernetes Secret with certificates
     *
     * @return          String secrets
     */
    private static String certsToPemString(Secret secret)  {
        if (secret == null || secret.getData() == null) {
            return "";
        } else {
            Base64.Decoder decoder = Base64.getDecoder();

            return secret
                    .getData()
                    .entrySet()
                    .stream()
                    .filter(record -> record.getKey().endsWith(".crt"))
                    .map(record -> {
                        byte[] bytes = decoder.decode(record.getValue());
                        return new String(bytes, StandardCharsets.US_ASCII);
                    })
                    .collect(Collectors.joining("\n"));
        }
    }
}
