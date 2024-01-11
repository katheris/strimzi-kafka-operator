/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.operator.common.model.PemKeyStoreSupplier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Provides the default KeyStore supplier for the cluster operator private and public key
 */
public class ClusterOperatorKeyStoreSupplier implements PemKeyStoreSupplier {

    private final String pemPrivateKey;
    private final String pemCertificateChain;

    private static final String KEY_CERT_NAME = "cluster-operator";

    /**
     * @param keyCertSecret Kubernetes Secret with the Cluster Operator public and private key
     */
    public ClusterOperatorKeyStoreSupplier(Secret keyCertSecret) {
        pemPrivateKey = decodeFromSecret(keyCertSecret, KEY_CERT_NAME + ".key");
        pemCertificateChain = decodeFromSecret(keyCertSecret, KEY_CERT_NAME + ".crt");
    }
    @Override
    public String pemPrivateKey() {
        return pemPrivateKey;
    }

    @Override
    public String pemCertificateChain() {
        return pemCertificateChain;
    }

    private static String decodeFromSecret(Secret secret, String key) {
        return Optional.ofNullable(secret)
                .map(Secret::getData)
                .map(data -> data.get(key))
                .map(value -> Base64.getDecoder().decode(value))
                .map(bytes -> new String(bytes, StandardCharsets.US_ASCII))
                .orElse("");
    }
}
