/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.user.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.operator.common.model.PemKeyStoreSupplier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Provides the default KeyStore supplier for the user operator private and public key
 */
public class UserOperatorKeyStoreSupplier implements PemKeyStoreSupplier {

    private String pemPrivateKey;
    private String pemCertificateChain;

    private static final String KEY_CERT_NAME = "entity-operator";

    /**
     * @param keyCertSecret Kubernetes Secret with the User Operator public and private key
     */
    public UserOperatorKeyStoreSupplier(Secret keyCertSecret) {
        if (keyCertSecret != null) {
            pemPrivateKey = new String(decodeFromSecret(keyCertSecret, KEY_CERT_NAME + ".key"), StandardCharsets.US_ASCII);
            pemCertificateChain = new String(decodeFromSecret(keyCertSecret, KEY_CERT_NAME + ".crt"), StandardCharsets.US_ASCII);
        }
    }

    @Override
    public String pemPrivateKey() {
        return pemPrivateKey;
    }

    @Override
    public String pemCertificateChain() {
        return pemCertificateChain;
    }

    private static byte[] decodeFromSecret(Secret secret, String key) {
        return Base64.getDecoder().decode(secret.getData().get(key));
    }
}
