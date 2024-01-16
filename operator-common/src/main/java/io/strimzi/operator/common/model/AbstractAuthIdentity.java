/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.ObjectMeta;
import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.operator.common.Util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Abstract class to represent the identity used during TLS client authentication
 */
public abstract class AbstractAuthIdentity {

    /**
     * Extract the certificate chain in PEM format from the provided Kubernetes Secret
     * @param secret Kubernetes Secret containing the client authentication identity
     * @param secretKey Key in the Kubernetes Secret that is associated with the requested identity
     * @return The certificate chain in PEM format as a byte array
     */
    protected static byte[] extractPemCertificateChain(Secret secret, String secretKey) {
        return decodeFromSecretAsBytes(secret, String.format("%s.crt", secretKey));
    }

    /**
     * Extract the private key in PEM format from the provided Kubernetes Secret
     * @param secret Kubernetes Secret containing the client authentication identity
     * @param secretKey Key in the Kubernetes Secret that is associated with the requested identity
     * @return The private key in PEM format as a byte array
     */
    protected static byte[] extractPemPrivateKey(Secret secret, String secretKey) {
        return decodeFromSecretAsBytes(secret, String.format("%s.key", secretKey));
    }

    /**
     * Extract the PKSC12 KeyStore from the provided Kubernetes Secret
     * @param secret Kubernetes Secret containing the client authentication identity
     * @param secretKey Key in the Kubernetes Secret that is associated with the requested identity
     * @return The PKSC12 KeyStore as a byte array
     */
    protected static byte[] extractPKCS12KeyStore(Secret secret, String secretKey) {
        return decodeFromSecretAsBytes(secret, String.format("%s.p12", secretKey));
    }

    /**
     * Extract the PKSC12 KeyStore password from the provided Kubernetes Secret
     * @param secret Kubernetes Secret containing the client authentication identity
     * @param secretKey Key in the Kubernetes Secret that is associated with the requested identity
     * @return The PKSC12 KeyStore password as a String
     */
    protected static String extractPKCS12Password(Secret secret, String secretKey) {
        return asString(decodeFromSecretAsBytes(secret, String.format("%s.password", secretKey)));
    }

    /**
     * Decodes the provided byte array using the charset StandardCharsets.US_ASCII
     * @param bytes Byte array to convert to String
     * @return New String object containing the provided byte array
     */
    protected static String asString(byte[] bytes) {
        return new String(bytes, StandardCharsets.US_ASCII);
    }

    private static byte[] decodeFromSecretAsBytes(Secret secret, String key) {
        return Optional.ofNullable(secret)
                .map(Secret::getData)
                .map(data -> data.get(key))
                .map(value -> Base64.getDecoder().decode(value))
                .orElseThrow(() -> {
                    String name = Optional.ofNullable(secret)
                            .map(Secret::getMetadata)
                            .map(ObjectMeta::getName)
                            .orElse("unknown");
                    String namespace = Optional.ofNullable(secret)
                            .map(Secret::getMetadata)
                            .map(ObjectMeta::getNamespace)
                            .orElse("unknown");
                    return Util.missingSecretKeyException(namespace, name, key);
                });
    }
}
