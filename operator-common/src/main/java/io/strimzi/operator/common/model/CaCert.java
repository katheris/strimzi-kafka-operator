/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.Util;

import java.util.Objects;

import static io.strimzi.operator.common.model.Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION;
import static io.strimzi.operator.common.model.Ca.INIT_GENERATION;

/**
 * Internal object that represents a Certificate (can be used for public certificate or private key)
 */
public class CaCert {
    private static final String CA_PREFIX = "ca";
    private static final String CA_CERT_IN_SECRET_DATA = CA_PREFIX + ".crt";
    private static final String CA_TRUSTSTORE_IN_SECRET_DATA = CA_PREFIX + ".p12";
    private static final String CA_PASSWORD_IN_SECRET_DATA = CA_PREFIX + ".password";
    private final int generation;
    private final byte[] certBytes;
    private byte[] trustStore;
    private String storePassword;

    private CaCert(int generation, byte[] certBytes) {
        this.generation = generation;
        this.certBytes = certBytes;
    }

    private CaCert(int generation, byte[] certBytes, byte[] trustStore, String storePassword) {
        this.generation = generation;
        this.certBytes = certBytes;
        this.trustStore = trustStore;
        this.storePassword = storePassword;
    }

    public static CaCert fromSecret(Secret secret) {
        Objects.requireNonNull(secret);
        Objects.requireNonNull(secret.getData().get(CA_CERT_IN_SECRET_DATA));
        int generation = secret.getMetadata() != null ? Annotations.intAnnotation(secret, ANNO_STRIMZI_IO_CA_CERT_GENERATION, INIT_GENERATION) : INIT_GENERATION;
        byte[] cert = secret.getData().get(CA_CERT_IN_SECRET_DATA) != null ? Util.decodeBytesFromBase64(secret.getData().get(CA_CERT_IN_SECRET_DATA)) : null;
        if (secret.getData().get(CA_TRUSTSTORE_IN_SECRET_DATA) != null && secret.getData().get(CA_PASSWORD_IN_SECRET_DATA) != null) {
            byte[] trustStore = Util.decodeBytesFromBase64(secret.getData().get(CA_TRUSTSTORE_IN_SECRET_DATA));
            String storePassword = Util.decodeFromBase64(secret.getData().get(CA_PASSWORD_IN_SECRET_DATA));
            return new CaCert(generation, cert, trustStore, storePassword);
        } else {
            return new CaCert(generation, cert);
        }
    }

    public int generation() {
        return generation;
    }

    public byte[] cert() {
        return certBytes;
    }

    public byte[] trustStore() {
        return trustStore;
    }

    public String storePassword() {
        return storePassword;
    }

    boolean containsCertBytes() {
        return certBytes != null;
    }

    boolean containsTrustStore() {
        return trustStore != null;
    }
}
