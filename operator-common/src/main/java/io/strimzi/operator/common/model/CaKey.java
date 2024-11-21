/**
 * Internal object that represents a CA private key
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.Util;

import java.util.Objects;

import static io.strimzi.operator.common.model.Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION;
import static io.strimzi.operator.common.model.Ca.INIT_GENERATION;

public class CaKey {
    private static final String CA_KEY_IN_SECRET_DATA = "ca.key";
    private final String caName;
    private final int generation;
    private final byte[] keyBytes;

    private CaKey(String caName, int generation, byte[] keyBytes) {
        this.caName = caName;
        this.generation = generation;
        this.keyBytes = keyBytes;
    }

    public static CaKey fromSecret(String caName, Secret secret) {
        Objects.requireNonNull(secret);
        int generation = secret.getMetadata() != null ? Annotations.intAnnotation(secret, ANNO_STRIMZI_IO_CA_KEY_GENERATION, INIT_GENERATION) : INIT_GENERATION;
        byte[] pemPrivateKey = secret.getData().get(CA_KEY_IN_SECRET_DATA) != null ? Util.decodeBytesFromBase64(secret.getData().get(CA_KEY_IN_SECRET_DATA)) : null;
        return new CaKey(caName, generation, pemPrivateKey);
    }

    public String caName() {
        return caName;
    }

    public int generation() {
        return generation;
    }

    public byte[] keyBytes() {
        return keyBytes;
    }

    boolean containsCertBytes() {
        return keyBytes != null;
    }
}
