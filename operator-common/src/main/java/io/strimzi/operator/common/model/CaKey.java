/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.strimzi.operator.common.Util;

import java.util.Map;

public class CaKey {
    private static final String CA_KEY_IN_SECRET_DATA = "ca.key";
    private byte[] keyBytes;

    public CaKey() {}

    public CaKey(byte[] keyBytes) {
        this.keyBytes = keyBytes;
    }

    public static CaKey fromSecretData(Map<String, String> secretData) {
        byte[] pemPrivateKey = secretData.get(CA_KEY_IN_SECRET_DATA) != null ? Util.decodeBytesFromBase64(secretData.get(CA_KEY_IN_SECRET_DATA)) : null;
        return new CaKey(pemPrivateKey);
    }

    public byte[] keyBytes() {
        return keyBytes;
    }

    public void setKeyBytes(byte[] keyBytes) {
        this.keyBytes = keyBytes;
    }

    public boolean containsKeyBytes() {
        return keyBytes != null;
    }

    public Map<String, String> toSecretData() {
        return Map.of(CA_KEY_IN_SECRET_DATA, Util.encodeBytesToBase64(keyBytes));
    }
}
