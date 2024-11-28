/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.strimzi.operator.common.Util;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class CaCert {
    private static final String CA_PREFIX = "ca";
    private static final String CRT_SUFFIX = ".crt";
    private static final String CA_CERT_IN_SECRET_DATA = CA_PREFIX + CRT_SUFFIX;
    private static final String CA_TRUSTSTORE_IN_SECRET_DATA = CA_PREFIX + ".p12";
    private static final String CA_PASSWORD_IN_SECRET_DATA = CA_PREFIX + ".password";
    private byte[] certBytes;
    private Map<String, String> previousCerts;
    private byte[] trustStore;
    private String storePassword;

    public CaCert() {}

    private CaCert(byte[] certBytes, Map<String, String> previousCerts) {
        this.certBytes = certBytes;
        this.previousCerts = previousCerts;
    }

    public CaCert(byte[] certBytes, Map<String, String> previousCerts, byte[] trustStore, String storePassword) {
        this.certBytes = certBytes;
        this.previousCerts = previousCerts;
        this.trustStore = trustStore;
        this.storePassword = storePassword;
    }

    public static CaCert fromSecretData(Map<String, String> secretData) {
        byte[] cert = secretData.get(CA_CERT_IN_SECRET_DATA) != null ? Util.decodeBytesFromBase64(secretData.get(CA_CERT_IN_SECRET_DATA)) : null;
        Map<String, String> previousCerts = extractPreviousCerts(secretData);
        if (secretData.get(CA_TRUSTSTORE_IN_SECRET_DATA) != null && secretData.get(CA_PASSWORD_IN_SECRET_DATA) != null) {
            byte[] trustStore = Util.decodeBytesFromBase64(secretData.get(CA_TRUSTSTORE_IN_SECRET_DATA));
            String storePassword = Util.decodeFromBase64(secretData.get(CA_PASSWORD_IN_SECRET_DATA));
            return new CaCert(cert, previousCerts, trustStore, storePassword);
        } else {
            return new CaCert(cert, previousCerts);
        }
    }

    public void markCurrentCertNotAfter(String notAfterDate) {
        previousCerts.put(CA_PREFIX + "-" + notAfterDate + CRT_SUFFIX, Base64.getEncoder().encodeToString(certBytes));
        certBytes = null;
    }

    public byte[] certBytes() {
        return certBytes;
    }

    public void setCertBytes(byte[] certBytes) {
        this.certBytes = certBytes;
    }

    public Map<String, String> previousCerts() {
        return previousCerts;
    }

    public byte[] trustStore() {
        return trustStore;
    }

    public void setTrustStore(byte[] trustStore) {
        this.trustStore = trustStore;
    }

    public String storePassword() {
        return storePassword;
    }

    public void setStorePassword(String storePassword) {
        this.storePassword = storePassword;
    }

    public boolean containsCertBytes() {
        return certBytes != null;
    }

    public boolean containsTrustStore() {
        return trustStore != null;
    }

    public boolean containsStorePassword() {
        return storePassword != null;
    }

    public Map<String, String> toSecretData() {
        Map<String, String> data = new HashMap<>();
        data.put(CA_CERT_IN_SECRET_DATA, Util.encodeBytesToBase64(certBytes));
        data.put(CA_TRUSTSTORE_IN_SECRET_DATA, Util.encodeBytesToBase64(trustStore));
        data.put(CA_PASSWORD_IN_SECRET_DATA, Util.encodeToBase64(storePassword));
        data.putAll(previousCerts);
        return data;
    }

    private static Map<String, String> extractPreviousCerts(Map<String, String> data)  {
        return data
                .entrySet()
                .stream()
                .filter(record -> record.getKey().endsWith(CRT_SUFFIX))
                .filter(record -> !record.getKey().equals(CA_CERT_IN_SECRET_DATA))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
