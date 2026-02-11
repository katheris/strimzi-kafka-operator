/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common;

import io.strimzi.api.kafka.model.common.CertificateExpirationPolicy;
import io.strimzi.operator.common.model.Ca;

import java.util.Map;

public class CaCertAndKey {
    protected int caCertGeneration;
    protected int caKeyGeneration;
    protected Map<String, String> caCertData;
    protected Map<String, String> caKeyData;
    protected Ca.RenewalType renewalType;
    protected boolean caCertsRemoved;

    public CaCertAndKey(int caCertGeneration, int caKeyGeneration, Map<String, String> caCertData, Map<String, String> caKeyData) {
        this.caCertGeneration = caCertGeneration;
        this.caKeyGeneration = caKeyGeneration;
        this.caCertData = caCertData;
        this.caKeyData = caKeyData;
    }

    public int getCaCertGeneration() {
        return caCertGeneration;
    }

    public int getCaKeyGeneration() {
        return caKeyGeneration;
    }

    public Map<String, String> getCaCertData() {
        return caCertData;
    }

    public Map<String, String> getCaKeyData() {
        return caKeyData;
    }

    public Ca.RenewalType getRenewalType() {
        return renewalType;
    }

    public boolean isCaCertsRemoved() {
        return caCertsRemoved;
    }

    public void incrementCaCertGeneration() {
        caCertGeneration++;
    }

    public void incrementCaKeyGeneration() {
        caKeyGeneration++;
    }
}
