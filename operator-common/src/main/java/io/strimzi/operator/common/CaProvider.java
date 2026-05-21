package io.strimzi.operator.common;

import io.strimzi.operator.common.model.Ca;

import java.util.Map;

public interface CaProvider {
    /**
     * Gets the CA certificate data, which contains both the current CA cert and also previous, still valid certs.
     *
     * @return the CA cert data, which contains both the current CA cert and also previous, still valid certs.
     */
    Map<String, String> caCertData();

    /**
     * Gets the CA key data, which contains the current CA private key.
     *
     * @return the CA key data, which contains the current CA private key.
     */
    Map<String, String> caKeyData();
}
