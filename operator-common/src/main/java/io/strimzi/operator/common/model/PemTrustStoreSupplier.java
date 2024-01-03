/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

/**
 * Interface to be implemented for returning a PEM TrustStore
 */
public interface PemTrustStoreSupplier {
    /**
     * Get trusted certificates from the PEM TrustStore
     *
     * @return trusted certificates
     */
    String pemTrustedCertificates();
}
