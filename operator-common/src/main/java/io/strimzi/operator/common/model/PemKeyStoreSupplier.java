/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

/**
 * Interface to be implemented for returning a PEM KeyStore
 */
public interface PemKeyStoreSupplier {
    /**
     * Get private key from the PEM KeyStore
     *
     * @return private key
     */
    String pemPrivateKey();

    /**
     * Get certificate chain from the PEM KeyStore
     *
     * @return certificate chain
     */
    String pemCertificateChain();
}
