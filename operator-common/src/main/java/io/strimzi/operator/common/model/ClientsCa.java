/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.api.kafka.model.common.certmanager.IssuerRef;
import io.strimzi.certs.CertManager;
import io.strimzi.operator.common.Reconciliation;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents the Strimzi Clients CA
 */
public class ClientsCa extends Ca {
    /**
     * Creates a ClientsCA instance
     *
     * @param reconciliation        Reconciliation marker
     * @param certManager           Certificate manager instance
     * @param passwordGenerator     Password generator instance
     * @param clientsCaCert         Kubernetes Secret where the Clients CA public key will be stored
     * @param clientsCaKey          Kubernetes Secret where the Clients CA private key will be stored
     * @param caConfig              Certificate Authority configuration
     */
    public ClientsCa(Reconciliation reconciliation, CertManager certManager, PasswordGenerator passwordGenerator,
                     Secret clientsCaCert, Secret clientsCaKey, CaConfig caConfig) {
        super(reconciliation, certManager, passwordGenerator,
                "clients-ca",
                clientsCaCert,
                clientsCaKey,
                caConfig,
                null);
    }

    /**
     * Creates a ClientsCA instance
     *
     * @param reconciliation         Reconciliation marker
     * @param certManager            Certificate manager instance
     * @param passwordGenerator      Password generator instance
     * @param clientsCaCert          Kubernetes Secret where the Clients CA public key will be stored
     * @param clientsCaKey           Kubernetes Secret where the Clients CA private key will be stored
     * @param caConfig              Certificate Authority configuration
     * @param issuerRef              Reference to issuer for issuing certificates through other services like cert-manager
     */
    public ClientsCa(Reconciliation reconciliation, CertManager certManager, PasswordGenerator passwordGenerator,
                     Secret clientsCaCert, Secret clientsCaKey, CaConfig caConfig, IssuerRef issuerRef) {
        super(reconciliation, certManager, passwordGenerator, "clients-ca", clientsCaCert, clientsCaKey, caConfig, issuerRef);
    }

    @Override
    public String caCertGenerationAnnotation() {
        return ANNO_STRIMZI_IO_CLIENTS_CA_CERT_GENERATION;
    }

    @Override
    public void updateCertAndIncrementGenerations(String caCert, X509Certificate endEntityCertificate) {
        Map<String, String> newCaCertData = new HashMap<>();
        newCaCertData.put(CA_CRT, caCert);
        this.caCertData = newCaCertData;
        this.caCertGeneration++;
    }

    @Override
    public String toString() {
        return "clients-ca";
    }

    @Override
    protected String caName() {
        return "Clients CA";
    }
}
