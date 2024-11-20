/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.api.kafka.model.common.CertificateAuthority;
import io.strimzi.api.kafka.model.common.CertificateAuthorityBuilder;
import io.strimzi.certs.CertManager;
import io.strimzi.operator.common.Reconciliation;

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
     * @param caCertSecretName      Name of the Kubernetes Secret where the Clients CA public key wil be stored
     * @param clientsCaCert         Kubernetes Secret where the Clients CA public key will be stored
     * @param caSecretKeyName       Name of the Kubernetes Secret where the Clients CA private key wil be stored
     * @param clientsCaKey          Kubernetes Secret where the Clients CA private key will be stored
     */
    public ClientsCa(Reconciliation reconciliation, CertManager certManager, PasswordGenerator passwordGenerator, String caCertSecretName, Secret clientsCaCert,
                     String caSecretKeyName, Secret clientsCaKey) {
        this(reconciliation, certManager, passwordGenerator,
                caCertSecretName,
                clientsCaCert, caSecretKeyName,
                clientsCaKey,
                new CertificateAuthorityBuilder()
                        .withValidityDays(365)
                        .withRenewalDays(30)
                        .withGenerateCertificateAuthority(true)
                        .build());
    }

    /**
     * Creates a ClientsCA instance
     *
     * @param reconciliation        Reconciliation marker
     * @param certManager           Certificate manager instance
     * @param passwordGenerator     Password generator instance
     * @param caCertSecretName      Name of the Kubernetes Secret where the Clients CA public key wil be stored
     * @param clientsCaCert         Kubernetes Secret where the Clients CA public key will be stored
     * @param caSecretKeyName       Name of the Kubernetes Secret where the Clients CA private key wil be stored
     * @param clientsCaKey          Kubernetes Secret where the Clients CA private key will be stored
     * @param caConfig              Configuration for the certificate authority
     */
    public ClientsCa(Reconciliation reconciliation, CertManager certManager, PasswordGenerator passwordGenerator, String caCertSecretName, Secret clientsCaCert,
                     String caSecretKeyName, Secret clientsCaKey,
                     CertificateAuthority caConfig) {
        super(reconciliation, certManager, passwordGenerator,
                "clients-ca", caCertSecretName,
                clientsCaCert, caSecretKeyName,
                clientsCaKey, caConfig);
    }

    @Override
    public String caCertGenerationAnnotation() {
        return ANNO_STRIMZI_IO_CLIENTS_CA_CERT_GENERATION;
    }

    @Override
    public String toString() {
        return "clients-ca";
    }
}
