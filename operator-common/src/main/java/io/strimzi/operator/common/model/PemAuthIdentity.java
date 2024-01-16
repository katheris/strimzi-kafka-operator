/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.operator.common.Util;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Optional;

/**
 * Class to represent the identity used during TLS client authentication in the PEM format.
 */
public class PemAuthIdentity extends AbstractAuthIdentity {

    private final byte[] pemPrivateKey;
    private final byte[] pemCertificateChainBytes;
    private final Certificate pemCertificateChain;
    private String secretName;
    private String secretNamespace;

    /**
     * @param secret Kubernetes Secret containing the Cluster Operator public and private key
     * @param secretKey Key in the Kubernetes Secret that is associated with the requested identity
     */
    private PemAuthIdentity(Secret secret, String secretKey) {
        Optional.ofNullable(secret)
                .map(Secret::getMetadata)
                .ifPresent(objectMeta -> {
                    secretName = objectMeta.getName();
                    secretNamespace = objectMeta.getNamespace();
                });
        pemPrivateKey = AbstractAuthIdentity.extractPemPrivateKey(secret, secretKey);
        pemCertificateChainBytes = AbstractAuthIdentity.extractPemCertificateChain(secret, secretKey);
        pemCertificateChain = validateCertificateChain(secretKey);
    }

    /**
     * Create a new instance of PemAuthIdentity that represents the identity of the
     * cluster operator during TLS client authentication. This also validates the provided
     * Secret contains a valid certificate chain.
     *
     * @param secret Kubernetes Secret containing the client authentication identity
     *
     * @return PemAuthIdentity to use as the client authentication identity during TLS authentication
     */
    public static PemAuthIdentity clusterOperator(Secret secret) {
        return new PemAuthIdentity(secret, "cluster-operator");
    }

    /**
     * Create a new instance of PemAuthIdentity that represents the identity of the
     * entity (i.e. user or topic) operator during TLS client authentication. This also validates
     * the provided Secret contains a valid certificate chain.
     *
     * @param secret Kubernetes Secret containing the client authentication identity
     *
     * @return PemAuthIdentity to use as the client authentication identity during TLS authentication
     */
    public static PemAuthIdentity entityOperator(Secret secret) {
        return new PemAuthIdentity(secret, "entity-operator");
    }

    /**
     * @return The certificate chain for this authentication identity as a Certificate
     */
    public Certificate pemCertificateChain() {
        return pemCertificateChain;
    }

    /**
     * @return The certificate chain for this authentication identity as a byte array
     */
    public byte[] pemCertificateChainBytes() {
        return pemCertificateChainBytes;
    }

    /**
     * @return The certificate chain for this authentication identity as a String
     */
    public String pemCertificateChainString() {
        return AbstractAuthIdentity.asString(pemCertificateChainBytes);
    }

    /**
     * @return The private key for this authentication identity as a byte array
     */
    public byte[] pemPrivateKey() {
        return pemPrivateKey;
    }

    /**
     * @return The private key for this authentication identity as a String
     */
    public String pemPrivateKeyString() {
        return AbstractAuthIdentity.asString(pemPrivateKey);
    }

    private Certificate validateCertificateChain(String secretKey) {
        try {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return certificateFactory.generateCertificate(new ByteArrayInputStream(pemCertificateChainBytes));
        } catch (CertificateException e) {
            throw Util.corruptCertificateException(secretNamespace, secretName, secretKey);
        }
    }
}
