/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.certmanager.api.model.v1.CertificateBuilder;
import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.api.kafka.model.common.certmanager.IssuerRef;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.*;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.ZoneId;
import java.util.*;
import java.util.function.*;


/**
 * A Certificate Authority managed by cert-manager
 */
@SuppressWarnings("checkstyle:CyclomaticComplexity")
public class CertManagerCa extends Ca {

    protected final IssuerRef issuerRef;

    /**
     * Constructs the CA object
     *
     * @param reconciliation        Reconciliation marker
     * @param caCertSecret          Kubernetes Secret where the CA public key is stored
     * @param caKeySecret           Kubernetes Secret where the CA private key is stored
     * @param caConfig              Certificate Authority configuration
     * @param issuerRef              Reference to issuer for issuing certificates through other services like cert-manager
     */
    public CertManagerCa(Reconciliation reconciliation,
                         CaRole caRole,
                         Secret caCertSecret,
                         Secret caKeySecret,
                         CaConfig caConfig,
                         IssuerRef issuerRef) {
        super(reconciliation, caRole, caCertSecret, caKeySecret, caConfig);
        this.issuerRef = issuerRef;
    }

    @Override
    protected int initCaKeyGeneration(Secret caKeySecret, Secret caCertSecret) {
        if (caCertSecret != null) {
            return Annotations.intAnnotation(caCertSecret, ANNO_STRIMZI_IO_CA_KEY_GENERATION, INIT_GENERATION);
        }
        return INIT_GENERATION;
    }

    @Override
    protected Map<String, String> initCaCertData(Secret caCertSecret) {
        if (caCertSecret != null) {
            validateUserCaCertChain(caCertSecret.getData());
            return caCertSecret.getData();
        }
        return new HashMap<>();
    }

    @Override
    protected Map<String, String> initCaKeyData(Secret caKeySecret) {
        // Cert-manager: NO key data (cert-manager manages the keys)
        return new HashMap<>();
    }

    private Subject getSubject(String commonName, String organization) {
        Subject.Builder subject = new Subject.Builder();
        if (organization != null) {
            subject.withOrganizationName(organization);
        }
        subject.withCommonName(commonName);
        return subject.build();
    }

    /**
     * Get Certificate
     * @param commonName Common name
     * @param organization Organization
     * @return Certificate
     */
    public io.fabric8.certmanager.api.model.v1.Certificate getCertManagerCert(String commonName, String organization) {
        return getCertManagerCert(getSubject(commonName, organization));
    }

    /**
     * Get cert-manager Certificate object
     * @param subject Subject
     * @return Certificate
     */
    public io.fabric8.certmanager.api.model.v1.Certificate getCertManagerCert(Subject subject) {
        return new CertificateBuilder()
                .withNewSpec()
                    .withCommonName(subject.commonName())
                    .withNewPrivateKey()
                        .withAlgorithm("RSA")
                        .withEncoding("PKCS8")
                        .withSize(2048)
                    .endPrivateKey()
                    .withDuration(new io.fabric8.kubernetes.api.model.Duration(Duration.ofDays(caConfig.getValidityDays())))
                    .withRenewBefore(new io.fabric8.kubernetes.api.model.Duration(Duration.ofDays(caConfig.getRenewalDays())))
                    .withIsCA(false)
                    .withNewSubject()
                        .withOrganizations(subject.organizationName())
                    .endSubject()
                    .withDnsNames(new ArrayList<>(subject.dnsNames()))
                    .withIpAddresses(new ArrayList<>(subject.ipAddresses()))
                    .withNewIssuerRef()
                        .withName(issuerRef.getName())
                        .withKind(issuerRef.getKind().toValue())
                        .withGroup(issuerRef.getGroup())
                    .endIssuerRef()
                .endSpec()
                .build();
    }

    /**
     * Create or update CA data when cert-manager is managing CA.
     * <p>
     * Store the new data if it doesn't exist already, otherwise check if the certificate has changed
     * and update the data and generations accordingly.
     *
     * @param newCaCertData         New CA cert data.
     * @param existingCaCertHash    Existing CA cert hash to determine if the cert has changed.
     */
    public void createOrUpdateCertManagerCaWithoutEntityCert(String newCaCertData, String existingCaCertHash) {
        if (this.caCertData.isEmpty()) {
            // No data, so we add it
            Map<String, String> caCertData = new HashMap<>();
            caCertData.put(CA_CRT, newCaCertData);
            this.caCertData = caCertData;
            renewalType = RenewalType.CREATE;
        } else {
            String newCaCertHash;
            try {
                X509Certificate x509CaCert = CaUtils.x509Certificate(Util.decodeBytesFromBase64(newCaCertData));
                newCaCertHash = String.format("%040x", new BigInteger(1, Util.sha1Digest(x509CaCert.getEncoded())));
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            }
            if (!existingCaCertHash.equals(newCaCertHash)) {
                // Certificate changed - update cert data and increment generation
                Map<String, String> newCaCertDataMap = new HashMap<>();
                newCaCertDataMap.put(CA_CRT, newCaCertData);
                this.caCertData = newCaCertDataMap;
                renewalType = RenewalType.RENEW_CERT;
                this.caCertGeneration++;
            }
        }
    }

    /**
     * Create or update CA data when cert-manager is managing CA.
     * <p>
     * Store the new data if it doesn't exist already, otherwise check if the certificate has changed
     * and update the data and generations accordingly.
     *
     * @param newCaCertData         New CA cert data.
     * @param existingCaCertHash    Existing CA cert hash to determine if the cert has changed.
     * @param endEntityCertificate  End entity certificate to use for cert path validation.
     */
    public void createOrUpdateCertManagerCa(String newCaCertData, String existingCaCertHash, X509Certificate endEntityCertificate) {
        if (this.caCertData.isEmpty()) {
            // No data, so we add it
            Map<String, String> caCertData = new HashMap<>();
            caCertData.put(CA_CRT, newCaCertData);
            this.caCertData = caCertData;
            renewalType = RenewalType.CREATE;
        } else {
            String newCaCertHash;
            try {
                X509Certificate x509CaCert = CaUtils.x509Certificate(Util.decodeBytesFromBase64(newCaCertData));
                newCaCertHash = String.format("%040x", new BigInteger(1, Util.sha1Digest(x509CaCert.getEncoded())));
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            }
            if (!existingCaCertHash.equals(newCaCertHash)) {
                updateCertAndIncrementGenerations(newCaCertData, endEntityCertificate);
            }
        }
    }

    private void updateCertAndIncrementGenerations(String caCert, X509Certificate endEntityCertificate) {
        if (endEntityCertificate == null) {
            // Cluster operator certificate is missing, so no cert path validation to perform
            // Don't update - wait for operator cert to be available
            LOGGER.warnCr(reconciliation, "Cluster CA cert has changed, but operator certificate is missing - cannot determine if key changed. Will retry in next reconciliation.");
            return;
        }
        X509Certificate x509CaCert;
        try {
            x509CaCert = CaUtils.x509Certificate(Util.decodeBytesFromBase64(caCert));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        if (CaUtils.certIsTrusted(reconciliation, List.of(endEntityCertificate), x509CaCert)) {
            // No key replacement
            Map<String, String> newCaCertData = new HashMap<>();
            newCaCertData.put(CA_CRT, caCert);
            this.caCertData = newCaCertData;
            renewalType = RenewalType.RENEW_CERT;
            this.caCertGeneration++;
        } else {
            // key replacement
            X509Certificate currentCert = currentCaCertX509();
            String notAfterDate = DATE_TIME_FORMATTER.format(currentCert.getNotAfter().toInstant().atZone(ZoneId.of("Z")));
            Map<String, String> newCaCertData = new HashMap<>();
            newCaCertData.put(SecretEntry.CRT.asKey("ca-" + notAfterDate), caCertData.get(CA_CRT));
            newCaCertData.put(CA_CRT, caCert);
            this.caCertData = newCaCertData;
            renewalType = RenewalType.REPLACE_KEY;
            this.caCertGeneration++;
            this.caKeyGeneration++;
        }
    }

    @Override
    protected boolean removeCerts(Map<String, String> newData, Predicate<Map.Entry<String, String>> predicate) {
        Iterator<Map.Entry<String, String>> iter = newData.entrySet().iterator();
        List<String> removed = new ArrayList<>();
        while (iter.hasNext()) {
            Map.Entry<String, String> entry = iter.next();
            boolean remove = predicate.test(entry);
            if (remove) {
                String certName = entry.getKey();
                LOGGER.debugCr(reconciliation, "Removing data.{} from Secret",
                        certName.replace(".", "\\."));
                iter.remove();
                removed.add(certName);
            }
        }
        if (removed.isEmpty()) {
            return false;
        } else {
            return true;
        }
    }

    @Override
    public void maybeDeleteOldCerts() {
        deleteOldCerts();
    }
}
