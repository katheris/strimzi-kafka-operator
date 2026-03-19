/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.api.kafka.model.common.CertificateExpirationPolicy;
import io.strimzi.api.kafka.model.common.CertificateManagerType;
import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.CertManager;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.model.Ca;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import static io.strimzi.operator.common.model.Ca.CA_CRT;
import static io.strimzi.operator.common.model.Ca.CA_KEY;

public class StrimziCaProvider extends CaProvider {
    protected static final ReconciliationLogger LOGGER = ReconciliationLogger.create(StrimziCaProvider.class);

    private final Reconciliation reconciliation;
    private final Ca ca;
    private final CertManager certManager;
    private final CertificateExpirationPolicy certificateExpirationPolicy;
    private final boolean maintenanceWindowSatisfied;
    private final boolean forceReplace;
    private final boolean forceRenew;

    public StrimziCaProvider(Reconciliation reconciliation, Ca ca, CertManager certManager, CertificateExpirationPolicy certificateExpirationPolicy, boolean maintenanceWindowSatisfied, boolean forceReplace, boolean forceRenew) {
        this.reconciliation = reconciliation;
        this.ca = ca;
        this.certManager = certManager;
        this.certificateExpirationPolicy = certificateExpirationPolicy;
        this.maintenanceWindowSatisfied = maintenanceWindowSatisfied;
        this.forceReplace = forceReplace;
        this.forceRenew = forceRenew;
    }

    @Override
    public CaData createOrUpdateCa() {
        X509Certificate currentCert = ca.currentCaCertX509();
        int caCertGeneration = ca.caCertGeneration();
        int caKeyGeneration = ca.caKeyGeneration();
        Map<String, String> certData;
        Map<String, String> keyData;
        boolean caCertsRemoved;
        Ca.RenewalType renewalType = shouldCreateOrRenewStrimziManagedCa(currentCert, maintenanceWindowSatisfied, forceReplace, forceRenew);
        LOGGER.debugCr(reconciliation, "{} renewalType {}", this, renewalType);

        switch (renewalType) {
            case CREATE -> {
                keyData = new HashMap<>(1);
                certData = new HashMap<>(3);
                generateCaKeyAndCert(nextCaSubject(ca.caKeyGeneration()), keyData, certData);
            }
            case REPLACE_KEY -> {
                keyData = new HashMap<>(1);
                certData = new HashMap<>(ca.caCertData());
                if (certData.containsKey(CA_CRT)) {
                    String notAfterDate = DATE_TIME_FORMATTER.format(currentCert.getNotAfter().toInstant().atZone(ZoneId.of("Z")));
                    addCertCaToTrustStore(Ca.SecretEntry.CRT.asKey("ca-" + notAfterDate), certData);
                    certData.put(Ca.SecretEntry.CRT.asKey("ca-" + notAfterDate), certData.remove(CA_CRT));
                }
                ++caCertGeneration;
                generateCaKeyAndCert(nextCaSubject(++caKeyGeneration), keyData, certData);
            }
            case RENEW_CERT -> {
                keyData = new HashMap<>(ca.caKeyData());
                certData = new HashMap<>(3);
                ++caCertGeneration;
                renewCaCert(nextCaSubject(caKeyGeneration), certData);
            }
            default -> {
                keyData = new HashMap<>(ca.caKeyData());
                certData = new HashMap<>(ca.caCertData());
                // coming from an older version, the secret could not have the CA truststore
                if (!certData.containsKey(Ca.CA_STORE)) {
                    addCertCaToTrustStore(CA_CRT, certData);
                }
            }
        }

        if (removeCerts(certData, this::removeExpiredCert)) {
            LOGGER.infoCr(reconciliation, "{}: Expired CA certificates removed", this);
            caCertsRemoved = true;
        }

        if (renewalType != Ca.RenewalType.NOOP && renewalType != Ca.RenewalType.POSTPONED) {
            LOGGER.debugCr(reconciliation, "{}: {}", this, renewalType.postDescription(ca.caName()));
        }
        return //TODO
    }

    private Ca.RenewalType shouldCreateOrRenewStrimziManagedCa(X509Certificate currentCert, boolean maintenanceWindowSatisfied, boolean forceReplace, boolean forceRenew) {
        String reason = null;
        Ca.RenewalType renewalType = Ca.RenewalType.NOOP;
        if (ca.caKeyData().get(CA_KEY) == null) {
            reason = "CA key secret for " + ca.caName() + " is missing or lacking data." + CA_KEY.replace(".", "\\.");
            renewalType = Ca.RenewalType.CREATE;
        } else if (ca.caCertData().get(CA_CRT) == null) {
            reason = "CA certificate secret for " + ca.caName() + " is missing or lacking data." + CA_CRT.replace(".", "\\.");
            renewalType = Ca.RenewalType.RENEW_CERT;
        } else if (forceRenew) {
            reason = "CA certificate secret for " + ca.caName() + " is annotated with " + Annotations.ANNO_STRIMZI_IO_FORCE_RENEW;

            if (maintenanceWindowSatisfied) {
                renewalType = Ca.RenewalType.RENEW_CERT;
            } else {
                renewalType = Ca.RenewalType.POSTPONED;
            }
        } else if (forceReplace) {
            reason = "CA key secret for " + ca.caName() + " is annotated with " + Annotations.ANNO_STRIMZI_IO_FORCE_REPLACE;

            if (maintenanceWindowSatisfied) {
                renewalType = Ca.RenewalType.REPLACE_KEY;
            } else {
                renewalType = Ca.RenewalType.POSTPONED;
            }
        } else if (currentCert != null
                && certNeedsRenewal(currentCert)) {
            reason = "Within renewal period for CA certificate (expires on " + currentCert.getNotAfter() + ")";

            if (maintenanceWindowSatisfied) {
                renewalType = switch (policy) {
                    case REPLACE_KEY -> Ca.RenewalType.REPLACE_KEY;
                    case RENEW_CERTIFICATE -> Ca.RenewalType.RENEW_CERT;
                };
            } else {
                renewalType = Ca.RenewalType.POSTPONED;
            }
        }

        switch (renewalType) {
            case REPLACE_KEY, RENEW_CERT, CREATE, NOOP ->
                    LOGGER.debugCr(reconciliation, "{}: {}: {}", this, renewalType.preDescription(caKeySecretName, caCertSecretName), reason);
            case POSTPONED ->
                    LOGGER.warnCr(reconciliation, "{}: {}: {}", this, renewalType.preDescription(caKeySecretName, caCertSecretName), reason);
        }

        return renewalType;
    }

    private void generateCaKeyAndCert(Subject subject, Map<String, String> keyData, Map<String, String> certData) {
        try {
            LOGGER.infoCr(reconciliation, "Generating CA with subject={}", subject);
            File keyFile = Files.createTempFile("tls", subject.commonName() + "-key").toFile();
            try {
                File certFile = Files.createTempFile("tls", subject.commonName() + "-cert").toFile();
                try {
                    File trustStoreFile = Files.createTempFile("tls", subject.commonName() + "-truststore").toFile();
                    String trustStorePassword;
                    // if secret already contains the truststore, we have to reuse it without changing password
                    if (certData.containsKey(CA_STORE)) {
                        Files.write(trustStoreFile.toPath(), Util.decodeBytesFromBase64(certData.get(CA_STORE)));
                        trustStorePassword = Util.decodeFromBase64(certData.get(CA_STORE_PASSWORD));
                    } else {
                        trustStorePassword = passwordGenerator.generate();
                    }
                    try {
                        certManager.generateSelfSignedCert(keyFile, certFile, subject, validityDays);
                        certManager.addCertToTrustStore(certFile, CA_CRT, trustStoreFile, trustStorePassword);
                        CertAndKey ca = new CertAndKey(
                                Files.readAllBytes(keyFile.toPath()),
                                Files.readAllBytes(certFile.toPath()),
                                Files.readAllBytes(trustStoreFile.toPath()),
                                null,
                                trustStorePassword);
                        certData.put(CA_CRT, ca.certAsBase64String());
                        keyData.put(CA_KEY, ca.keyAsBase64String());
                        certData.put(CA_STORE, ca.trustStoreAsBase64String());
                        certData.put(CA_STORE_PASSWORD, ca.storePasswordAsBase64String());
                    } finally {
                        delete(reconciliation, trustStoreFile);
                    }
                } finally {
                    delete(reconciliation, certFile);
                }
            } finally {
                delete(reconciliation, keyFile);
            }
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private Subject nextCaSubject(int version) {
        return new Subject.Builder()
                // Key replacements does not work if both old and new CA certs have the same subject DN, so include the
                // key generation in the DN so the certificates appear distinct during CA key replacement.
                .withCommonName(ca.commonName() + " v" + version)
                .withOrganizationName(Ca.IO_STRIMZI).build();
    }

    private void addCertCaToTrustStore(String alias, Map<String, String> certData) {
        try {
            File certFile = Files.createTempFile("tls", "-cert").toFile();
            Files.write(certFile.toPath(), Util.decodeBytesFromBase64(certData.get(CA_CRT)));
            try {
                File trustStoreFile = Files.createTempFile("tls", "-truststore").toFile();
                if (certData.containsKey(CA_STORE)) {
                    Files.write(trustStoreFile.toPath(), Util.decodeBytesFromBase64(certData.get(CA_STORE)));
                }
                try {
                    String trustStorePassword = certData.containsKey(CA_STORE_PASSWORD) ?
                            Util.decodeFromBase64(certData.get(CA_STORE_PASSWORD)) :
                            passwordGenerator.generate();
                    certManager.addCertToTrustStore(certFile, alias, trustStoreFile, trustStorePassword);
                    certData.put(CA_STORE, Base64.getEncoder().encodeToString(Files.readAllBytes(trustStoreFile.toPath())));
                    certData.put(CA_STORE_PASSWORD, Base64.getEncoder().encodeToString(trustStorePassword.getBytes(StandardCharsets.US_ASCII)));
                } finally {
                    delete(reconciliation, trustStoreFile);
                }
            } finally {
                delete(reconciliation, certFile);
            }

        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private void renewCaCert(Subject subject, Map<String, String> certData) {
        try {
            LOGGER.infoCr(reconciliation, "Renewing CA with subject={}", subject);

            byte[] bytes = Util.decodeBytesFromBase64(caKeyData.get(CA_KEY));
            File keyFile = Files.createTempFile("tls", subject.commonName() + "-key").toFile();
            try {
                Files.write(keyFile.toPath(), bytes);
                File certFile = Files.createTempFile("tls", subject.commonName() + "-cert").toFile();
                try {
                    File trustStoreFile = Files.createTempFile("tls", subject.commonName() + "-truststore").toFile();
                    try {
                        String trustStorePassword = passwordGenerator.generate();
                        certManager.renewSelfSignedCert(keyFile, certFile, subject, validityDays);
                        certManager.addCertToTrustStore(certFile, CA_CRT, trustStoreFile, trustStorePassword);
                        CertAndKey ca = new CertAndKey(
                                bytes,
                                Files.readAllBytes(certFile.toPath()),
                                Files.readAllBytes(trustStoreFile.toPath()),
                                null,
                                trustStorePassword);
                        certData.put(CA_CRT, ca.certAsBase64String());
                        certData.put(CA_STORE, ca.trustStoreAsBase64String());
                        certData.put(CA_STORE_PASSWORD, ca.storePasswordAsBase64String());
                    } finally {
                        delete(reconciliation, trustStoreFile);
                    }
                } finally {
                    delete(reconciliation, certFile);
                }
            } finally {
                delete(reconciliation, keyFile);
            }
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Predicate used to remove expired certificates that are stored in the CA Secret
     *
     * @param entry entry in the CA Secret data section to check
     * @return if the certificate is expired and has to be removed
     */
    private boolean removeExpiredCert(Map.Entry<String, String> entry) {
        boolean remove = false;
        String certName = entry.getKey();
        String certText = entry.getValue();
        try {
            X509Certificate cert = x509Certificate(Util.decodeBytesFromBase64(certText));
            Instant expiryDate = cert.getNotAfter().toInstant();
            remove = expiryDate.isBefore(clock.instant());
            if (remove) {
                LOGGER.infoCr(reconciliation, "The certificate (data.{}) in Secret expired {}; removing it",
                        certName.replace(".", "\\."), expiryDate);
            }
        } catch (CertificateException e) {
            // doesn't remove stores and related password
            if (!Ca.SecretEntry.P12_KEYSTORE.matchesType(certName) && !Ca.SecretEntry.P12_KEYSTORE_PASSWORD.matchesType(certName)) {
                remove = true;
                LOGGER.debugCr(reconciliation, "The certificate (data.{}) in Secret is not an X.509 certificate; removing it",
                        certName.replace(".", "\\."));
            }
        }
        return remove;
    }

    /**
     * Remove certificates from the CA related Secret and store which match the provided predicate
     *
     * @param newData data section of the CA Secret containing certificates
     * @param predicate predicate to match for removing a certificate
     * @return boolean indicating whether any certs were removed
     */
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
        } else if (CertificateManagerType.CERT_MANAGER_IO.equals(certificateManagerType)) {
            // when using Cert Manager secrets there is no store
            return true;
        } else {
            // the certificates removed from the Secret data has to be removed from the store as well
            try {
                File trustStoreFile = Files.createTempFile("tls", "-truststore").toFile();
                Files.write(trustStoreFile.toPath(), Util.decodeBytesFromBase64(newData.get(CA_STORE)));
                try {
                    String trustStorePassword = Util.decodeFromBase64(newData.get(CA_STORE_PASSWORD));
                    certManager.deleteFromTrustStore(removed, trustStoreFile, trustStorePassword);
                    newData.put(CA_STORE, Base64.getEncoder().encodeToString(Files.readAllBytes(trustStoreFile.toPath())));
                } finally {
                    delete(reconciliation, trustStoreFile);
                }
            } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            return true;
        }
    }
}
