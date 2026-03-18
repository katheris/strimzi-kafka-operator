/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.CertManager;
import io.strimzi.certs.OpenSslCertManager;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.model.Ca;
import io.strimzi.operator.common.model.PasswordGenerator;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

public class StrimziCaProvider {
    protected static final ReconciliationLogger LOGGER = ReconciliationLogger.create(StrimziCaProvider.class);
    private final CertManager certManager;
    private final PasswordGenerator passwordGenerator;

    public StrimziCaProvider() {
        this.certManager = new OpenSslCertManager();
        this.passwordGenerator = new PasswordGenerator(12,
                "abcdefghijklmnopqrstuvwxyz" +
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "abcdefghijklmnopqrstuvwxyz" +
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                        "0123456789");
    }

    public Ca createOrUpdateCa(Reconciliation reconciliation, boolean maintenanceWindowSatisfied, boolean forceReplace, boolean forceRenew,
                               String commonName,
                               String caCertSecretName, Secret caCertSecret,
                               String caKeySecretName, Secret caKeySecret,
                               int validityDays, int renewalDays, boolean generateCa) {
        X509Certificate currentCert = currentCaCertX509();
        Map<String, String> certData;
        Map<String, String> keyData;
        this.renewalType = shouldCreateOrRenewStrimziManagedCa(currentCert, maintenanceWindowSatisfied, forceReplace, forceRenew);
        LOGGER.debugCr(reconciliation, "{} renewalType {}", this, renewalType);

        switch (renewalType) {
            case CREATE -> {
                keyData = new HashMap<>(1);
                certData = new HashMap<>(3);
                generateCaKeyAndCert(nextCaSubject(caKeyGeneration), keyData, certData);
            }
            case REPLACE_KEY -> {
                keyData = new HashMap<>(1);
                certData = new HashMap<>(caCertData);
                if (certData.containsKey(CA_CRT)) {
                    String notAfterDate = DATE_TIME_FORMATTER.format(currentCert.getNotAfter().toInstant().atZone(ZoneId.of("Z")));
                    addCertCaToTrustStore("ca-" + notAfterDate + Ca.SecretEntry.CRT.suffix, certData);
                    certData.put("ca-" + notAfterDate + Ca.SecretEntry.CRT.suffix, certData.remove(CA_CRT));
                }
                ++caCertGeneration;
                generateCaKeyAndCert(nextCaSubject(++caKeyGeneration), keyData, certData);
            }
            case RENEW_CERT -> {
                keyData = new HashMap<>(caKeyData);
                certData = new HashMap<>(3);
                ++caCertGeneration;
                renewCaCert(nextCaSubject(caKeyGeneration), certData);
            }
            default -> {
                keyData = new HashMap<>(caKeyData);
                certData = new HashMap<>(caCertData);
                // coming from an older version, the secret could not have the CA truststore
                if (!certData.containsKey(CA_STORE)) {
                    addCertCaToTrustStore(CA_CRT, certData);
                }
            }
        }

        if (removeCerts(certData, this::removeExpiredCert)) {
            LOGGER.infoCr(reconciliation, "{}: Expired CA certificates removed", this);
            this.caCertsRemoved = true;
        }

        if (renewalType != Ca.RenewalType.NOOP && renewalType != Ca.RenewalType.POSTPONED) {
            LOGGER.debugCr(reconciliation, "{}: {}", this, renewalType.postDescription(caKeySecretName, caCertSecretName));
        }
        caCertData = certData;
        caKeyData = keyData;

    }

    protected CertAndKey generateSignedCert(Reconciliation reconciliation, Ca ca, int validityDays, Subject subject,
                                            File csrFile, File keyFile, File certFile, File keyStoreFile, boolean includeCaChain) {
        LOGGER.infoCr(reconciliation, "Generating certificate {}, signed by CA {}", subject, ca);

        try {
            byte[] caCertBytes = ca.currentCaCertBytes();
            certManager.generateCsr(keyFile, csrFile, subject);
            certManager.generateCert(csrFile, ca.currentCaKey(), caCertBytes,
                    certFile, subject, validityDays);

            String keyStorePassword = passwordGenerator.generate();
            certManager.addKeyAndCertToKeyStore(keyFile, certFile, subject.commonName(), keyStoreFile, keyStorePassword);

            byte[] certChain;
            if (includeCaChain) {
                byte[] leafCert = Files.readAllBytes(certFile.toPath());
                certChain = new byte[leafCert.length + caCertBytes.length];
                System.arraycopy(leafCert, 0, certChain, 0, leafCert.length);
                System.arraycopy(caCertBytes, 0, certChain, leafCert.length, caCertBytes.length);
            } else {
                certChain = Files.readAllBytes(certFile.toPath());
            }

            return new CertAndKey(
                    Files.readAllBytes(keyFile.toPath()),
                    certChain,
                    null,
                    Files.readAllBytes(keyStoreFile.toPath()),
                    keyStorePassword,
                    ca.caCertGeneration());
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException |
                 InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
