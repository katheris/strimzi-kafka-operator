/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common;

import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.CertManager;
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
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class StrimziCaProvider {
    protected static final ReconciliationLogger LOGGER = ReconciliationLogger.create(StrimziCaProvider.class);
    private final Reconciliation reconciliation;
    private final CertManager certManager;
    private final PasswordGenerator passwordGenerator;
    private final Ca ca;
    private final int validityDays;
    private final int renewalDays;
    private final Clock clock;

    public StrimziCaProvider(Reconciliation reconciliation, CertManager certManager, PasswordGenerator passwordGenerator, Ca ca, int validityDays, int renewalDays) {
        this.reconciliation = reconciliation;
        this.certManager = certManager;
        this.passwordGenerator = passwordGenerator;
        this.ca = ca;
        this.validityDays = validityDays;
        this.renewalDays = renewalDays;
        this.clock = Clock.systemUTC();
    }

    /**
     * Copy already existing certificates from based on number of effective replicas
     * and maybe generate new ones for new replicas (i.e. scale-up).
     *
     * @param reconciliation                    Reconciliation marker
     * @param subjects                          Function to generate certificate subject for given node / pod
     * @param existingCertificates              Existing certificates (or null if they do not exist yet)
     * @param isMaintenanceTimeWindowsSatisfied Flag indicating if we are inside a maintenance window or not
     * @return Returns map with node certificates which can be used to create or update the stored certificates
     * @throws IOException Throws IOException when working with files fails
     */
    public Map<String, CertAndKey> maybeCopyOrGenerateCerts(
            Reconciliation reconciliation,
            Map<String, Subject> subjects,
            Map<String, CertAndKey> existingCertificates,
            boolean isMaintenanceTimeWindowsSatisfied
    ) throws IOException {
        // Maps for storing the certificates => will be used in the new or updated certificate store. This map is filled in this method and returned at the end.
        Map<String, CertAndKey> certs = new HashMap<>();

        // Temp files used when we need to generate new certificates
        File brokerCsrFile = Files.createTempFile("tls", "broker-csr").toFile();
        File brokerKeyFile = Files.createTempFile("tls", "broker-key").toFile();
        File brokerCertFile = Files.createTempFile("tls", "broker-cert").toFile();
        File brokerKeyStoreFile = Files.createTempFile("tls", "broker-p12").toFile();

        for (Map.Entry<String, Subject> certKeyAndSubject : subjects.entrySet())  {
            String certKey = certKeyAndSubject.getKey();
            Subject subject = certKeyAndSubject.getValue();
            CertAndKey certAndKey = Optional.ofNullable(existingCertificates)
                    .map(existing -> existing.get(certKey))
                    .orElse(null);

            if (!ca.certRenewed() // No CA renewal is happening
                    && certAndKey != null // There is a public cert and private key for this pod
            )   {
                // A certificate for this node already exists, so we will try to reuse it
                LOGGER.debugCr(reconciliation, "Certificate for node {} already exists", certKeyAndSubject);

                List<String> reasons = new ArrayList<>(2);

                if (certSubjectChanged(certAndKey, subject, certKey))   {
                    reasons.add("DNS names changed");
                }

                if (isExpiring(certAndKey.cert()) && isMaintenanceTimeWindowsSatisfied)  {
                    reasons.add("certificate is expiring");
                }

                if (ca.keyCreated()) {
                    reasons.add("certificate added");
                }

                if (!reasons.isEmpty())  {
                    LOGGER.infoCr(reconciliation, "Certificate for pod {} need to be regenerated because: {}", certKey, String.join(", ", reasons));

                    CertAndKey newCertAndKey = generateSignedCert(subject, brokerCsrFile, brokerKeyFile, brokerCertFile, brokerKeyStoreFile);
                    certs.put(certKey, newCertAndKey);
                }   else {
                    certs.put(certKey, certAndKey);
                }
            } else {
                // A certificate for this node does not exist or it the CA got renewed, so we will generate new certificate
                LOGGER.debugCr(reconciliation, "Generating new certificate for node {}", certKeyAndSubject);
                CertAndKey k = generateSignedCert(subject, brokerCsrFile, brokerKeyFile, brokerCertFile, brokerKeyStoreFile);
                certs.put(certKey, k);
            }
        }

        // Delete the temp files used to generate new certificates
        delete(reconciliation, brokerCsrFile);
        delete(reconciliation, brokerKeyFile);
        delete(reconciliation, brokerCertFile);
        delete(reconciliation, brokerKeyStoreFile);

        return certs;
    }

    /**
     * Checks whether subject alternate names changed and certificate needs a renewal
     *
     * @param certAndKey        Current certificate
     * @param desiredSubject    Desired subject alternate names
     * @param podName           Name of the pod to which this certificate belongs (used for log messages)
     *
     * @return  True if the subjects are different, false otherwise
     */
    protected boolean certSubjectChanged(CertAndKey certAndKey, Subject desiredSubject, String podName)    {
        Collection<String> desiredAltNames = desiredSubject.subjectAltNames().values();
        Collection<String> currentAltNames = getSubjectAltNames(certAndKey.cert());

        if (currentAltNames != null && desiredAltNames.containsAll(currentAltNames) && currentAltNames.containsAll(desiredAltNames))   {
            LOGGER.traceCr(reconciliation, "Alternate subjects match. No need to refresh cert for pod {}.", podName);
            return false;
        } else {
            LOGGER.infoCr(reconciliation, "Alternate subjects for pod {} differ", podName);
            LOGGER.infoCr(reconciliation, "Current alternate subjects: {}", currentAltNames);
            LOGGER.infoCr(reconciliation, "Desired alternate subjects: {}", desiredAltNames);
            return true;
        }
    }

    /**
     * Extracts the alternate subject names out of existing certificate
     *
     * @param certificate   Existing X509 certificate as a byte array
     *
     * @return  List of certificate Subject Alternate Names
     */
    private List<String> getSubjectAltNames(byte[] certificate) {
        List<String> subjectAltNames = null;

        try {
            X509Certificate cert = Ca.x509Certificate(certificate);
            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            subjectAltNames = altNames.stream()
                    .filter(name -> name.get(1) instanceof String)
                    .map(item -> (String) item.get(1))
                    .collect(Collectors.toList());
        } catch (CertificateException | RuntimeException e) {
            // TODO: We should mock the certificates properly so that this doesn't fail in tests (not now => long term :-o)
            LOGGER.debugCr(reconciliation, "Failed to parse existing certificate", e);
        }

        return subjectAltNames;
    }

    /**
     * Returns whether the certificate is expiring or not
     *
     * @param certificate Byte array with the certificate
     *
     * @return  True when the certificate should be renewed. False otherwise.
     */
    protected boolean isExpiring(byte[] certificate)  {
        try {
            X509Certificate currentCert = Ca.x509Certificate(certificate);
            return certNeedsRenewal(currentCert);
        } catch (CertificateException e) {
            LOGGER.errorCr(reconciliation, "Failed to parse existing certificate", e);
            throw new RuntimeException(e);
        }
    }

    private boolean certNeedsRenewal(X509Certificate cert)  {
        Instant notAfter = cert.getNotAfter().toInstant();
        Instant renewalPeriodBegin = notAfter.minus(renewalDays, ChronoUnit.DAYS);
        LOGGER.traceCr(reconciliation, "Certificate {} expires on {} renewal period begins on {}", cert.getSubjectX500Principal(), notAfter, renewalPeriodBegin);
        return this.clock.instant().isAfter(renewalPeriodBegin);
    }

    protected CertAndKey generateSignedCert(Subject subject,
                                            File csrFile, File keyFile, File certFile, File keyStoreFile) throws IOException {
        LOGGER.infoCr(reconciliation, "Generating certificate {}, signed by CA {}", subject, this);

        try {
            certManager.generateCsr(keyFile, csrFile, subject);
            certManager.generateCert(csrFile, ca.currentCaKey(), ca.currentCaCertBytes(),
                    certFile, subject, validityDays);

            String keyStorePassword = passwordGenerator.generate();
            certManager.addKeyAndCertToKeyStore(keyFile, certFile, subject.commonName(), keyStoreFile, keyStorePassword);

            return new CertAndKey(
                    Files.readAllBytes(keyFile.toPath()),
                    Files.readAllBytes(certFile.toPath()),
                    null,
                    Files.readAllBytes(keyStoreFile.toPath()),
                    keyStorePassword);
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException |
                 InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    protected static void delete(Reconciliation reconciliation, File file) {
        if (!file.delete()) {
            LOGGER.warnCr(reconciliation, "{} cannot be deleted", file.getName());
        }
    }

    /**
     * Remove old certificates that are stored in the CA Secret matching the "ca-YYYY-MM-DDTHH-MM-SSZ.crt" naming pattern.
     * NOTE: mostly used when a CA certificate is renewed by replacing the key
     */
    public void maybeDeleteOldCerts() {
        // the operator doesn't have to touch Secret provided by the user with his own custom CA certificate
        if (ca.generateCa) {
            if (ca.removeCerts(ca.caCertData(), entry -> Ca.OLD_CA_CERT_PATTERN.matcher(entry.getKey()).matches())) {
                LOGGER.infoCr(reconciliation, "{}: Old CA certificates removed", this);
                ca.caCertsRemoved = true;
            }
        }
    }
}
