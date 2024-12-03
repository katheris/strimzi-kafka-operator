/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.api.kafka.model.common.CertificateExpirationPolicy;
import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.CertManager;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.ReconciliationLogger;
import io.strimzi.operator.common.Util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.chrono.IsoChronology;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.SignStyle;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static java.time.temporal.ChronoField.DAY_OF_MONTH;
import static java.time.temporal.ChronoField.HOUR_OF_DAY;
import static java.time.temporal.ChronoField.MINUTE_OF_HOUR;
import static java.time.temporal.ChronoField.MONTH_OF_YEAR;
import static java.time.temporal.ChronoField.NANO_OF_SECOND;
import static java.time.temporal.ChronoField.SECOND_OF_MINUTE;
import static java.time.temporal.ChronoField.YEAR;

/**
 * A Certificate Authority which can renew its own (self-signed) certificates, and generate signed certificates
 */
@SuppressWarnings("checkstyle:CyclomaticComplexity")
public abstract class Ca {

    /**
     * A certificate entry in a Map. Used to construct the keys in the Map where certificates are stored.
     */
    public enum CertEntry {
        /**
         * A 64-bit encoded X509 Certificate
         */
        CRT(".crt"),
        /**
         * Entity private key
         */
        KEY(".key"),
        /**
         * Entity certificate and key as a P12 keystore
         */
        P12_KEYSTORE(".p12"),
        /**
         * P12 keystore password
         */
        P12_KEYSTORE_PASSWORD(".password");

        final String suffix;

        CertEntry(String suffix) {
            this.suffix = suffix;
        }

        /**
         * Build the Map key to use with this type of CertEntry.
         *
         * @param prefix to use for the certificate Map key
         * @return a certificate Map key with the provided prefix and the suffix of this type of CertEntry
         */
        public String asKey(String prefix) {
            return prefix + suffix;
        }

        /**
         * Checks whether the key has the desired suffix based on the entry.
         *
         * @param key   The key that will be checked whether it matches
         *
         * @return  True if the key matches. False otherwise.
         */
        private boolean matchesType(String key) {
            return key.endsWith(suffix);
        }

    }

    protected static final ReconciliationLogger LOGGER = ReconciliationLogger.create(Ca.class);

    private static final DateTimeFormatter DATE_TIME_FORMATTER = new DateTimeFormatterBuilder()
            .appendValue(YEAR, 4, 10, SignStyle.EXCEEDS_PAD)
            .appendLiteral('-')
            .appendValue(MONTH_OF_YEAR, 2)
            .appendLiteral('-')
            .appendValue(DAY_OF_MONTH, 2)
            .appendLiteral('T')
            .appendValue(HOUR_OF_DAY, 2)
            .appendLiteral('-')
            .appendValue(MINUTE_OF_HOUR, 2)
            .optionalStart()
            .appendLiteral('-')
            .appendValue(SECOND_OF_MINUTE, 2)
            .optionalStart()
            .appendFraction(NANO_OF_SECOND, 0, 9, true)
            .optionalStart()
            .appendOffsetId()
            .toFormatter().withChronology(IsoChronology.INSTANCE);

    private static final String CA_MAP_PREFIX = "ca";

    /**
     * Key for storing the CA private key in a Map
     */
    public static final String CA_KEY = CertEntry.KEY.asKey(CA_MAP_PREFIX);

    /**
     * Key for storing the CA public key in a Map
     */
    public static final String CA_CRT = CertEntry.CRT.asKey(CA_MAP_PREFIX);

    /**
     * Key for storing the CA PKCS21 store in a Map
     */
    public static final String CA_STORE = CertEntry.P12_KEYSTORE.asKey(CA_MAP_PREFIX);

    /**
     * Key for storing the PKCS12 store password in a Map
     */
    public static final String CA_STORE_PASSWORD = CertEntry.P12_KEYSTORE_PASSWORD.asKey(CA_MAP_PREFIX);

    /**
     * Organization used in the generated CAs
     */
    public static final String IO_STRIMZI = "io.strimzi";

    /**
     * Annotation for tracking the CA key generation used by Kubernetes resources
     */
    public static final String ANNO_STRIMZI_IO_CA_KEY_GENERATION = Annotations.STRIMZI_DOMAIN + "ca-key-generation";

    /**
     * Annotation for tracking the CA certificate generation used by Kubernetes resources
     */
    public static final String ANNO_STRIMZI_IO_CA_CERT_GENERATION = Annotations.STRIMZI_DOMAIN + "ca-cert-generation";

    /**
     * Annotation for tracking the Cluster CA generation used by Kubernetes resources
     */
    public static final String ANNO_STRIMZI_IO_CLUSTER_CA_CERT_GENERATION = Annotations.STRIMZI_DOMAIN + "cluster-ca-cert-generation";

    /**
     * Annotation for tracking the Clients CA generation used by Kubernetes resources
     */
    public static final String ANNO_STRIMZI_IO_CLIENTS_CA_CERT_GENERATION = Annotations.STRIMZI_DOMAIN + "clients-ca-cert-generation";

    /**
     * Annotation for tracking the Cluster CA key generation used by Kubernetes resources
     */
    public static final String ANNO_STRIMZI_IO_CLUSTER_CA_KEY_GENERATION = Annotations.STRIMZI_DOMAIN + "cluster-ca-key-generation";

    /**
     * Initial generation used for the CAs
     */
    public static final int INIT_GENERATION = 0;

    private final PasswordGenerator passwordGenerator;
    protected final Reconciliation reconciliation;
    private Clock clock;

    /**
     * Enum describing whether an event related to a certificate renewal is happening or not.
     */
    public enum RenewalType {
        /**
         * No changes to the CA, no renewals are happening.
         */
        NOOP() {
            @Override
            public String preDescription(String caName) {
                return "CA key and certificate for " + caName + " already exist and do not need replacing or renewing";
            }
            @Override
            public String postDescription(String caName) {
                return "noop";
            }
        },
        /**
         * Renewal should be done, but was currently postponed because of the maintenance window configuration
         */
        POSTPONED() {
            @Override
            public String preDescription(String caName) {
                return "CA operation was postponed and will be done in the next maintenance window";
            }
            @Override
            public String postDescription(String caName) {
                return "postponed";
            }
        },
        /**
         * New CA is being created
         */
        CREATE() {
            @Override
            public String preDescription(String caName) {
                return "CA key and certificate for " + caName + " needs to be created";
            }
            @Override
            public String postDescription(String caName) {
                return "CA key and certificate for " + caName + " created";
            }
        },
        /**
         * CA is being renewed (new public key s generated using the same private key)
         */
        RENEW_CERT() {
            @Override
            public String preDescription(String caName) {
                return "CA certificate for " + caName + " needs to be renewed";
            }
            @Override
            public String postDescription(String caName) {
                return "CA certificate for " + caName + " renewed";
            }
        },
        /**
         * CA is being renewed including new private key
         */
        REPLACE_KEY() {
            @Override
            public String preDescription(String caName) {
                return "CA key for " + caName + " needs to be replaced";
            }
            @Override
            public String postDescription(String caName) {
                return "CA key for " + caName + " replaced";
            }
        };

        RenewalType() {
        }

        /**
         * Pre-renewal description which is used to log what is going to happen.
         *
         * @param caName     Name of the CA
         *
         * @return  String with the description
         */
        public abstract String preDescription(String caName);

        /**
         * Post-renewal description which is used to log what was just done.
         *
         * @param caName     Name of the CA
         *
         * @return  String with the description
         */
        public abstract String postDescription(String caName);
    }

    protected final String commonName;
    protected final CertManager certManager;
    protected final int validityDays;
    protected final int renewalDays;
    protected final boolean generateCa;
    protected CertAndGeneration caCert;
    protected CertAndGeneration caKey;
    protected RenewalType renewalType;
    protected boolean caCertsRemoved;
    protected final CertificateExpirationPolicy policy;

    /**
     * Constructs the CA object
     *
     * @param reconciliation        Reconciliation marker
     * @param certManager           Certificate manager instance
     * @param passwordGenerator     Password generator instance
     * @param commonName            Common name which should be used by this CA
     * @param caCertData            CA public cert data
     * @param caCertGeneration      Generation of the CA public cert
     * @param caKeyData             CA private key data
     * @param caKeyGeneration       Generation of the CA private key
     * @param validityDays          Number of days for which the CA certificate should be value
     * @param renewalDays           Number of day before expiration, when the certificate should be renewed
     * @param generateCa            Flag indicating whether the CA should be generated by Strimzi or not
     * @param policy                Policy defining the behavior when the CA expires (renewal or completely replacing the CA)
     */
    public Ca(Reconciliation reconciliation, CertManager certManager, PasswordGenerator passwordGenerator, String commonName,
              Map<String, String> caCertData, int caCertGeneration,
              Map<String, String> caKeyData, int caKeyGeneration,
              int validityDays, int renewalDays, boolean generateCa, CertificateExpirationPolicy policy) {
        if (!generateCa && (caCertData == null || caKeyData == null))   {
            throw new InvalidResourceException(caName() + " should not be generated, but the CA resources were not found.");
        }

        this.reconciliation = reconciliation;
        this.commonName = commonName;
        this.caCert = caCertData != null ? new CertAndGeneration(caCertData, caCertGeneration) : null;
        this.caKey = caKeyData != null ? new CertAndGeneration(caKeyData, caKeyGeneration) : null;
        this.certManager = certManager;
        this.passwordGenerator = passwordGenerator;
        this.validityDays = validityDays;
        this.renewalDays = renewalDays;
        this.generateCa = generateCa;
        this.policy = policy == null ? CertificateExpirationPolicy.RENEW_CERTIFICATE : policy;
        this.renewalType = RenewalType.NOOP;
        this.clock = Clock.systemUTC();
    }

    protected abstract String caName();

    /**
     * Sets the clock to some specific value. This method is useful in testing. But it has to be public because of how
     * the Ca class is shared and inherited between different modules.
     *
     * @param clock     Clock instance that should be used to determine time
     */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    public boolean replacementOrRenewalPostponed() {
        return RenewalType.POSTPONED.equals(this.renewalType);
    }

    protected static void delete(Reconciliation reconciliation, File file) {
        if (!file.delete()) {
            LOGGER.warnCr(reconciliation, "{} cannot be deleted", file.getName());
        }
    }

    /**
     * Adds a certificate into a PKCS12 keystore
     *
     * @param alias     Alias under which it should be stored in the PKCS12 store
     * @param key       Private key
     * @param cert      Public key
     *
     * @return  PKCS12 store with the certificate
     *
     * @throws IOException  Throws an IOException if something fails when working with the files
     */
    public CertAndKey addKeyAndCertToKeyStore(String alias, byte[] key, byte[] cert) throws IOException {
        File keyFile = Files.createTempFile("tls", "key").toFile();
        File certFile = Files.createTempFile("tls", "cert").toFile();
        File keyStoreFile = Files.createTempFile("tls", "p12").toFile();

        Files.write(keyFile.toPath(), key);
        Files.write(certFile.toPath(), cert);

        String keyStorePassword = passwordGenerator.generate();
        certManager.addKeyAndCertToKeyStore(keyFile, certFile, alias, keyStoreFile, keyStorePassword);

        CertAndKey result = new CertAndKey(
                Files.readAllBytes(keyFile.toPath()),
                Files.readAllBytes(certFile.toPath()),
                null,
                Files.readAllBytes(keyStoreFile.toPath()),
                keyStorePassword);

        delete(reconciliation, keyFile);
        delete(reconciliation, certFile);
        delete(reconciliation, keyStoreFile);

        return result;
    }

    protected CertAndKey generateSignedCert(Subject subject,
                                           File csrFile, File keyFile, File certFile, File keyStoreFile) throws IOException {
        LOGGER.infoCr(reconciliation, "Generating certificate {}, signed by CA {}", subject, this);

        certManager.generateCsr(keyFile, csrFile, subject);
        certManager.generateCert(csrFile, currentCaKey(), currentCaCertBytes(),
                certFile, subject, validityDays);

        String keyStorePassword = passwordGenerator.generate();
        certManager.addKeyAndCertToKeyStore(keyFile, certFile, subject.commonName(), keyStoreFile, keyStorePassword);

        return new CertAndKey(
                Files.readAllBytes(keyFile.toPath()),
                Files.readAllBytes(certFile.toPath()),
                null,
                Files.readAllBytes(keyStoreFile.toPath()),
                keyStorePassword);
    }

    /**
     * Generates a certificate signed by this CA
     *
     * @param commonName The CN of the certificate to be generated.
     * @return The CertAndKey
     * @throws IOException If the cert could not be generated.
     */
    public CertAndKey generateSignedCert(String commonName) throws IOException {
        return generateSignedCert(commonName, null);
    }

    /**
     * Generates a certificate signed by this CA
     *
     * @param commonName The CN of the certificate to be generated.
     * @param organization The O of the certificate to be generated. May be null.
     * @return The CertAndKey
     * @throws IOException If the cert could not be generated.
     */
    public CertAndKey generateSignedCert(String commonName, String organization) throws IOException {
        File csrFile = Files.createTempFile("tls", "csr").toFile();
        File keyFile = Files.createTempFile("tls", "key").toFile();
        File certFile = Files.createTempFile("tls", "cert").toFile();
        File keyStoreFile = Files.createTempFile("tls", "p12").toFile();

        Subject.Builder subject = new Subject.Builder();

        if (organization != null) {
            subject.withOrganizationName(organization);
        }

        subject.withCommonName(commonName);

        CertAndKey result = generateSignedCert(subject.build(),
                csrFile, keyFile, certFile, keyStoreFile);

        delete(reconciliation, csrFile);
        delete(reconciliation, keyFile);
        delete(reconciliation, certFile);
        delete(reconciliation, keyStoreFile);
        return result;
    }

    /**
     * Returns whether the certificate is expiring or not
     *
     * @param secret  Secret with the certificate
     * @param certKey   Key under which is the certificate stored
     * @return  True when the certificate should be renewed. False otherwise.
     */
    public boolean isExpiring(Secret secret, String certKey)  {
        boolean isExpiring = false;

        try {
            X509Certificate currentCert = cert(caName(), secret.getData(), certKey);
            isExpiring = certNeedsRenewal(currentCert);
        } catch (RuntimeException e) {
            // TODO: We should mock the certificates properly so that this doesn't fail in tests (not now => long term :-o)
            LOGGER.debugCr(reconciliation, "Failed to parse existing certificate", e);
        }

        return isExpiring;
    }

    /**
     * Returns whether the certificate is expiring or not
     *
     * @param certificate Byte array with the certificate
     *
     * @return  True when the certificate should be renewed. False otherwise.
     */
    public boolean isExpiring(byte[] certificate)  {
        try {
            X509Certificate currentCert = x509Certificate(certificate);
            return certNeedsRenewal(currentCert);
        } catch (CertificateException e) {
            LOGGER.errorCr(reconciliation, "Failed to parse existing certificate", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Create the CA {@code Secrets} if they don't exist, otherwise if within the renewal period then either renew
     * the CA cert or replace the CA cert and key, according to the configured policy. After calling this method
     * {@link #certRenewed()} and {@link #certsRemoved()} will return whether the certificate was renewed and whether
     * expired secrets were removed from the Secret.
     *
     * @param maintenanceWindowSatisfied Flag indicating whether we are in the maintenance window
     */
    public void createRenewOrReplace(
            boolean maintenanceWindowSatisfied,
            boolean forceRenew,
            boolean forceReplace
    ) {
        Map<String, String> certData;
        Map<String, String> keyData;
        int caCertGeneration = caCertGeneration();
        int caKeyGeneration = caKeyGeneration();

        if (!generateCa) {
            certData = caCertData();
            keyData = caKeyData();
            renewalType = RenewalType.NOOP; // User is managing CA
            caCertsRemoved = false;
        } else {
            X509Certificate currentCert = cert(caName(), caCertData(), CA_CRT);
            this.renewalType = shouldCreateOrRenew(currentCert, maintenanceWindowSatisfied, forceRenew, forceReplace);
            LOGGER.debugCr(reconciliation, "{} renewalType {}", this, renewalType);

            switch (renewalType) {
                case CREATE:
                    keyData = new HashMap<>(1);
                    certData = new HashMap<>(3);
                    generateCaKeyAndCert(nextCaSubject(caKeyGeneration), keyData, certData);
                    break;
                case REPLACE_KEY:
                    keyData = new HashMap<>(1);
                    certData = caCertData();
                    if (certData.containsKey(CA_CRT)) {
                        String notAfterDate = DATE_TIME_FORMATTER.format(currentCert.getNotAfter().toInstant().atZone(ZoneId.of("Z")));
                        addCertCaToTrustStore("ca-" + notAfterDate + CertEntry.CRT.suffix, certData);
                        certData.put("ca-" + notAfterDate + CertEntry.CRT.suffix, certData.remove(CA_CRT));
                    }
                    ++caCertGeneration;
                    generateCaKeyAndCert(nextCaSubject(++caKeyGeneration), keyData, certData);
                    break;
                case RENEW_CERT:
                    keyData = caKeyData();
                    certData = new HashMap<>(3);
                    ++caCertGeneration;
                    renewCaCert(nextCaSubject(caKeyGeneration), certData);
                    break;
                default:
                    certData = caCertData();
                    keyData = caKeyData();
                    // coming from an older version, the cert data could not have the CA truststore
                    if (!certData.containsKey(CA_STORE)) {
                        addCertCaToTrustStore(CA_CRT, certData);
                    }
            }
            this.caCertsRemoved = removeCerts(certData, this::removeExpiredCert) > 0;
        }

        if (caCertsRemoved) {
            LOGGER.infoCr(reconciliation, "{}: Expired CA certificates removed", this);
        }

        if (renewalType != RenewalType.NOOP && renewalType != RenewalType.POSTPONED) {
            LOGGER.debugCr(reconciliation, "{}: {}", this, renewalType.postDescription(caName()));
        }

        caCert = new CertAndGeneration(certData, caCertGeneration);
        caKey = new CertAndGeneration(keyData, caKeyGeneration);
    }

    private Subject nextCaSubject(int version) {
        return new Subject.Builder()
        // Key replacements does not work if both old and new CA certs have the same subject DN, so include the
        // key generation in the DN so the certificates appear distinct during CA key replacement.
            .withCommonName(commonName + " v" + version)
            .withOrganizationName(IO_STRIMZI).build();
    }

    private RenewalType shouldCreateOrRenew(X509Certificate currentCert, boolean maintenanceWindowSatisfied, boolean forceRenew, boolean forceReplace) {
        String reason = null;
        RenewalType renewalType = RenewalType.NOOP;
        if (caKey == null
                || caKey.certData() == null
                || caKey.certData().get(CA_KEY) == null) {
            reason = "CA key data for " + caName() + " is missing or lacking data." + CA_KEY.replace(".", "\\.");
            renewalType = RenewalType.CREATE;
        } else if (this.caCert == null
                || this.caCert.certData() == null
                || this.caCert.certData().get(CA_CRT) == null) {
            reason = "CA certificate data for " + caName() + " is missing or lacking data." + CA_CRT.replace(".", "\\.");
            renewalType = RenewalType.RENEW_CERT;
        } else if (forceRenew) {
            reason = "CA certificate for " + caName() + " is being force renewed.";

            if (maintenanceWindowSatisfied) {
                renewalType = RenewalType.RENEW_CERT;
            } else {
                renewalType = RenewalType.POSTPONED;
            }
        } else if (forceReplace) {
            reason = "CA key for " + caName() + " is being force replaced.";

            if (maintenanceWindowSatisfied) {
                renewalType = RenewalType.REPLACE_KEY;
            } else {
                renewalType = RenewalType.POSTPONED;
            }
        } else if (currentCert != null
                && certNeedsRenewal(currentCert)) {
            reason = "Within renewal period for CA certificate (expires on " + currentCert.getNotAfter() + ")";

            if (maintenanceWindowSatisfied) {
                switch (policy) {
                    case REPLACE_KEY:
                        renewalType = RenewalType.REPLACE_KEY;
                        break;
                    case RENEW_CERTIFICATE:
                        renewalType = RenewalType.RENEW_CERT;
                        break;
                }
            } else {
                renewalType = RenewalType.POSTPONED;
            }
        }

        switch (renewalType) {
            case REPLACE_KEY, RENEW_CERT, CREATE, NOOP ->
                    LOGGER.debugCr(reconciliation, "{}: {}: {}", this, renewalType.preDescription(caName()), reason);
            case POSTPONED ->
                    LOGGER.warnCr(reconciliation, "{}: {}: {}", this, renewalType.preDescription(caName()), reason);
        }

        return renewalType;
    }

    /**
     * @return the CA cert data, which contains both the current CA cert and also previous, still valid certs.
     */
    public Map<String, String> caCertData() {
        return caCert != null ? caCert.certData() : null;
    }

    /**
     * @return the CA key data, which contains the current CA private key.
     */
    public Map<String, String> caKeyData() {
        return caKey != null ? caKey.certData() : null;
    }

    /**
     * @return The current CA certificate as bytes.
     */
    public byte[] currentCaCertBytes() {
        return Util.decodeBytesFromBase64(caCertData().get(CA_CRT));
    }

    /**
     * @return The base64 encoded bytes of the current CA certificate.
     */
    public String currentCaCertBase64() {
        return caCertData().get(CA_CRT);
    }

    /**
     * @return The current CA key as bytes.
     */
    public byte[] currentCaKey() {
        return Util.decodeBytesFromBase64(caKeyData().get(CA_KEY));
    }

    /**
     * True if the last call to {@link #createRenewOrReplace(boolean, boolean, boolean)}
     * resulted in expired certificates being removed from the CA {@code Secret}.
     * @return Whether any expired certificates were removed.
     */
    public boolean certsRemoved() {
        return this.caCertsRemoved;
    }

    /**
     * True if the last call to {@link #createRenewOrReplace(boolean, boolean, boolean)}
     * resulted in a renewed CA certificate.
     * @return Whether the certificate was renewed.
     */
    public boolean certRenewed() {
        return renewalType.equals(RenewalType.RENEW_CERT) || renewalType.equals(RenewalType.REPLACE_KEY);
    }

    /**
     * True if the last call to {@link #createRenewOrReplace(boolean, boolean, boolean)}
     * resulted in a replaced CA key.
     * @return Whether the key was replaced.
     */
    public boolean keyReplaced() {
        return renewalType.equals(RenewalType.REPLACE_KEY);
    }

    /**
     * @return  Returns true if the key was newly created
     */
    public boolean keyCreated() {
        return renewalType.equals(RenewalType.CREATE);
    }

    /**
     * @return the generation of the current CA certificate
     */
    public int caCertGeneration() {
        if (caCert != null) {
            return caCert.generation();
        }
        return INIT_GENERATION;
    }

    /**
     * @return the generation of the current CA certificate as an annotation
     */
    public Map.Entry<String, String> caCertGenerationFullAnnotation() {
        return Map.entry(caCertGenerationAnnotation(), String.valueOf(caCertGeneration()));
    }

    /**
     * @return the generation of the current CA key
     */
    public int caKeyGeneration() {
        if (caKey != null) {
            return caKey.generation();
        }
        return INIT_GENERATION;
    }

    /**
     * Predicate used to remove expired certificates that are stored in the CA resource
     *
     * @param entry entry in the CA resource data section to check
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
                LOGGER.infoCr(reconciliation, "The certificate (data.{}) expired {}; removing it",
                        certName.replace(".", "\\."), expiryDate);
            }
        } catch (CertificateException e) {
            // doesn't remove stores and related password
            if (!CertEntry.P12_KEYSTORE.matchesType(certName) && !CertEntry.P12_KEYSTORE_PASSWORD.matchesType(certName)) {
                remove = true;
                LOGGER.debugCr(reconciliation, "The certificate (data.{}) is not an X.509 certificate; removing it",
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
     * @return the number of removed certificates
     */
    protected int removeCerts(Map<String, String> newData, Predicate<Map.Entry<String, String>> predicate) {
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

        if (removed.size() > 0) {
            // the certificates removed from the Secret data has tobe removed from the store as well
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
        }

        return removed.size();
    }

    private boolean certNeedsRenewal(X509Certificate cert)  {
        Instant notAfter = cert.getNotAfter().toInstant();
        Instant renewalPeriodBegin = notAfter.minus(renewalDays, ChronoUnit.DAYS);
        LOGGER.traceCr(reconciliation, "Certificate {} expires on {} renewal period begins on {}", cert.getSubjectX500Principal(), notAfter, renewalPeriodBegin);
        return this.clock.instant().isAfter(renewalPeriodBegin);
    }

    /**
     * Extracts X509 certificate from a Map
     *
     * @param resourceName  Name of the resource the certificate is being stored in
     * @param certData      Map containing the certificate
     * @param key           Key under which the certificate is stored in the Map
     *
     * @return  An X509Certificate instance with the certificate
     */
    public static X509Certificate cert(String resourceName,  Map<String, String> certData, String key)  {
        if (certData == null || certData.get(key) == null) {
            return null;
        }
        byte[] bytes = Util.decodeBytesFromBase64(certData.get(key));
        try {
            return x509Certificate(bytes);
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to decode certificate in data." + key.replace(".", "\\.") + " for " + resourceName, e);
        }
    }

    /**
     * Returns set of all public keys (all .crt records) from a secret
     *
     * @param secret    Kubernetes Secret with certificates
     *
     * @return          Set with X509Certificate instances
     */
    public static Set<X509Certificate> certs(Secret secret)  {
        if (secret == null || secret.getData() == null) {
            return Set.of();
        } else {
            return secret
                    .getData()
                    .entrySet()
                    .stream()
                    .filter(record -> CertEntry.CRT.matchesType(record.getKey()))
                    .map(record -> {
                        byte[] bytes = Util.decodeBytesFromBase64(record.getValue());
                        try {
                            return x509Certificate(bytes);
                        } catch (CertificateException e) {
                            throw new RuntimeException("Failed to decode certificate in data." + record.getKey().replace(".", "\\.") + " of Secret " + secret.getMetadata().getName(), e);
                        }
                    })
                    .collect(Collectors.toSet());
        }
    }

    /**
     * Creates X509Certificate instance from a byte array containing a certificate.
     *
     * @param bytes     Bytes with the X509 certificate
     *
     * @throws CertificateException     Thrown when the creation of the X509Certificate instance fails. Typically, this
     *                                  would happen because the bytes do not contain a valid X509 certificate.
     *
     * @return  X509Certificate instance created based on the Certificate bytes
     */
    public static X509Certificate x509Certificate(byte[] bytes) throws CertificateException {
        CertificateFactory factory = certificateFactory();
        return x509Certificate(factory, bytes);
    }

    static X509Certificate x509Certificate(CertificateFactory factory, byte[] bytes) throws CertificateException {
        Certificate certificate = factory.generateCertificate(new ByteArrayInputStream(bytes));
        if (certificate instanceof X509Certificate) {
            return (X509Certificate) certificate;
        } else {
            throw new CertificateException("Not an X509Certificate: " + certificate);
        }
    }

    static CertificateFactory certificateFactory() {
        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException("No security provider with support for X.509 certificates", e);
        }
        return factory;
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

    private void renewCaCert(Subject subject, Map<String, String> certData) {
        try {
            LOGGER.infoCr(reconciliation, "Renewing CA with subject={}", subject);

            byte[] bytes = Util.decodeBytesFromBase64(caKey.certData().get(CA_KEY));
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
     * @return the name of the annotation bringing the generation of the specific CA certificate type (cluster or clients)
     *         on the Secrets containing certificates signed by that CA (i.e. ZooKeeper nodes, Kafka brokers, ...)
     */
    protected abstract String caCertGenerationAnnotation();

    /**
     * It checks if the current (cluster or clients) CA certificate generation is changed compared to the one
     * brought by the corresponding annotation on the provided Secret (i.e. ZooKeeper nodes, Kafka brokers, ...)
     *
     * @param secret Secret containing certificates signed by the current (clients or cluster) CA
     * @return if the current (cluster or clients) CA certificate generation is changed compared to the one
     *         brought by the corresponding annotation on the provided Secret
     */
    public boolean hasCaCertGenerationChanged(HasMetadata secret) {
        if (secret != null) {
            String caCertGenerationAnno = Annotations.stringAnnotation(secret, caCertGenerationAnnotation(), null);
            int currentCaCertGeneration = caCertGeneration();
            LOGGER.debugOp("Secret {}/{} generation anno = {}, current CA generation = {}",
                    secret.getMetadata().getNamespace(), secret.getMetadata().getName(), caCertGenerationAnno, currentCaCertGeneration);
            return caCertGenerationAnno != null && Integer.parseInt(caCertGenerationAnno) != currentCaCertGeneration;
        }
        return false;
    }


    /**
     * Generates the expiration date as epoch of the CA certificate.
     * @return  Epoch representation of the expiration date of the certificate
     * @throws  RuntimeException if the certificate cannot be decoded or the cert does not exist
     */
    public long getCertificateExpirationDateEpoch() {
        var cert = cert(caName(), caCertData(), CA_CRT);
        if (cert == null) {
            throw new RuntimeException(CA_CRT + " does not exist for CA " + caName());
        }
        return cert.getNotAfter().getTime();
    }

    /**
     * Represents a public certificate that is associated with a particular generation.
     * @param certData Map of certificates
     * @param generation Generation for the public certificate
     */
    public record CertAndGeneration(Map<String, String> certData, int generation) {
    }
}
