/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.CertManager;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.CaProvider;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.ReconciliationLogger;
import io.strimzi.operator.common.InternalCaProvider;
import io.strimzi.operator.common.Util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A Certificate Authority which can renew its own (self-signed) certificates, and generate signed certificates
 */
@SuppressWarnings("checkstyle:CyclomaticComplexity")
public abstract class Ca {

    /**
     * A certificate entry in a Kubernetes Secret. Used to construct the keys in the Secret data where certificates are stored.
     */
    public enum SecretEntry {
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

        SecretEntry(String suffix) {
            this.suffix = suffix;
        }

        /**
         * Build the Kubernetes Secret key to use with this type of SecretEntry.
         *
         * @param prefix to use for the certificate Secret key
         * @return a certificate Secret key with the provided prefix and the suffix of this type of SecretEntry
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
        public boolean matchesType(String key) {
            return key.endsWith(suffix);
        }

    }

    /**
     * Pattern used for the old CA certificate during CA renewal. This pattern is used to recognize this certificate
     * and delete it when it is not needed anymore.
     */
    public static final Pattern OLD_CA_CERT_PATTERN = Pattern.compile("^ca-\\d{4}-\\d{2}-\\d{2}T\\d{2}-\\d{2}-\\d{2}Z.crt$");


    protected static final ReconciliationLogger LOGGER = ReconciliationLogger.create(Ca.class);

    private static final String CA_SECRET_PREFIX = "ca";

    /**
     * Key for storing the CA private key in a Kubernetes Secret
     */
    public static final String CA_KEY = SecretEntry.KEY.asKey(CA_SECRET_PREFIX);

    /**
     * Key for storing the CA public key in a Kubernetes Secret
     */
    public static final String CA_CRT = SecretEntry.CRT.asKey(CA_SECRET_PREFIX);

    /**
     * Key for storing the CA PKCS21 store in a Kubernetes Secret
     */
    public static final String CA_STORE = SecretEntry.P12_KEYSTORE.asKey(CA_SECRET_PREFIX);

    /**
     * Key for storing the PKCS12 store password in a Kubernetes Secret
     */
    public static final String CA_STORE_PASSWORD = SecretEntry.P12_KEYSTORE_PASSWORD.asKey(CA_SECRET_PREFIX);

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
    private final CaProvider caProvider;
    protected final String commonName;
    protected final CertManager certManager;
    protected int caCertGeneration;
    protected int caKeyGeneration;
    protected final CaConfig caConfig;

    /**
     * Constructs the CA object
     *
     * @param reconciliation        Reconciliation marker
     * @param certManager           Certificate manager instance
     * @param passwordGenerator     Password generator instance
     * @param commonName            Common name which should be used by this CA
     * @param caCertSecret          Kubernetes Secret where the CA public key is stored
     * @param caKeySecret           Kubernetes Secret where the CA private key is stored
     * @param caConfig              Certificate Authority configuration
     */
    //Tested by CaTest
    public Ca(Reconciliation reconciliation,
              CertManager certManager,
              PasswordGenerator passwordGenerator,
              String commonName,
              Secret caCertSecret,
              Secret caKeySecret,
              CaConfig caConfig) {
        boolean isGenerateCa = caConfig.isGenerateCa();
        if (!isGenerateCa && (caCertSecret == null || caKeySecret == null))   {
            throw new InvalidResourceException(caName() + " should not be generated, but the secrets were not found.");
        }

        this.reconciliation = reconciliation;
        this.commonName = commonName;
        this.caCertGeneration = initCaCertGeneration(caCertSecret);
        this.caKeyGeneration = initCaKeyGeneration(caKeySecret);
        this.certManager = certManager;
        this.passwordGenerator = passwordGenerator;
        this.caConfig = caConfig;
        this.clock = Clock.systemUTC();
        this.caProvider = new InternalCaProvider(reconciliation, caName(), certManager, passwordGenerator, commonName, caCertSecret, caKeySecret, caConfig);
    }

    public abstract String caName();

    /**
     * Sets the clock to some specific value. This method is useful in testing. But it has to be public because of how
     * the Ca class is shared and inherited between different modules.
     *
     * @param clock     Clock instance that should be used to determine time
     */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    /**
     * Extracts the CA generation from the CA cert Secret
     *
     * @param caCertSecret Secret to extract the CA cert from
     * @return CA generation or the initial generation if no generation is set
     */
    protected int initCaCertGeneration(Secret caCertSecret) {
        if (caCertSecret != null) {
            if (!Annotations.hasAnnotation(caCertSecret, ANNO_STRIMZI_IO_CA_CERT_GENERATION)) {
                LOGGER.warnOp("Secret {}/{} is missing generation annotation {}",
                        caCertSecret.getMetadata().getNamespace(), caCertSecret.getMetadata().getName(), ANNO_STRIMZI_IO_CA_CERT_GENERATION);
            }
            return Annotations.intAnnotation(caCertSecret, ANNO_STRIMZI_IO_CA_CERT_GENERATION, INIT_GENERATION);
        }
        return INIT_GENERATION;
    }

    /**
     * Extracts the CA key generation from the CA key Secret
     *
     * @param caKeySecret Secret to extract the CA key from
     * @return CA key generation or the initial generation if no generation is set
     */
    private int initCaKeyGeneration(Secret caKeySecret) {
        if (caKeySecret != null) {
            if (!Annotations.hasAnnotation(caKeySecret, ANNO_STRIMZI_IO_CA_KEY_GENERATION)) {
                LOGGER.warnOp("Secret {}/{} is missing generation annotation {}",
                        caKeySecret.getMetadata().getNamespace(), caKeySecret.getMetadata().getName(), ANNO_STRIMZI_IO_CA_KEY_GENERATION);
            }
            return Annotations.intAnnotation(caKeySecret, ANNO_STRIMZI_IO_CA_KEY_GENERATION, INIT_GENERATION);
        }
        return INIT_GENERATION;
    }

    protected static void delete(Reconciliation reconciliation, File file) {
        if (file != null && !file.delete()) {
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
        try {
            File keyFile = Files.createTempFile("tls", "key").toFile();
            File certFile = Files.createTempFile("tls", "cert").toFile();
            File keyStoreFile = null;

            try {
                Files.write(keyFile.toPath(), key);
                Files.write(certFile.toPath(), cert);

                if (caConfig.isGeneratePkcs12Stores()) {
                    keyStoreFile = Files.createTempFile("tls", "p12").toFile();

                    String keyStorePassword = passwordGenerator.generate();
                    certManager.addKeyAndCertToKeyStore(keyFile, certFile, alias, keyStoreFile, keyStorePassword);

                    return new CertAndKey(
                            Files.readAllBytes(keyFile.toPath()),
                            Files.readAllBytes(certFile.toPath()),
                            null,
                            Files.readAllBytes(keyStoreFile.toPath()),
                            keyStorePassword);
                } else {
                    return new CertAndKey(
                            Files.readAllBytes(keyFile.toPath()),
                            Files.readAllBytes(certFile.toPath()),
                            null,
                            null,
                            null);
                }
            } finally {
                delete(reconciliation, keyFile);
                delete(reconciliation, certFile);
                delete(reconciliation, keyStoreFile);
            }
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    protected CertAndKey generateSignedCert(Subject subject,
                                           File csrFile, File keyFile, File certFile, File keyStoreFile, boolean includeCaChain) {
        LOGGER.infoCr(reconciliation, "Generating certificate {}, signed by CA {}", subject, this);

        try {
            byte[] caCertBytes = currentCaCertBytes();
            certManager.generateCsr(keyFile, csrFile, subject);
            certManager.generateCert(csrFile, currentCaKey(), caCertBytes,
                    certFile, subject, caConfig.getValidityDays());

            byte[] certChain;
            if (includeCaChain) {
                byte[] leafCert = Files.readAllBytes(certFile.toPath());
                certChain = new byte[leafCert.length + caCertBytes.length];
                System.arraycopy(leafCert, 0, certChain, 0, leafCert.length);
                System.arraycopy(caCertBytes, 0, certChain, leafCert.length, caCertBytes.length);
            } else {
                certChain = Files.readAllBytes(certFile.toPath());
            }

            if (caConfig.isGeneratePkcs12Stores()) {
                String keyStorePassword = passwordGenerator.generate();
                certManager.addKeyAndCertToKeyStore(keyFile, certFile, subject.commonName(), keyStoreFile, keyStorePassword);

                return new CertAndKey(
                        Files.readAllBytes(keyFile.toPath()),
                        certChain,
                        null,
                        Files.readAllBytes(keyStoreFile.toPath()),
                        keyStorePassword,
                        caCertGeneration);
            } else {
                return new CertAndKey(
                        Files.readAllBytes(keyFile.toPath()),
                        certChain,
                        null,
                        null,
                        null,
                        caCertGeneration);
            }
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
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
                csrFile, keyFile, certFile, keyStoreFile, false);

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
    //Tested by ClusterCaTest
    public boolean isExpiring(Secret secret, String certKey)  {
        X509Certificate currentCert = cert(secret, certKey);
        return certNeedsRenewal(currentCert);
    }

    /**
     * Create the CA {@code Secrets} if they don't exist, otherwise if within the renewal period then either renew
     * the CA cert or replace the CA cert and key, according to the configured policy. After calling this method
     * {@link #certsRemoved()} will return whether expired secrets were removed from the Secret.
     *
     * @param maintenanceWindowSatisfied Flag indicating whether we are in the maintenance window
     * @param forceReplace Flag indicating whether to do a force replace
     * @param forceRenew Flag indicating whether to do a force renew
     */
    //Tested by CaTest, ClusterCaTest
    public void createRenewOrReplace(boolean maintenanceWindowSatisfied, boolean forceReplace, boolean forceRenew) {
        caProvider.createRenewOrReplace(maintenanceWindowSatisfied, forceReplace, forceRenew);
    }



    /**
     * Gets the CA certificate data, which contains both the current CA cert and also previous, still valid certs.
     *
     * @return the CA cert data, which contains both the current CA cert and also previous, still valid certs.
     */
    public Map<String, String> caCertData() {
        return caProvider.caCertData();
    }

    /**
     * Gets the CA key data, which contains the current CA private key.
     *
     * @return the CA key data, which contains the current CA private key.
     */
    public Map<String, String> caKeyData() {
        return caProvider.caKeyData();
    }

    /**
     * Gets the current CA certificate as bytes.
     *
     * @return The current CA certificate as bytes.
     */
    public byte[] currentCaCertBytes() {
        return Util.decodeBytesFromBase64(caCertData().get(CA_CRT));
    }

    /**
     * Gets the base64 encoded bytes of the current CA certificate.
     *
     * @return The base64 encoded bytes of the current CA certificate.
     */
    public String currentCaCertBase64() {
        return caCertData().get(CA_CRT);
    }

    private X509Certificate currentCaCertX509() {
        if (caCertData().get(CA_CRT) != null) {
            try {
                return x509Certificate(currentCaCertBytes());
            } catch (CertificateException e) {
                throw new RuntimeException("Failed to decode "  + CA_CRT + " in Secret for " + caName(), e);
            }
        } else {
            return null;
        }
    }

    /**
     * Returns the certificates that a client authenticating against the CA should trust. When a chain of multiple CAs
     * is used, only the last certificate from the chain should be included.
     *
     * @return  Certificates that clients authenticating against this CA should trust
     */
    public String trustedCaCerts() {
        return caCertData().entrySet().stream()
                .filter(e -> e.getKey().endsWith(SecretEntry.CRT.suffix) && e.getValue() != null && !e.getValue().isBlank())
                .map(e -> {
                    try {
                        return x509CertificateToPem(x509Certificate(Util.decodeBytesFromBase64(e.getValue())));
                    } catch (CertificateException ex) {
                        throw new RuntimeException("Failed to decode " + e.getKey() + " in Secret for " + caName(), ex);
                    }
                })
                .collect(Collectors.joining(System.lineSeparator()));
    }

    /**
     * Converts the Java X509Certificate into the proper PEM format.
     *
     * @param cert  X509 certificate to convert
     *
     * @return  String with PEM encoded certificate
     *
     * @throws CertificateEncodingException An exception might be thrown if the certificate encoding fails
     */
    //Tested by CaTest
    public static String x509CertificateToPem(X509Certificate cert) throws CertificateEncodingException {
        Base64.Encoder encoder = Base64.getMimeEncoder(64, System.lineSeparator().getBytes(StandardCharsets.US_ASCII));

        return "-----BEGIN CERTIFICATE-----\n"
                + new String(encoder.encode(cert.getEncoded()), StandardCharsets.US_ASCII)
                + "\n-----END CERTIFICATE-----";
    }

    /**
     * Gets the current CA key as bytes.
     *
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
        return caProvider.certsRemoved();
    }

    /**
     * True if the last call to {@link #createRenewOrReplace(boolean, boolean, boolean)}
     * resulted in a renewed CA certificate.
     * @return Whether the certificate was renewed.
     */
    public boolean certRenewed() {
        return caProvider.certRenewed();
    }

    /**
     * True if the last call to {@link #createRenewOrReplace(boolean, boolean, boolean)}
     * resulted in a replaced CA key.
     * @return Whether the key was replaced.
     */
    public boolean keyReplaced() {
        return caProvider.keyReplaced();
    }

    /**
     * Checks if the key was newly created.
     *
     * @return  Returns true if the key was newly created
     */
    public boolean keyCreated() {
        return caProvider.keyCreated();
    }

    /**
     * Checks if the renewal or replacement was postponed.
     *
     * @return Returns true if the renewal or replacement was postponed
     */
    public boolean postponed() {
        return caProvider.postponed();
    }

    /**
     * Gets the generation of the current CA certificate.
     *
     * @return the generation of the current CA certificate
     */
    public int caCertGeneration() {
        return caCertGeneration;
    }

    /**
     * Gets the generation of the current CA certificate as an annotation.
     *
     * @return the generation of the current CA certificate as an annotation
     */
    public Map.Entry<String, String> caCertGenerationFullAnnotation() {
        return Map.entry(caCertGenerationAnnotation(), String.valueOf(caCertGeneration));
    }

    /**
     * Gets the generation of the current CA key.
     *
     * @return the generation of the current CA key
     */
    public int caKeyGeneration() {
        return caKeyGeneration;
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
        } else {
            if (caConfig.isGeneratePkcs12Stores()) {
                // the certificates removed from the Secret data have to be removed from the store as well
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

            return true;
        }
    }

    private boolean certNeedsRenewal(X509Certificate cert)  {
        Instant notAfter = cert.getNotAfter().toInstant();
        Instant renewalPeriodBegin = notAfter.minus(caConfig.getRenewalDays(), ChronoUnit.DAYS);
        LOGGER.traceCr(reconciliation, "Certificate {} expires on {} renewal period begins on {}", cert.getSubjectX500Principal(), notAfter, renewalPeriodBegin);
        return this.clock.instant().isAfter(renewalPeriodBegin);
    }

    /**
     * Extracts X509 certificate from a Kubernetes Secret
     *
     * @param secret    Kubernetes Secret with the certificate
     * @param key       Key under which the certificate is stored in the Secret
     *
     * @return  An X509Certificate instance with the certificate
     */
    public static X509Certificate cert(Secret secret, String key)  {
        if (secret == null || secret.getData() == null || secret.getData().get(key) == null) {
            return null;
        }
        byte[] bytes = Util.decodeBytesFromBase64(secret.getData().get(key));
        try {
            return x509Certificate(bytes);
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to decode certificate in data." + key.replace(".", "\\.") + " of Secret " + secret.getMetadata().getName(), e);
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
    //Tested by CaTest
    public static X509Certificate x509Certificate(byte[] bytes) throws CertificateException {
        CertificateFactory factory = certificateFactory();
        return x509Certificate(factory, bytes);
    }

    static X509Certificate x509Certificate(CertificateFactory factory, byte[] bytes) throws CertificateException {
        // When bytes contain a certificate chain, read only the first certificate
        // to get thumbprints of the leaf certificate
        Certificate certificate = factory.generateCertificates(new ByteArrayInputStream(bytes)).stream().findFirst().orElse(null);
        if (certificate instanceof X509Certificate) {
            return (X509Certificate) certificate;
        } else {
            throw new CertificateException("Not an X509Certificate: " + certificate);
        }
    }

    public static CertificateFactory certificateFactory() {
        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException("No security provider with support for X.509 certificates", e);
        }
        return factory;
    }

    /**
     * Gets the name of the annotation bringing the generation of the specific CA certificate type.
     *
     * @return the name of the annotation bringing the generation of the specific CA certificate type (cluster or clients)
     *         on the Secrets containing certificates signed by that CA (i.e. Kafka brokers, ...)
     */
    protected abstract String caCertGenerationAnnotation();

    /**
     * It checks if the current (cluster or clients) CA certificate generation is changed compared to the one
     * brought by the corresponding annotation on the provided Resource (i.e. Secret containing Kafka broker certificates, Kafka Pods presenting certificates...)
     *
     * @param resource Resource (Secret or Pod) containing or presenting certificates signed by the current (clients or cluster) CA
     * @return if the current (cluster or clients) CA certificate generation is changed compared to the one
     *         brought by the corresponding annotation on the provided Resource
     */
    public boolean hasCaCertGenerationChanged(HasMetadata resource) {
        if (resource != null && Annotations.hasAnnotation(resource, caCertGenerationAnnotation())) {
            int caCertGenerationAnno = Annotations.intAnnotation(resource, caCertGenerationAnnotation(), INIT_GENERATION);
            LOGGER.debugOp("{} {}/{} generation anno = {}, current CA generation = {}", resource.getKind(),
                    resource.getMetadata().getNamespace(), resource.getMetadata().getName(), caCertGenerationAnno, caCertGeneration);
            return caCertGenerationAnno != caCertGeneration;
        }
        return false;
    }

    /**
     * Generates the expiration date as epoch of the CA certificate.
     * @return  Epoch representation of the expiration date of the certificate
     * @throws  RuntimeException if the certificate cannot be decoded or the cert does not exist
     */
    // Tested by CaTest
    public long getCertificateExpirationDateEpoch() {
        var cert = currentCaCertX509();
        if (cert == null) {
            throw new RuntimeException(CA_CRT + " does not exist in the secret for " + caName());
        }
        return cert.getNotAfter().getTime();
    }

    /**
     * Validates whether the provided cert chain is trusted and valid using the provided CA certificate.
     * <p>
     * Uses the <code>CertPathValidator.validate</code> method to check if a cert chain
     * can be validated with the provided caCert. If the cert chain contains more than one
     * certificate the first certificate should be the end entity (or leaf) certificate, while
     * the final certificate should be the one issued by the root Ca. The root Ca should not be
     * included in the cert chain list.
     *
     * @param reconciliation Reconciliation marker
     * @param certChainToValidate Certificates to validate. Can be a single certificate or a chain of ordered certificates.
     * @param caCert The root Ca certificate to use for validation.
     *
     * @return True if the CA certificate can be used to validate the provided certificate or certificate chain. False otherwise.
     */
    //Tested by CaTest
    public static boolean certIsTrusted(Reconciliation reconciliation, List<X509Certificate> certChainToValidate, X509Certificate caCert) {
        CertPathValidator certPathValidator;
        CertPath eeCertPath;
        PKIXParameters pkixParams;
        try {
            certPathValidator = CertPathValidator.getInstance("PKIX");
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            TrustAnchor trustAnchor = new TrustAnchor(caCert, null);
            pkixParams = new PKIXParameters(Collections.singleton(trustAnchor));
            pkixParams.setRevocationEnabled(false);
            eeCertPath = factory.generateCertPath(certChainToValidate);
        } catch (NoSuchAlgorithmException | CertificateException | InvalidAlgorithmParameterException e) {
            LOGGER.errorCr(reconciliation, "Error constructing objects to validate certificate chain.", e);
            throw new RuntimeException(e);
        }
        try {
            certPathValidator.validate(eeCertPath, pkixParams);
            LOGGER.debugCr(reconciliation, "Certificate chain validated using supplied CA cert.");
            return true;
        } catch (CertPathValidatorException e) {
            LOGGER.errorCr(reconciliation, "Certificate chain cannot be validated with supplied CA cert.", e);
            return false;
        } catch (InvalidAlgorithmParameterException e) {
            LOGGER.errorCr(reconciliation, "Error validating the certificate chain.", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Remove old certificates that are stored in the CA Secret matching the "ca-YYYY-MM-DDTHH-MM-SSZ.crt" naming pattern.
     * NOTE: mostly used when a CA certificate is renewed by replacing the key
     */
    public void maybeDeleteOldCerts() {
        caProvider.maybeDeleteOldCerts();
    }

    /**
     * Copy already existing certificates from based on number of effective replicas
     * and maybe generate new ones for new replicas (i.e. scale-up).
     *
     * @param reconciliation                        Reconciliation marker
     * @param subjects                              Subjects for a given pod
     * @param existingCertificates                  Existing certificates (or null if they do not exist yet)
     * @param isMaintenanceTimeWindowsSatisfied     Flag indicating if we are inside a maintenance window or not
     *
     * @return Returns map with node certificates which can be used to create or update the stored certificates
     *
     * @throws IOException Throws IOException when working with files fails
     */
    //Tested by ClusterCaRenewalTest
    public Map<String, CertAndKey> maybeCopyOrGenerateServerCerts(
            Reconciliation reconciliation,
            Map<String, Subject> subjects,
            Map<String, CertAndKey> existingCertificates,
            boolean isMaintenanceTimeWindowsSatisfied,
            boolean includeCaChain
    ) throws IOException {
        return caProvider.maybeCopyOrGenerateServerCerts(reconciliation,
                subjects,
                existingCertificates,
                isMaintenanceTimeWindowsSatisfied,
                includeCaChain);
    }


    /**
     * Generates or reuses a single certificate signed by this Cluster CA.
     * Used for components that only act as clients, like Entity Operators and Kafka Exporter.
     *
     * @param reconciliation                        Reconciliation marker
     * @param commonName                            Common Name for the certificate
     * @param existingCertAndKey                    Existing certificate (or null if none exists)
     * @param isMaintenanceTimeWindowsSatisfied     Whether we are in a maintenance window
     *
     * @return CertAndKey object containing the certificate and key with CA generation set
     */
    //Tested by ClusterCaRenewalTest
    public CertAndKey maybeCopyOrGenerateClientCert(
            Reconciliation reconciliation,
            String commonName,
            CertAndKey existingCertAndKey,
            boolean isMaintenanceTimeWindowsSatisfied
    ) {
       return caProvider.maybeCopyOrGenerateClientCert(
               reconciliation,
               commonName,
               existingCertAndKey,
               isMaintenanceTimeWindowsSatisfied
       );
    }
}
