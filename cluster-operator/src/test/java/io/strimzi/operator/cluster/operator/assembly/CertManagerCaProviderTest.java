/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.assembly;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.strimzi.api.kafka.model.common.CertificateAuthority;
import io.strimzi.api.kafka.model.common.CertificateAuthorityBuilder;
import io.strimzi.api.kafka.model.common.CertificateManagerType;
import io.strimzi.api.kafka.model.kafka.Kafka;
import io.strimzi.api.kafka.model.kafka.KafkaBuilder;
import io.strimzi.api.kafka.model.kafka.KafkaResources;
import io.strimzi.api.kafka.model.kafka.listener.GenericKafkaListenerBuilder;
import io.strimzi.api.kafka.model.kafka.listener.KafkaListenerType;
import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.OpenSslCertIssuer;
import io.strimzi.certs.Subject;
import io.strimzi.operator.cluster.ResourceUtils;
import io.strimzi.operator.cluster.model.AbstractModel;
import io.strimzi.operator.cluster.model.CertSecretUtils;
import io.strimzi.operator.cluster.model.ModelUtils;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.Util;
import io.strimzi.operator.common.ca.Ca;
import io.strimzi.operator.common.ca.CaConfig;
import io.strimzi.operator.common.ca.CertManagerCa;
import io.strimzi.operator.common.ca.CertificateUtils;
import io.strimzi.operator.common.model.InvalidResourceException;
import io.strimzi.operator.common.model.Labels;
import io.strimzi.operator.common.model.PasswordGenerator;
import io.strimzi.operator.common.operator.MockCertIssuer;
import io.strimzi.operator.common.operator.resource.kubernetes.CertManagerCertificateOperator;
import io.strimzi.operator.common.operator.resource.kubernetes.SecretOperator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static io.strimzi.operator.common.ca.Ca.CA_CRT;
import static io.strimzi.operator.common.ca.Ca.CA_KEY;
import static io.strimzi.operator.common.ca.InternalCa.CA_STORE;
import static io.strimzi.operator.common.ca.InternalCa.CA_STORE_PASSWORD;
import static java.util.Collections.singleton;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CertManagerCaProviderTest {
    private static final String NAMESPACE = Reconciliation.DUMMY_RECONCILIATION.namespace();
    private static final String NAME = Reconciliation.DUMMY_RECONCILIATION.name();
    private static final Kafka KAFKA = new KafkaBuilder()
            .withNewMetadata()
            .withName(NAME)
            .withNamespace(NAMESPACE)
            .endMetadata()
            .withNewSpec()
            .withNewKafka()
            .withListeners(new GenericKafkaListenerBuilder()
                    .withName("plain")
                    .withPort(9092)
                    .withType(KafkaListenerType.INTERNAL)
                    .withTls(false)
                    .build())
            .endKafka()
            .endSpec()
            .build();

    private final static OpenSslCertIssuer CERT_ISSUER = new OpenSslCertIssuer();
    private final static PasswordGenerator PASSWORD_GENERATOR = new PasswordGenerator(12,
            "abcdefghijklmnopqrstuvwxyz" +
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "abcdefghijklmnopqrstuvwxyz" +
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "0123456789");

    private SecretOperator secretOperations;
    private CertManagerCertificateOperator certificateOperator;

    @BeforeEach
    public void setup() {
        secretOperations = mock(SecretOperator.class);
        certificateOperator = mock(CertManagerCertificateOperator.class);
    }

    private void reconcileCas(CertificateAuthority clusterCa, CertificateAuthority clientsCa, CaSecrets caSecrets, Secret clusterOperatorSecret) {
        Kafka kafka = new KafkaBuilder(KAFKA)
                .editSpec()
                .withClusterCa(clusterCa)
                .withClientsCa(clientsCa)
                .endSpec()
                .build();

        reconcileCas(kafka, caSecrets, clusterOperatorSecret);
    }

    private void reconcileCas(Kafka kafka, CaSecrets caSecrets, Secret clusterOperatorSecret) {
        CertManagerCaProvider clusterCaProvider = new CertManagerCaProvider(Reconciliation.DUMMY_RECONCILIATION,
                Ca.CaRole.CLUSTER_CA,
                new CaConfig(kafka.getSpec().getClusterCa(), false),
                kafka,
                caSecrets == null ? null : caSecrets.clusterCaCert,
                clusterOperatorSecret,
                certificateOperator,
                secretOperations
        );

        clusterCaProvider.createAndReconcileCa().toCompletableFuture().join();

        CertManagerCaProvider clientsCaProvider = new CertManagerCaProvider(Reconciliation.DUMMY_RECONCILIATION,
                Ca.CaRole.CLIENTS_CA,
                new CaConfig(kafka.getSpec().getClientsCa(), false),
                kafka,
                caSecrets == null ? null : caSecrets.clientsCaCert,
                clusterOperatorSecret,
                certificateOperator,
                secretOperations
        );

        clientsCaProvider.createAndReconcileCa().toCompletableFuture().join();
    }

    private CertAndKey generateCa(CertificateAuthority certificateAuthority, String commonName)
            throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        String clusterCaStorePassword = "123456";

        Path clusterCaKeyFile = Files.createTempFile("tls", "cluster-ca-key");
        clusterCaKeyFile.toFile().deleteOnExit();
        Path clusterCaCertFile = Files.createTempFile("tls", "cluster-ca-cert");
        clusterCaCertFile.toFile().deleteOnExit();
        Path clusterCaStoreFile = Files.createTempFile("tls", "cluster-ca-store");
        clusterCaStoreFile.toFile().deleteOnExit();

        Subject sbj = new Subject.Builder()
                .withOrganizationName("io.strimzi")
                .withCommonName(commonName).build();

        CERT_ISSUER.generateSelfSignedCert(clusterCaKeyFile.toFile(), clusterCaCertFile.toFile(), sbj, certificateAuthority.getValidityDays());

        CERT_ISSUER.addCertToTrustStore(clusterCaCertFile.toFile(), CA_CRT, clusterCaStoreFile.toFile(), clusterCaStorePassword);
        return new CertAndKey(
                Files.readAllBytes(clusterCaKeyFile),
                Files.readAllBytes(clusterCaCertFile),
                Files.readAllBytes(clusterCaStoreFile),
                null,
                clusterCaStorePassword);
    }

    private CertAndKey renewCaCert(CertAndKey certAndKey) throws IOException {
        Path caKeyFile = Files.createTempFile("tls", "cluster-ca-key");
        caKeyFile.toFile().deleteOnExit();
        Files.write(caKeyFile, certAndKey.key());
        Path caCertFile = Files.createTempFile("tls", "cluster-ca-cert");
        caCertFile.toFile().deleteOnExit();
        Files.write(caCertFile, certAndKey.cert());

        Subject sbj = new Subject.Builder()
                .withOrganizationName("io.strimzi")
                .withCommonName("cluster-ca").build();

        CERT_ISSUER.renewSelfSignedCert(caKeyFile.toFile(), caCertFile.toFile(), sbj, 10);

        return new CertAndKey(
                Files.readAllBytes(caKeyFile),
                Files.readAllBytes(caCertFile),
                null,
                null,
                null);
    }

    private CertAndKey generateClusterOperatorCert(CertAndKey ca) throws IOException {
        File csrFile = Files.createTempFile("tls", "csr").toFile();
        csrFile.deleteOnExit();
        File keyFile = Files.createTempFile("tls", "key").toFile();
        keyFile.deleteOnExit();
        File certFile = Files.createTempFile("tls", "cert").toFile();
        certFile.deleteOnExit();

        Subject sbj = new Subject.Builder()
                .withOrganizationName("io.strimzi")
                .withCommonName("cluster-operator").build();

        CERT_ISSUER.generateCsr(keyFile, csrFile, sbj);
        CERT_ISSUER.generateCert(csrFile, ca.key(), ca.cert(), certFile, sbj, 10);

        return new CertAndKey(
                Files.readAllBytes(keyFile.toPath()),
                Files.readAllBytes(certFile.toPath()),
                null,
                null,
                null);
    }

    private List<Secret> initialClusterCaSecrets(CertificateAuthority certificateAuthority)
            throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        return initialCaSecrets(certificateAuthority, "cluster-ca",
                AbstractModel.clusterCaKeySecretName(NAME),
                AbstractModel.clusterCaCertSecretName(NAME));
    }

    private List<Secret> initialClientsCaSecrets(CertificateAuthority certificateAuthority)
            throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        return initialCaSecrets(certificateAuthority, "clients-ca",
                KafkaResources.clientsCaKeySecretName(NAME),
                KafkaResources.clientsCaCertificateSecretName(NAME));
    }

    private List<Secret> initialCaSecrets(CertificateAuthority certificateAuthority, String commonName, String caKeySecretName, String caCertSecretName)
            throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        CertAndKey result = generateCa(certificateAuthority, commonName);
        Secret caKeySecret = ResourceUtils.createInitialCaKeySecret(NAMESPACE, NAME, caKeySecretName, result.keyAsBase64String());
        Secret caCertSecret = ResourceUtils.createInitialCaCertSecret(NAMESPACE, NAME, caCertSecretName,
                result.certAsBase64String(), result.trustStoreAsBase64String(), result.storePasswordAsBase64String());

        assertCertDataNotNull(caCertSecret.getData());
        assertThat(isCertInTrustStore(CA_CRT, caCertSecret.getData()), is(true));
        assertKeyDataNotNull(caKeySecret.getData());
        return List.of(caKeySecret, caCertSecret);
    }

    private KeyStore getTrustStore(Map<String, String> data)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(new ByteArrayInputStream(
                        Util.decodeBytesFromBase64(data.get(CA_STORE))),
                Util.decodeFromBase64(data.get(CA_STORE_PASSWORD)).toCharArray()
        );
        return trustStore;
    }

    private boolean isCertInTrustStore(String alias, Map<String, String> data)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore trustStore = getTrustStore(data);
        return trustStore.isCertificateEntry(alias);
    }

    private X509Certificate getCertificateFromTrustStore(String alias, Map<String, String> data)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore trustStore = getTrustStore(data);
        return (X509Certificate) trustStore.getCertificate(alias);
    }

    private void assertCaptorSecretsNotNull(CaSecrets secrets) {
        assertThat(secrets.clusterCaCert(), is(notNullValue()));
        assertThat(secrets.clientsCaCert(), is(notNullValue()));
    }

    private CaSecrets verifyCaSecretReconcileCalls(SecretOperator secretOps) {
        ArgumentCaptor<Secret> clusterCaCert = ArgumentCaptor.forClass(Secret.class);
        ArgumentCaptor<Secret> clientsCaCert = ArgumentCaptor.forClass(Secret.class);
        verify(secretOps).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaCertSecretName(NAME)), clusterCaCert.capture());
        verify(secretOps).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaCertificateSecretName(NAME)), clientsCaCert.capture());

        return new CaSecrets(clusterCaCert.getValue(), clientsCaCert.getValue());
    }

    private void assertCertDataNotNull(Map<String, String> certData) {
        assertThat(certData.keySet(), is(Set.of(CA_CRT, CA_STORE, CA_STORE_PASSWORD)));
        assertThat(certData.get(CA_CRT), is(notNullValue()));
        assertThat(certData.get(CA_STORE), is(notNullValue()));
        assertThat(certData.get(CA_STORE_PASSWORD), is(notNullValue()));
    }

    private void assertKeyDataNotNull(Map<String, String> keyData) {
        assertThat(keyData.keySet(), is(singleton(CA_KEY)));
        assertThat(keyData.get(CA_KEY), is(notNullValue()));
    }

    private record CaSecrets(
            Secret clusterCaCert,
            Secret clientsCaCert
    ) { }

    private static Secret createInitialClusterCaCertSecret(String caCert) throws CertificateException {
        String hash = CertSecretUtils.getCertificateThumbprint(CertificateUtils.x509Certificate(Util.decodeFromBase64(caCert).getBytes(StandardCharsets.UTF_8)));
        return new SecretBuilder()
                .withNewMetadata()
                    .withName(AbstractModel.clusterCaCertSecretName(NAME))
                    .withNamespace(NAMESPACE)
                    .addToAnnotations(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION, "0")
                    .addToAnnotations(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION, "0")
                    .addToAnnotations(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH, hash)
                .endMetadata()
                .addToData("ca.crt", caCert)
                .build();
    }

    private static Secret createInitialClientsCaCertSecret(String caCert) throws CertificateException {
        String hash = CertSecretUtils.getCertificateThumbprint(CertificateUtils.x509Certificate(Util.decodeFromBase64(caCert).getBytes(StandardCharsets.UTF_8)));
        return new SecretBuilder()
                .withNewMetadata()
                    .withName(KafkaResources.clientsCaCertificateSecretName(NAME))
                    .withNamespace(NAMESPACE)
                    .addToAnnotations(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION, "0")
                    .addToAnnotations(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH, hash)
                .endMetadata()
                .addToData("ca.crt", caCert)
                .build();
    }

    @ParameterizedTest
    @EnumSource(Ca.CaRole.class)
    public void throwsWhenCaCertSecretMissing(Ca.CaRole caRole) {
        String caCertSecretName = "cert-manager-ca-cert";
        CertificateAuthority ca = new CertificateAuthorityBuilder()
                .withValidityDays(100)
                .withRenewalDays(10)
                .withGenerateCertificateAuthority(false)
                .withType(CertificateManagerType.CERT_MANAGER_IO)
                .withNewCertManager()
                    .withNewCaCert()
                        .withSecretName(caCertSecretName)
                        .withCertificate(CA_CRT)
                    .endCaCert()
                .endCertManager()
                .build();

        Kafka kafkaCluster = switch (caRole) {
            case CLUSTER_CA -> new KafkaBuilder(KAFKA).editSpec().withClusterCa(ca).endSpec().build();
            case CLIENTS_CA -> new KafkaBuilder(KAFKA).editSpec().withClientsCa(ca).endSpec().build();
        };

        CertManagerCaProvider caProvider = new CertManagerCaProvider(Reconciliation.DUMMY_RECONCILIATION,
                caRole,
                new CaConfig(ca, false),
                kafkaCluster,
                null,
                null,
                certificateOperator,
                secretOperations
        );

        Exception exception = assertThrows(CompletionException.class, () -> caProvider.createAndReconcileCa().toCompletableFuture().join());
        assertThat(exception.getCause(), instanceOf(InvalidResourceException.class));
        assertThat(exception.getCause().getMessage(), is("CA public certificate Secret " + caCertSecretName + " missing."));
    }

    @ParameterizedTest
    @EnumSource(Ca.CaRole.class)
    public void throwsWhenCaCertSecretDataMissing(Ca.CaRole caRole) {
        String caCertSecretName = "cert-manager-ca-cert";
        String caCertSecretKey = "cm-ca.crt";
        CertificateAuthority ca = new CertificateAuthorityBuilder()
                .withValidityDays(100)
                .withRenewalDays(10)
                .withGenerateCertificateAuthority(false)
                .withType(CertificateManagerType.CERT_MANAGER_IO)
                .withNewCertManager()
                    .withNewCaCert()
                        .withSecretName(caCertSecretName)
                        .withCertificate(caCertSecretKey)
                    .endCaCert()
                .endCertManager()
                .build();

        Secret caCertSecret = ModelUtils.createSecret(caCertSecretName, NAMESPACE,  Labels.EMPTY, null, Map.of(), Map.of(), Map.of());
        when(secretOperations.getAsync(eq(NAMESPACE), eq(caCertSecretName))).thenReturn(CompletableFuture.completedFuture(caCertSecret));

        Kafka kafkaCluster = switch (caRole) {
            case CLUSTER_CA -> new KafkaBuilder(KAFKA).editSpec().withClusterCa(ca).endSpec().build();
            case CLIENTS_CA -> new KafkaBuilder(KAFKA).editSpec().withClientsCa(ca).endSpec().build();
        };

        CertManagerCaProvider caProvider = new CertManagerCaProvider(Reconciliation.DUMMY_RECONCILIATION,
                caRole,
                new CaConfig(ca, false),
                kafkaCluster,
                null,
                null,
                certificateOperator,
                secretOperations
        );

        Exception exception = assertThrows(CompletionException.class, () -> caProvider.createAndReconcileCa().toCompletableFuture().join());
        assertThat(exception.getCause(), instanceOf(InvalidResourceException.class));
        assertThat(exception.getCause().getMessage(), is("CA public certificate Secret " + caCertSecretName + " missing key " + caCertSecretKey));
    }

    @Test
    public void createsClusterCaSecretInitially() throws CertificateException {
        String caCertSecretName = "cert-manager-ca-cert";
        CertificateAuthority ca = new CertificateAuthorityBuilder()
                .withValidityDays(100)
                .withRenewalDays(10)
                .withGenerateCertificateAuthority(false)
                .withType(CertificateManagerType.CERT_MANAGER_IO)
                .withNewCertManager()
                    .withNewCaCert()
                        .withSecretName(caCertSecretName)
                        .withCertificate(CA_CRT)
                    .endCaCert()
                .endCertManager()
                .build();

        Map<String, String> caCertData = Map.of(CA_CRT, MockCertIssuer.clusterCaCert());

        Secret userCaCertSecret = ModelUtils.createSecret(caCertSecretName, NAMESPACE,  Labels.EMPTY, null, caCertData, Map.of(), Map.of());
        when(secretOperations.getAsync(eq(NAMESPACE), eq(caCertSecretName))).thenReturn(CompletableFuture.completedFuture(userCaCertSecret));

        CertManagerCaProvider caProvider = new CertManagerCaProvider(Reconciliation.DUMMY_RECONCILIATION,
                Ca.CaRole.CLUSTER_CA,
                new CaConfig(ca, false),
                new KafkaBuilder(KAFKA).editSpec().withClusterCa(ca).endSpec().build(),
                null,
                null,
                certificateOperator,
                secretOperations
        );

        CaProviderResult result = caProvider.createAndReconcileCa().toCompletableFuture().join();

        // Verify result
        assertThat(result, notNullValue());

        assertThat(result.ca(), instanceOf(CertManagerCa.class));
        assertThat(result.ca().caCertData(), is(caCertData));
        assertThat(result.ca().caCertGeneration(), is(0));
        assertThat(result.ca().caKeyGeneration(), is(0));

        assertThat(result.certSecret(), notNullValue());
        assertThat(result.certSecret().getData(), is(caCertData));
        Map<String, String> secretAnnotations = result.certSecret().getMetadata().getAnnotations();
        assertThat(secretAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("0"));
        assertThat(secretAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), is("0"));
        String caCertHash = CertSecretUtils.getCertificateThumbprint(CertificateUtils.x509Certificate(Util.decodeBytesFromBase64(MockCertIssuer.clusterCaCert())));
        assertThat(secretAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(caCertHash));

        // Verify K8s calls
        ArgumentCaptor<Secret> caCertSecret = ArgumentCaptor.forClass(Secret.class);
        verify(secretOperations).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaCertSecretName(NAME)), caCertSecret.capture());
        verify(secretOperations, never()).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaKeySecretName(NAME)), any(Secret.class));

        assertThat(caCertSecret.getValue(), is(result.certSecret()));
    }

    @Test
    public void createsClientsCaSecretInitially() throws CertificateException {
        String caCertSecretName = "cert-manager-ca-cert";
        CertificateAuthority ca = new CertificateAuthorityBuilder()
                .withValidityDays(100)
                .withRenewalDays(10)
                .withGenerateCertificateAuthority(false)
                .withType(CertificateManagerType.CERT_MANAGER_IO)
                .withNewCertManager()
                    .withNewCaCert()
                        .withSecretName(caCertSecretName)
                        .withCertificate(CA_CRT)
                    .endCaCert()
                .endCertManager()
                .build();

        Map<String, String> caCertData = Map.of(CA_CRT, MockCertIssuer.clientsCaCert());

        Secret userCaCertSecret = ModelUtils.createSecret(caCertSecretName, NAMESPACE,  Labels.EMPTY, null, caCertData, Map.of(), Map.of());
        when(secretOperations.getAsync(eq(NAMESPACE), eq(caCertSecretName))).thenReturn(CompletableFuture.completedFuture(userCaCertSecret));

        CertManagerCaProvider caProvider = new CertManagerCaProvider(Reconciliation.DUMMY_RECONCILIATION,
                Ca.CaRole.CLIENTS_CA,
                new CaConfig(ca, false),
                new KafkaBuilder(KAFKA).editSpec().withClientsCa(ca).endSpec().build(),
                null,
                null,
                certificateOperator,
                secretOperations
        );

        CaProviderResult result = caProvider.createAndReconcileCa().toCompletableFuture().join();

        // Verify result
        assertThat(result, notNullValue());

        assertThat(result.ca(), instanceOf(CertManagerCa.class));
        assertThat(result.ca().caCertData(), is(caCertData));
        assertThat(result.ca().caCertGeneration(), is(0));
        assertThat(result.ca().caKeyGeneration(), is(0));

        assertThat(result.certSecret(), notNullValue());
        assertThat(result.certSecret().getData(), is(caCertData));
        Map<String, String> secretAnnotations = result.certSecret().getMetadata().getAnnotations();
        assertThat(secretAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("0"));
        // Clients Ca cert secret does not need key annotation
        assertThat(Annotations.hasAnnotation(result.certSecret(), Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), is(false));
        String caCertHash = CertSecretUtils.getCertificateThumbprint(CertificateUtils.x509Certificate(Util.decodeBytesFromBase64(MockCertIssuer.clientsCaCert())));
        assertThat(secretAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(caCertHash));

        // Verify K8s calls
        ArgumentCaptor<Secret> caCertSecret = ArgumentCaptor.forClass(Secret.class);
        verify(secretOperations).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaCertificateSecretName(NAME)), caCertSecret.capture());
        verify(secretOperations, never()).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaKeySecretName(NAME)), any(Secret.class));

        assertThat(caCertSecret.getValue(), is(result.certSecret()));
    }

    @Test
    public void noChangeToClusterCaSecret() throws CertificateException {
        String caCertSecretName = "cert-manager-ca-cert";
        CertificateAuthority ca = new CertificateAuthorityBuilder()
                .withValidityDays(100)
                .withRenewalDays(10)
                .withGenerateCertificateAuthority(false)
                .withType(CertificateManagerType.CERT_MANAGER_IO)
                .withNewCertManager()
                    .withNewCaCert()
                        .withSecretName(caCertSecretName)
                        .withCertificate(CA_CRT)
                    .endCaCert()
                .endCertManager()
                .build();

        Map<String, String> caCertData = Map.of(CA_CRT, MockCertIssuer.clusterCaCert());

        Secret userCaCertSecret = ModelUtils.createSecret(caCertSecretName, NAMESPACE,  Labels.EMPTY, null, caCertData, Map.of(), Map.of());
        when(secretOperations.getAsync(eq(NAMESPACE), eq(caCertSecretName))).thenReturn(CompletableFuture.completedFuture(userCaCertSecret));

        Secret existingCaCertSecret = createInitialClusterCaCertSecret(MockCertIssuer.clusterCaCert());
        Secret clusterOperatorSecret = ModelUtils.createSecret(KafkaResources.clusterOperatorCertsSecretName(NAME),
                NAMESPACE,
                Labels.EMPTY,
                null,
                Map.of("cluster-operator.crt", Util.encodeToBase64(MockCertIssuer.serverCert()),
                        "cluster-operator.key", Util.encodeToBase64(MockCertIssuer.serverKey())),
                Map.of(),
                Map.of());

        CertManagerCaProvider caProvider = new CertManagerCaProvider(Reconciliation.DUMMY_RECONCILIATION,
                Ca.CaRole.CLUSTER_CA,
                new CaConfig(ca, false),
                new KafkaBuilder(KAFKA).editSpec().withClusterCa(ca).endSpec().build(),
                existingCaCertSecret,
                clusterOperatorSecret,
                certificateOperator,
                secretOperations
        );

        CaProviderResult result = caProvider.createAndReconcileCa().toCompletableFuture().join();

        // Verify result
        assertThat(result, notNullValue());

        assertThat(result.ca(), instanceOf(CertManagerCa.class));
        assertThat(result.ca().caCertData(), is(caCertData));
        assertThat(result.ca().caCertGeneration(), is(0));
        assertThat(result.ca().caKeyGeneration(), is(0));

        assertThat(result.certSecret(), notNullValue());
        assertThat(result.certSecret().getData(), is(caCertData));
        Map<String, String> secretAnnotations = result.certSecret().getMetadata().getAnnotations();
        assertThat(secretAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("0"));
        assertThat(secretAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), is("0"));
        String caCertHash = CertSecretUtils.getCertificateThumbprint(CertificateUtils.x509Certificate(Util.decodeBytesFromBase64(MockCertIssuer.clusterCaCert())));
        assertThat(secretAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(caCertHash));

        // Verify K8s calls
        ArgumentCaptor<Secret> caCertSecret = ArgumentCaptor.forClass(Secret.class);
        verify(secretOperations).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaCertSecretName(NAME)), caCertSecret.capture());
        verify(secretOperations, never()).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaKeySecretName(NAME)), any(Secret.class));

        assertThat(caCertSecret.getValue(), is(result.certSecret()));
    }

    @Test
    public void noChangeToClientsCaSecret() throws CertificateException {
        String caCertSecretName = "cert-manager-ca-cert";
        CertificateAuthority ca = new CertificateAuthorityBuilder()
                .withValidityDays(100)
                .withRenewalDays(10)
                .withGenerateCertificateAuthority(false)
                .withType(CertificateManagerType.CERT_MANAGER_IO)
                .withNewCertManager()
                    .withNewCaCert()
                        .withSecretName(caCertSecretName)
                        .withCertificate(CA_CRT)
                    .endCaCert()
                .endCertManager()
                .build();

        Map<String, String> caCertData = Map.of(CA_CRT, MockCertIssuer.clientsCaCert());

        Secret userCaCertSecret = ModelUtils.createSecret(caCertSecretName, NAMESPACE,  Labels.EMPTY, null, caCertData, Map.of(), Map.of());
        when(secretOperations.getAsync(eq(NAMESPACE), eq(caCertSecretName))).thenReturn(CompletableFuture.completedFuture(userCaCertSecret));

        Secret existingCaCertSecret = createInitialClientsCaCertSecret(MockCertIssuer.clientsCaCert());
        Secret clusterOperatorSecret = ModelUtils.createSecret(KafkaResources.clusterOperatorCertsSecretName(NAME),
                NAMESPACE,
                Labels.EMPTY,
                null,
                Map.of("cluster-operator.crt", Util.encodeToBase64(MockCertIssuer.serverCert()),
                        "cluster-operator.key", Util.encodeToBase64(MockCertIssuer.serverKey())),
                Map.of(),
                Map.of());

        CertManagerCaProvider caProvider = new CertManagerCaProvider(Reconciliation.DUMMY_RECONCILIATION,
                Ca.CaRole.CLIENTS_CA,
                new CaConfig(ca, false),
                new KafkaBuilder(KAFKA).editSpec().withClientsCa(ca).endSpec().build(),
                existingCaCertSecret,
                clusterOperatorSecret,
                certificateOperator,
                secretOperations
        );

        CaProviderResult result = caProvider.createAndReconcileCa().toCompletableFuture().join();

        // Verify result
        assertThat(result, notNullValue());

        assertThat(result.ca(), instanceOf(CertManagerCa.class));
        assertThat(result.ca().caCertData(), is(caCertData));
        assertThat(result.ca().caCertGeneration(), is(0));
        assertThat(result.ca().caKeyGeneration(), is(0));

        assertThat(result.certSecret(), notNullValue());
        assertThat(result.certSecret().getData(), is(caCertData));
        Map<String, String> secretAnnotations = result.certSecret().getMetadata().getAnnotations();
        assertThat(secretAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("0"));
        // Clients Ca cert secret does not need key annotation
        assertThat(Annotations.hasAnnotation(result.certSecret(), Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), is(false));
        String caCertHash = CertSecretUtils.getCertificateThumbprint(CertificateUtils.x509Certificate(Util.decodeBytesFromBase64(MockCertIssuer.clientsCaCert())));
        assertThat(secretAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(caCertHash));

        // Verify K8s calls
        ArgumentCaptor<Secret> caCertSecret = ArgumentCaptor.forClass(Secret.class);
        verify(secretOperations).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaCertificateSecretName(NAME)), caCertSecret.capture());
        verify(secretOperations, never()).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaKeySecretName(NAME)), any(Secret.class));

        assertThat(caCertSecret.getValue(), is(result.certSecret()));
    }

    @Test
    public void clusterCaSecretRenewed() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        String caCertSecretName = "cert-manager-ca-cert";
        CertificateAuthority ca = new CertificateAuthorityBuilder()
                .withValidityDays(100)
                .withRenewalDays(10)
                .withGenerateCertificateAuthority(false)
                .withType(CertificateManagerType.CERT_MANAGER_IO)
                .withNewCertManager()
                    .withNewCaCert()
                        .withSecretName(caCertSecretName)
                        .withCertificate(CA_CRT)
                    .endCaCert()
                .endCertManager()
                .build();

        CertAndKey caCert = generateCa(ca, Ca.CaRole.CLUSTER_CA.caCommonName());
        CertAndKey renewedCaCert = renewCaCert(caCert);
        Map<String, String> caCertData = Map.of(CA_CRT, renewedCaCert.certAsBase64String());

        Secret userCaCertSecret = ModelUtils.createSecret(caCertSecretName, NAMESPACE,  Labels.EMPTY, null, caCertData, Map.of(), Map.of());
        when(secretOperations.getAsync(eq(NAMESPACE), eq(caCertSecretName))).thenReturn(CompletableFuture.completedFuture(userCaCertSecret));

        Secret existingCaCertSecret = createInitialClusterCaCertSecret(caCert.certAsBase64String());
        CertAndKey clusterOperatorCert = generateClusterOperatorCert(caCert);
        Secret clusterOperatorSecret = ModelUtils.createSecret(KafkaResources.clusterOperatorCertsSecretName(NAME),
                NAMESPACE,
                Labels.EMPTY,
                null,
                Map.of("cluster-operator.crt", clusterOperatorCert.certAsBase64String(),
                        "cluster-operator.key", clusterOperatorCert.keyAsBase64String()),
                Map.of(),
                Map.of());

        CertManagerCaProvider caProvider = new CertManagerCaProvider(Reconciliation.DUMMY_RECONCILIATION,
                Ca.CaRole.CLUSTER_CA,
                new CaConfig(ca, false),
                new KafkaBuilder(KAFKA).editSpec().withClusterCa(ca).endSpec().build(),
                existingCaCertSecret,
                clusterOperatorSecret,
                certificateOperator,
                secretOperations
        );

        CaProviderResult result = caProvider.createAndReconcileCa().toCompletableFuture().join();

        // Verify result
        assertThat(result, notNullValue());

        assertThat(result.ca(), instanceOf(CertManagerCa.class));
        assertThat(result.ca().caCertData(), is(caCertData));
        assertThat(result.ca().caCertGeneration(), is(1));
        assertThat(result.ca().caKeyGeneration(), is(0));

        assertThat(result.certSecret(), notNullValue());
        assertThat(result.certSecret().getData(), is(caCertData));
        Map<String, String> secretAnnotations = result.certSecret().getMetadata().getAnnotations();
        assertThat(secretAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("1"));
        assertThat(secretAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), is("0"));
        String caCertHash = CertSecretUtils.getCertificateThumbprint(CertificateUtils.x509Certificate(Util.decodeBytesFromBase64(caCertData.get(CA_CRT))));
        assertThat(secretAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(caCertHash));

        // Verify K8s calls
        ArgumentCaptor<Secret> caCertSecret = ArgumentCaptor.forClass(Secret.class);
        verify(secretOperations).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaCertSecretName(NAME)), caCertSecret.capture());
        verify(secretOperations, never()).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaKeySecretName(NAME)), any(Secret.class));

        assertThat(caCertSecret.getValue(), is(result.certSecret()));
    }

    @Test
    public void clientsCaSecretRenewed() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        String caCertSecretName = "cert-manager-ca-cert";
        CertificateAuthority ca = new CertificateAuthorityBuilder()
                .withValidityDays(100)
                .withRenewalDays(10)
                .withGenerateCertificateAuthority(false)
                .withType(CertificateManagerType.CERT_MANAGER_IO)
                .withNewCertManager()
                    .withNewCaCert()
                        .withSecretName(caCertSecretName)
                        .withCertificate(CA_CRT)
                    .endCaCert()
                .endCertManager()
                .build();

        CertAndKey caCert = generateCa(ca, Ca.CaRole.CLIENTS_CA.caCommonName());
        CertAndKey renewedCaCert = renewCaCert(caCert);
        Map<String, String> caCertData = Map.of(CA_CRT, renewedCaCert.certAsBase64String());

        Secret userCaCertSecret = ModelUtils.createSecret(caCertSecretName, NAMESPACE,  Labels.EMPTY, null, caCertData, Map.of(), Map.of());
        when(secretOperations.getAsync(eq(NAMESPACE), eq(caCertSecretName))).thenReturn(CompletableFuture.completedFuture(userCaCertSecret));

        Secret existingCaCertSecret = createInitialClientsCaCertSecret(caCert.certAsBase64String());
        Secret clusterOperatorSecret = ModelUtils.createSecret(KafkaResources.clusterOperatorCertsSecretName(NAME),
                NAMESPACE,
                Labels.EMPTY,
                null,
                Map.of("cluster-operator.crt", Util.encodeToBase64(MockCertIssuer.serverCert()),
                        "cluster-operator.key", Util.encodeToBase64(MockCertIssuer.serverKey())),
                Map.of(),
                Map.of());

        CertManagerCaProvider caProvider = new CertManagerCaProvider(Reconciliation.DUMMY_RECONCILIATION,
                Ca.CaRole.CLIENTS_CA,
                new CaConfig(ca, false),
                new KafkaBuilder(KAFKA).editSpec().withClientsCa(ca).endSpec().build(),
                existingCaCertSecret,
                clusterOperatorSecret,
                certificateOperator,
                secretOperations
        );

        CaProviderResult result = caProvider.createAndReconcileCa().toCompletableFuture().join();

        // Verify result
        assertThat(result, notNullValue());

        assertThat(result.ca(), instanceOf(CertManagerCa.class));
        assertThat(result.ca().caCertData(), is(caCertData));
        assertThat(result.ca().caCertGeneration(), is(1));
        assertThat(result.ca().caKeyGeneration(), is(0));

        assertThat(result.certSecret(), notNullValue());
        assertThat(result.certSecret().getData(), is(caCertData));
        Map<String, String> secretAnnotations = result.certSecret().getMetadata().getAnnotations();
        assertThat(secretAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("1"));
        // Clients Ca cert secret does not need key annotation
        assertThat(Annotations.hasAnnotation(result.certSecret(), Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), is(false));
        String caCertHash = CertSecretUtils.getCertificateThumbprint(CertificateUtils.x509Certificate(Util.decodeBytesFromBase64(caCertData.get(CA_CRT))));
        assertThat(secretAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(caCertHash));

        // Verify K8s calls
        ArgumentCaptor<Secret> caCertSecret = ArgumentCaptor.forClass(Secret.class);
        verify(secretOperations).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaCertificateSecretName(NAME)), caCertSecret.capture());
        verify(secretOperations, never()).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaKeySecretName(NAME)), any(Secret.class));

        assertThat(caCertSecret.getValue(), is(result.certSecret()));
    }

//
//    @Test
//    public void testReconcileCMCasNewCaKeyAndCert(VertxTestContext context) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
//        String clusterCaSecretName = "cert-manager-cluster-ca-cert";
//        String clientsCaSecretName = "cert-manager-clients-ca-cert";
//        CertificateAuthority clusterCa = new CertificateAuthorityBuilder()
//                .withValidityDays(100)
//                .withRenewalDays(10)
//                .withGenerateCertificateAuthority(false)
//                .withType(CertificateManagerType.CERT_MANAGER_IO)
//                .withNewCertManager()
//                .withNewCaCert()
//                .withSecretName(clusterCaSecretName)
//                .withCertificate(CA_CRT)
//                .endCaCert()
//                .endCertManager()
//                .build();
//
//        CertificateAuthority clientsCa = new CertificateAuthorityBuilder()
//                .withValidityDays(100)
//                .withRenewalDays(10)
//                .withGenerateCertificateAuthority(false)
//                .withType(CertificateManagerType.CERT_MANAGER_IO)
//                .withNewCertManager()
//                .withNewCaCert()
//                .withSecretName(clientsCaSecretName)
//                .withCertificate(CA_CRT)
//                .endCaCert()
//                .endCertManager()
//                .build();
//
//        CertAndKey initialClusterCa = generateCa(clusterCa, "ca");
//        CertAndKey renewedClusterCa = generateCa(clusterCa, "ca");
//        CertAndKey initialClientsCa = generateCa(clientsCa, "ca");
//        CertAndKey renewedClientsCa = generateCa(clientsCa, "ca");
//
//        Secret initialClusterCaCertSecret = ResourceUtils.createInitialCaCertSecretForCMCa(NAMESPACE, NAME, AbstractModel.clusterCaCertSecretName(NAME), initialClusterCa.certAsBase64String(), true);
//        Secret renewedClusterCaCertSecret = createSecret(clusterCaSecretName, Map.of(CA_CRT, renewedClusterCa.certAsBase64String()), Map.of());
//
//        Secret initialClientsCaCertSecret = ResourceUtils.createInitialCaCertSecretForCMCa(NAMESPACE, NAME, KafkaResources.clientsCaCertificateSecretName(NAME), initialClientsCa.certAsBase64String(), false);
//        Secret renewedClientsCaCertSecret = createSecret(clientsCaSecretName, Map.of(CA_CRT, renewedClientsCa.certAsBase64String()), Map.of());
//
//        CertAndKey clusterOperatorCertAndKey = generateClusterOperatorSignedCert(initialClusterCa, clusterCa.getValidityDays());
//        Secret clusterOperatorSecret = createSecret(KafkaResources.clusterOperatorCertsSecretName(NAME),
//                Map.of("cluster-operator.crt", clusterOperatorCertAndKey.certAsBase64String(),
//                        "cluster-operator.key", clusterOperatorCertAndKey.keyAsBase64String()),
//                Labels.forStrimziCluster(NAME).withStrimziKind(Kafka.RESOURCE_KIND).toMap());
//
//        secrets.add(initialClusterCaCertSecret);
//        secrets.add(renewedClusterCaCertSecret);
//        secrets.add(initialClientsCaCertSecret);
//        secrets.add(renewedClientsCaCertSecret);
//        secrets.add(clusterOperatorSecret);
//
//        Checkpoint async = context.checkpoint();
//        reconcileCas(clusterCa, clientsCa)
//                .onComplete(context.succeeding(v -> context.verify(() -> {
//                    ArgumentCaptor<Secret> clusterCaCert = ArgumentCaptor.forClass(Secret.class);
//                    ArgumentCaptor<Secret> clientsCaCert = ArgumentCaptor.forClass(Secret.class);
//                    verify(supplier.secretOperations).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaCertSecretName(NAME)), clusterCaCert.capture());
//                    verify(supplier.secretOperations, times(0)).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaKeySecretName(NAME)), any(Secret.class));
//                    verify(supplier.secretOperations).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaCertificateSecretName(NAME)), clientsCaCert.capture());
//                    verify(supplier.secretOperations, times(0)).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaKeySecretName(NAME)), any(Secret.class));
//
//                    assertThat(clusterCaCert.getValue(), is(notNullValue()));
//                    Map<String, String> clusterCaAnnotations = clusterCaCert.getValue().getMetadata().getAnnotations();
//                    assertThat(clusterCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("1"));
//                    assertThat(clusterCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), is("1"));
//                    assertThat(clusterCaAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(CertUtils.getCertificateThumbprint(CaUtils.x509Certificate(renewedClusterCa.cert()))));
//                    Map<String, String> clusterCaCertData = clusterCaCert.getValue().getData();
//                    assertThat(clusterCaCertData, is(aMapWithSize(2)));
//                    assertThat(clusterCaCert.getValue().getData().get(CA_CRT), is(renewedClusterCaCertSecret.getData().get(CA_CRT)));
//                    clusterCaCertData.remove(CA_CRT);
//                    Pattern oldCaCertKeyPattern = Pattern.compile("ca-[0-9]+-[0-9]+-[0-9]+T[0-9]+-[0-9]+-[0-9]+Z\\.crt");
//                    String oldCaCertKey = clusterCaCertData.keySet().stream().findFirst().orElse("");
//                    assertThat(oldCaCertKeyPattern.matcher(oldCaCertKey).matches(), is(true));
//                    assertThat(clusterCaCertData.get(oldCaCertKey), is(initialClusterCaCertSecret.getData().get(CA_CRT)));
//
//                    assertThat(clientsCaCert.getValue(), is(notNullValue()));
//                    Map<String, String> clientsCaAnnotations = clientsCaCert.getValue().getMetadata().getAnnotations();
//                    assertThat(clientsCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("1"));
//                    assertThat(clientsCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), nullValue());
//                    assertThat(clientsCaAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(CertUtils.getCertificateThumbprint(CaUtils.x509Certificate(renewedClientsCa.cert()))));
//                    assertThat(clientsCaCert.getValue().getData().get(CA_CRT), is(renewedClientsCaCertSecret.getData().get(CA_CRT)));
//
//                    async.flag();
//                })));
//    }
//
//    @Test
//    public void testReconcileCMCasNewCaCertMissingClusterOperatorSecret(VertxTestContext context) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
//        String clusterCaSecretName = "cert-manager-cluster-ca-cert";
//        String clientsCaSecretName = "cert-manager-clients-ca-cert";
//        CertificateAuthority clusterCa = new CertificateAuthorityBuilder()
//                .withValidityDays(100)
//                .withRenewalDays(10)
//                .withGenerateCertificateAuthority(false)
//                .withType(CertificateManagerType.CERT_MANAGER_IO)
//                .withNewCertManager()
//                .withNewCaCert()
//                .withSecretName(clusterCaSecretName)
//                .withCertificate(CA_CRT)
//                .endCaCert()
//                .endCertManager()
//                .build();
//
//        CertificateAuthority clientsCa = new CertificateAuthorityBuilder()
//                .withValidityDays(100)
//                .withRenewalDays(10)
//                .withGenerateCertificateAuthority(false)
//                .withType(CertificateManagerType.CERT_MANAGER_IO)
//                .withNewCertManager()
//                .withNewCaCert()
//                .withSecretName(clientsCaSecretName)
//                .withCertificate(CA_CRT)
//                .endCaCert()
//                .endCertManager()
//                .build();
//
//        CertAndKey initialClusterCa = generateCa(clusterCa, "ca");
//        CertAndKey renewedClusterCa = renewCaCert(initialClusterCa, clusterCa.getValidityDays());
//        CertAndKey initialClientsCa = generateCa(clientsCa, "ca");
//        CertAndKey renewedClientsCa = renewCaCert(initialClientsCa, clientsCa.getValidityDays());
//
//        Secret initialClusterCaCertSecret = ResourceUtils.createInitialCaCertSecretForCMCa(NAMESPACE, NAME, AbstractModel.clusterCaCertSecretName(NAME), initialClusterCa.certAsBase64String(), true);
//        Secret renewedClusterCaCertSecret = createSecret(clusterCaSecretName, Map.of(CA_CRT, renewedClusterCa.certAsBase64String()), Map.of());
//
//        Secret initialClientsCaCertSecret = ResourceUtils.createInitialCaCertSecretForCMCa(NAMESPACE, NAME, KafkaResources.clientsCaCertificateSecretName(NAME), initialClientsCa.certAsBase64String(), false);
//        Secret renewedClientsCaCertSecret = createSecret(clientsCaSecretName, Map.of(CA_CRT, renewedClientsCa.certAsBase64String()), Map.of());
//
//        secrets.add(initialClusterCaCertSecret);
//        secrets.add(renewedClusterCaCertSecret);
//        secrets.add(initialClientsCaCertSecret);
//        secrets.add(renewedClientsCaCertSecret);
//
//        Checkpoint async = context.checkpoint();
//        reconcileCas(clusterCa, clientsCa)
//                .onComplete(context.succeeding(v -> context.verify(() -> {
//                    ArgumentCaptor<Secret> clusterCaCert = ArgumentCaptor.forClass(Secret.class);
//                    ArgumentCaptor<Secret> clientsCaCert = ArgumentCaptor.forClass(Secret.class);
//                    verify(supplier.secretOperations).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaCertSecretName(NAME)), clusterCaCert.capture());
//                    verify(supplier.secretOperations, times(0)).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaKeySecretName(NAME)), any(Secret.class));
//                    verify(supplier.secretOperations).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaCertificateSecretName(NAME)), clientsCaCert.capture());
//                    verify(supplier.secretOperations, times(0)).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaKeySecretName(NAME)), any(Secret.class));
//
//                    // Since cluster operator Secret is missing we can't perform path validation, so cluster CA is not updated
//                    assertThat(clusterCaCert.getValue(), is(notNullValue()));
//                    Map<String, String> clusterCaAnnotations = clusterCaCert.getValue().getMetadata().getAnnotations();
//                    assertThat(clusterCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("0"));
//                    assertThat(clusterCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), is("0"));
//                    assertThat(clusterCaAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(CertUtils.getCertificateThumbprint(CaUtils.x509Certificate(initialClusterCa.cert()))));
//                    assertThat(clusterCaCert.getValue().getData().get(CA_CRT), is(initialClusterCaCertSecret.getData().get(CA_CRT)));
//
//                    assertThat(clientsCaCert.getValue(), is(notNullValue()));
//                    Map<String, String> clientsCaAnnotations = clientsCaCert.getValue().getMetadata().getAnnotations();
//                    assertThat(clientsCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("1"));
//                    assertThat(clientsCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), nullValue());
//                    assertThat(clientsCaAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(CertUtils.getCertificateThumbprint(CaUtils.x509Certificate(renewedClientsCa.cert()))));
//                    assertThat(clientsCaCert.getValue().getData().get(CA_CRT), is(renewedClientsCaCertSecret.getData().get(CA_CRT)));
//
//                    async.flag();
//                })));
//    }
//
//    @Test
//    public void testReconcileCMCasNewCaKeyAndCertMissingClusterOperatorSecret(VertxTestContext context) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
//        String clusterCaSecretName = "cert-manager-cluster-ca-cert";
//        String clientsCaSecretName = "cert-manager-clients-ca-cert";
//        CertificateAuthority clusterCa = new CertificateAuthorityBuilder()
//                .withValidityDays(100)
//                .withRenewalDays(10)
//                .withGenerateCertificateAuthority(false)
//                .withType(CertificateManagerType.CERT_MANAGER_IO)
//                .withNewCertManager()
//                .withNewCaCert()
//                .withSecretName(clusterCaSecretName)
//                .withCertificate(CA_CRT)
//                .endCaCert()
//                .endCertManager()
//                .build();
//
//        CertificateAuthority clientsCa = new CertificateAuthorityBuilder()
//                .withValidityDays(100)
//                .withRenewalDays(10)
//                .withGenerateCertificateAuthority(false)
//                .withType(CertificateManagerType.CERT_MANAGER_IO)
//                .withNewCertManager()
//                .withNewCaCert()
//                .withSecretName(clientsCaSecretName)
//                .withCertificate(CA_CRT)
//                .endCaCert()
//                .endCertManager()
//                .build();
//
//        CertAndKey initialClusterCa = generateCa(clusterCa, "ca");
//        CertAndKey renewedClusterCa = generateCa(clusterCa, "ca");
//        CertAndKey initialClientsCa = generateCa(clientsCa, "ca");
//        CertAndKey renewedClientsCa = generateCa(clientsCa, "ca");
//
//        Secret initialClusterCaCertSecret = ResourceUtils.createInitialCaCertSecretForCMCa(NAMESPACE, NAME, AbstractModel.clusterCaCertSecretName(NAME), initialClusterCa.certAsBase64String(), true);
//        Secret renewedClusterCaCertSecret = createSecret(clusterCaSecretName, Map.of(CA_CRT, renewedClusterCa.certAsBase64String()), Map.of());
//
//        Secret initialClientsCaCertSecret = ResourceUtils.createInitialCaCertSecretForCMCa(NAMESPACE, NAME, KafkaResources.clientsCaCertificateSecretName(NAME), initialClientsCa.certAsBase64String(), false);
//        Secret renewedClientsCaCertSecret = createSecret(clientsCaSecretName, Map.of(CA_CRT, renewedClientsCa.certAsBase64String()), Map.of());
//
//        secrets.add(initialClusterCaCertSecret);
//        secrets.add(renewedClusterCaCertSecret);
//        secrets.add(initialClientsCaCertSecret);
//        secrets.add(renewedClientsCaCertSecret);
//
//        Checkpoint async = context.checkpoint();
//        reconcileCas(clusterCa, clientsCa)
//                .onComplete(context.succeeding(v -> context.verify(() -> {
//                    ArgumentCaptor<Secret> clusterCaCert = ArgumentCaptor.forClass(Secret.class);
//                    ArgumentCaptor<Secret> clientsCaCert = ArgumentCaptor.forClass(Secret.class);
//                    verify(supplier.secretOperations).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaCertSecretName(NAME)), clusterCaCert.capture());
//                    verify(supplier.secretOperations, times(0)).reconcile(any(), eq(NAMESPACE), eq(AbstractModel.clusterCaKeySecretName(NAME)), any(Secret.class));
//                    verify(supplier.secretOperations).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaCertificateSecretName(NAME)), clientsCaCert.capture());
//                    verify(supplier.secretOperations, times(0)).reconcile(any(), eq(NAMESPACE), eq(KafkaResources.clientsCaKeySecretName(NAME)), any(Secret.class));
//
//                    // Since cluster operator Secret is missing we can't perform path validation, so cluster CA is not updated
//                    assertThat(clusterCaCert.getValue(), is(notNullValue()));
//                    Map<String, String> clusterCaAnnotations = clusterCaCert.getValue().getMetadata().getAnnotations();
//                    assertThat(clusterCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("0"));
//                    assertThat(clusterCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), is("0"));
//                    assertThat(clusterCaAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(CertUtils.getCertificateThumbprint(CaUtils.x509Certificate(initialClusterCa.cert()))));
//                    assertThat(clusterCaCert.getValue().getData().get(CA_CRT), is(initialClusterCaCertSecret.getData().get(CA_CRT)));
//
//                    assertThat(clientsCaCert.getValue(), is(notNullValue()));
//                    Map<String, String> clientsCaAnnotations = clientsCaCert.getValue().getMetadata().getAnnotations();
//                    assertThat(clientsCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("1"));
//                    assertThat(clientsCaAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), nullValue());
//                    assertThat(clientsCaAnnotations.get(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(CertUtils.getCertificateThumbprint(CaUtils.x509Certificate(renewedClientsCa.cert()))));
//                    assertThat(clientsCaCert.getValue().getData().get(CA_CRT), is(renewedClientsCaCertSecret.getData().get(CA_CRT)));
//
//                    async.flag();
//                })));
//    }
}
