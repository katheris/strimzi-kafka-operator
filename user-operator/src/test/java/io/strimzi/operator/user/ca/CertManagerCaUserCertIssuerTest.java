/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.user.ca;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.strimzi.api.kafka.model.common.certmanager.IssuerKind;
import io.strimzi.api.kafka.model.common.certmanager.IssuerRef;
import io.strimzi.api.kafka.model.common.certmanager.IssuerRefBuilder;
import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.CertIssuer;
import io.strimzi.certs.OpenSslCertIssuer;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.Util;
import io.strimzi.operator.common.ca.CertificateUtils;
import io.strimzi.operator.common.model.Labels;
import io.strimzi.operator.common.operator.MockCertIssuer;
import io.strimzi.operator.common.operator.resource.kubernetes.CertManagerCertificateOperator;
import io.strimzi.operator.common.operator.resource.kubernetes.SecretOperator;
import io.strimzi.operator.user.ResourceUtils;
import io.strimzi.operator.user.model.InvalidCertificateException;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CertManagerCaUserCertIssuerTest {
    private static final String CERT_MANAGER_SECRET_NAME = ResourceUtils.NAME + "-cm";

    private final Secret clientsCaCert = ResourceUtils.createClientsCaCertSecret(ResourceUtils.NAMESPACE);
    private final IssuerRef issuerRef = new IssuerRefBuilder()
            .withName("test-issuer")
            .withKind(IssuerKind.CLUSTER_ISSUER)
            .withGroup("cert-manager.io")
            .build();

    private CertAndKey generateCert(CertAndKey ca) throws IOException {
        File csrFile = Files.createTempFile("tls", "csr").toFile();
        csrFile.deleteOnExit();
        File keyFile = Files.createTempFile("tls", "key").toFile();
        keyFile.deleteOnExit();
        File certFile = Files.createTempFile("tls", "cert").toFile();
        certFile.deleteOnExit();

        CertIssuer certIssuer = new OpenSslCertIssuer();
        Subject subject = CertificateUtils.getSubject(ResourceUtils.NAME, null);
        certIssuer.generateCsr(keyFile, csrFile, subject);
        certIssuer.generateCert(csrFile, ca.key(), ca.cert(), certFile, subject, 10);

        return new CertAndKey(
                Files.readAllBytes(keyFile.toPath()),
                Files.readAllBytes(certFile.toPath()),
                null,
                null,
                null);
    }

    @Test
    public void testNewUser() {
        CertManagerCertificateOperator certManagerOp = mock(CertManagerCertificateOperator.class);
        when(certManagerOp.reconcile(any(), any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));
        when(certManagerOp.waitForReady(any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));

        SecretOperator secretOp = mock(SecretOperator.class);
        when(secretOp.getAsync(eq(ResourceUtils.NAMESPACE), eq(CERT_MANAGER_SECRET_NAME))).thenReturn(CompletableFuture.completedStage(
                new SecretBuilder()
                        .withNewMetadata()
                            .withName(CERT_MANAGER_SECRET_NAME)
                            .withNamespace(ResourceUtils.NAMESPACE)
                        .endMetadata()
                        .withData(Map.of("tls.crt", Util.encodeToBase64(MockCertIssuer.serverCert()), "tls.key", Util.encodeToBase64(MockCertIssuer.serverKey())))
                        .build()));

        Secret userSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .withData(Map.of())
                .build();

        CertManagerCaUserCertIssuer issuer = new CertManagerCaUserCertIssuer(certManagerOp, secretOp, issuerRef);
        UserCertResult result = issuer.maybeCopyOrGenerateCert(
                Reconciliation.DUMMY_RECONCILIATION, clientsCaCert, null,
                userSecret, ResourceUtils.NAME, 365, 30, true, Labels.EMPTY, null)
                .toCompletableFuture().join();

        assertThat(result.caCertBase64(), is(MockCertIssuer.clientsCaCert()));
        assertThat(result.userCertAndKey().cert(), is(MockCertIssuer.serverCert().getBytes(StandardCharsets.UTF_8)));
        assertThat(result.userCertAndKey().key(), is(MockCertIssuer.serverKey().getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testExistingUserWithMissingKey() {
        CertManagerCertificateOperator certManagerOp = mock(CertManagerCertificateOperator.class);
        when(certManagerOp.reconcile(any(), any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));
        when(certManagerOp.waitForReady(any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));

        SecretOperator secretOp = mock(SecretOperator.class);
        when(secretOp.getAsync(eq(ResourceUtils.NAMESPACE), eq(CERT_MANAGER_SECRET_NAME))).thenReturn(CompletableFuture.completedStage(
                new SecretBuilder()
                        .withNewMetadata().withName(CERT_MANAGER_SECRET_NAME).withNamespace(ResourceUtils.NAMESPACE).endMetadata()
                        .withData(Map.of("tls.crt", Util.encodeToBase64(MockCertIssuer.serverCert()), "tls.key", Util.encodeToBase64(MockCertIssuer.serverKey())))
                        .build()));

        Secret userSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .withData(Map.of("user.crt", Util.encodeToBase64(MockCertIssuer.serverCert())))
                .build();

        CertManagerCaUserCertIssuer issuer = new CertManagerCaUserCertIssuer(certManagerOp, secretOp, issuerRef);
        UserCertResult result = issuer.maybeCopyOrGenerateCert(
                Reconciliation.DUMMY_RECONCILIATION, clientsCaCert, null,
                userSecret, ResourceUtils.NAME, 365, 30, true, Labels.EMPTY, null)
                .toCompletableFuture().join();

        assertThat(result.caCertBase64(), is(MockCertIssuer.clientsCaCert()));
        assertThat(result.userCertAndKey().cert(), is(MockCertIssuer.serverCert().getBytes(StandardCharsets.UTF_8)));
        assertThat(result.userCertAndKey().key(), is(MockCertIssuer.serverKey().getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testExistingUserWithMissingCert() {
        CertManagerCertificateOperator certManagerOp = mock(CertManagerCertificateOperator.class);
        when(certManagerOp.reconcile(any(), any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));
        when(certManagerOp.waitForReady(any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));

        SecretOperator secretOp = mock(SecretOperator.class);
        when(secretOp.getAsync(eq(ResourceUtils.NAMESPACE), eq(CERT_MANAGER_SECRET_NAME))).thenReturn(CompletableFuture.completedStage(
                new SecretBuilder()
                        .withNewMetadata().withName(CERT_MANAGER_SECRET_NAME).withNamespace(ResourceUtils.NAMESPACE).endMetadata()
                        .withData(Map.of("tls.crt", Util.encodeToBase64(MockCertIssuer.serverCert()), "tls.key", Util.encodeToBase64(MockCertIssuer.serverKey())))
                        .build()));

        Secret userSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .withData(Map.of("user.key", Util.encodeToBase64(MockCertIssuer.serverKey())))
                .build();

        CertManagerCaUserCertIssuer issuer = new CertManagerCaUserCertIssuer(certManagerOp, secretOp, issuerRef);
        UserCertResult result = issuer.maybeCopyOrGenerateCert(
                Reconciliation.DUMMY_RECONCILIATION, clientsCaCert, null,
                userSecret, ResourceUtils.NAME, 365, 30, true, Labels.EMPTY, null)
                .toCompletableFuture().join();

        assertThat(result.caCertBase64(), is(MockCertIssuer.clientsCaCert()));
        assertThat(result.userCertAndKey().cert(), is(MockCertIssuer.serverCert().getBytes(StandardCharsets.UTF_8)));
        assertThat(result.userCertAndKey().key(), is(MockCertIssuer.serverKey().getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testExistingUserWithCompleteSecret() {
        CertManagerCertificateOperator certManagerOp = mock(CertManagerCertificateOperator.class);
        when(certManagerOp.reconcile(any(), any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));
        when(certManagerOp.waitForReady(any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));

        SecretOperator secretOp = mock(SecretOperator.class);
        when(secretOp.getAsync(eq(ResourceUtils.NAMESPACE), eq(CERT_MANAGER_SECRET_NAME))).thenReturn(CompletableFuture.completedStage(
                new SecretBuilder()
                        .withNewMetadata().withName(CERT_MANAGER_SECRET_NAME).withNamespace(ResourceUtils.NAMESPACE).endMetadata()
                        .withData(Map.of("tls.crt", Util.encodeToBase64(MockCertIssuer.serverCert()), "tls.key", Util.encodeToBase64(MockCertIssuer.serverKey())))
                        .build()));

        Secret userSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .withData(Map.of("user.crt", Util.encodeToBase64(MockCertIssuer.serverCert()),
                        "user.key", Util.encodeToBase64(MockCertIssuer.serverKey())))
                .build();

        CertManagerCaUserCertIssuer issuer = new CertManagerCaUserCertIssuer(certManagerOp, secretOp, issuerRef);
        UserCertResult result = issuer.maybeCopyOrGenerateCert(
                Reconciliation.DUMMY_RECONCILIATION, clientsCaCert, null,
                userSecret, ResourceUtils.NAME, 365, 30, true, Labels.EMPTY, null)
                .toCompletableFuture().join();

        assertThat(result.caCertBase64(), is(MockCertIssuer.clientsCaCert()));
        assertThat(result.userCertAndKey().cert(), is(MockCertIssuer.serverCert().getBytes(StandardCharsets.UTF_8)));
        assertThat(result.userCertAndKey().key(), is(MockCertIssuer.serverKey().getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testExistingUserWithUpdatedCert() throws IOException {
        Secret clientsCaCertSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.CA_CERT_NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .addToData("ca.crt", MockCertIssuer.clusterCaCert()) // User clusterCA here since that is what issues the MockCertIssuer server cert
                .build();

        CertManagerCertificateOperator certManagerOp = mock(CertManagerCertificateOperator.class);
        when(certManagerOp.reconcile(any(), any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));
        when(certManagerOp.waitForReady(any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));

        SecretOperator secretOp = mock(SecretOperator.class);
        when(secretOp.getAsync(eq(ResourceUtils.NAMESPACE), eq(CERT_MANAGER_SECRET_NAME))).thenReturn(CompletableFuture.completedStage(
                new SecretBuilder()
                        .withNewMetadata().withName(CERT_MANAGER_SECRET_NAME).withNamespace(ResourceUtils.NAMESPACE).endMetadata()
                        .withData(Map.of("tls.crt", Util.encodeToBase64(MockCertIssuer.serverCert()), "tls.key", Util.encodeToBase64(MockCertIssuer.serverKey())))
                        .build()));

        CertAndKey existingCertAndKey = generateCert(new CertAndKey(Util.decodeBytesFromBase64(MockCertIssuer.clusterCaKey()), Util.decodeBytesFromBase64(MockCertIssuer.clusterCaCert()), 0));
        Secret userSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .withData(Map.of("user.crt", existingCertAndKey.certAsBase64String(),
                        "user.key", existingCertAndKey.keyAsBase64String()))
                .build();

        CertManagerCaUserCertIssuer issuer = new CertManagerCaUserCertIssuer(certManagerOp, secretOp, issuerRef);
        UserCertResult result = issuer.maybeCopyOrGenerateCert(
                Reconciliation.DUMMY_RECONCILIATION, clientsCaCertSecret, null,
                userSecret, ResourceUtils.NAME, 365, 30, true, Labels.EMPTY, null)
                .toCompletableFuture().join();

        // The new cert should replace the existing one since it's trusted by the CA
        assertThat(result.userCertAndKey().cert(), is(MockCertIssuer.serverCert().getBytes(StandardCharsets.UTF_8)));
        assertThat(result.userCertAndKey().key(), is(MockCertIssuer.serverKey().getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testExistingUserWithUpdatedCertFromDifferentCa() throws IOException {
        CertManagerCertificateOperator certManagerOp = mock(CertManagerCertificateOperator.class);
        when(certManagerOp.reconcile(any(), any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));
        when(certManagerOp.waitForReady(any(), any(), any())).thenReturn(CompletableFuture.completedStage(null));

        // Cert-manager returns a cert signed by a different CA — not trusted by the clients CA
        SecretOperator secretOp = mock(SecretOperator.class);
        when(secretOp.getAsync(eq(ResourceUtils.NAMESPACE), eq(CERT_MANAGER_SECRET_NAME))).thenReturn(CompletableFuture.completedStage(
                new SecretBuilder()
                        .withNewMetadata().withName(CERT_MANAGER_SECRET_NAME).withNamespace(ResourceUtils.NAMESPACE).endMetadata()
                        .withData(Map.of("tls.crt", Util.encodeToBase64(MockCertIssuer.serverCert()), "tls.key", Util.encodeToBase64(MockCertIssuer.serverKey())))
                        .build()));

        CertAndKey existingCertAndKey = generateCert(new CertAndKey(Util.decodeBytesFromBase64(MockCertIssuer.clientsCaKey()), Util.decodeBytesFromBase64(MockCertIssuer.clientsCaCert()), 0));
        Secret userSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .withData(Map.of("user.crt", existingCertAndKey.certAsBase64String(),
                        "user.key", existingCertAndKey.keyAsBase64String()))
                .build();

        CertManagerCaUserCertIssuer issuer = new CertManagerCaUserCertIssuer(certManagerOp, secretOp, issuerRef);
        UserCertResult result = issuer.maybeCopyOrGenerateCert(
                Reconciliation.DUMMY_RECONCILIATION, clientsCaCert, null,
                userSecret, ResourceUtils.NAME, 365, 30, true, Labels.EMPTY, null)
                .toCompletableFuture().join();

        // The existing cert should be kept since the new cert is not trusted by the current CA
        assertThat(result.userCertAndKey().cert(), is(existingCertAndKey.cert()));
        assertThat(result.userCertAndKey().key(), is(existingCertAndKey.key()));
    }

    @Test
    public void testMissingCaCertSecretThrowsException() {
        CertManagerCertificateOperator certManagerOp = mock(CertManagerCertificateOperator.class);
        SecretOperator secretOp = mock(SecretOperator.class);

        Secret userSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .withData(Map.of())
                .build();

        CertManagerCaUserCertIssuer issuer = new CertManagerCaUserCertIssuer(certManagerOp, secretOp, issuerRef);
        assertThrows(InvalidCertificateException.class, () -> issuer.maybeCopyOrGenerateCert(
                Reconciliation.DUMMY_RECONCILIATION, null, null,
                userSecret, ResourceUtils.NAME, 365, 30, true, Labels.EMPTY, null)
                .toCompletableFuture().join());
    }

    @Test
    public void testCaCertSecretWithMissingDataThrowsException() {
        CertManagerCertificateOperator certManagerOp = mock(CertManagerCertificateOperator.class);
        SecretOperator secretOp = mock(SecretOperator.class);

        Secret emptyCaCertSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.CA_CERT_NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .build();

        Secret userSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .withData(Map.of())
                .build();

        CertManagerCaUserCertIssuer issuer = new CertManagerCaUserCertIssuer(certManagerOp, secretOp, issuerRef);
        assertThrows(InvalidCertificateException.class, () -> issuer.maybeCopyOrGenerateCert(
                Reconciliation.DUMMY_RECONCILIATION, emptyCaCertSecret, null,
                userSecret, ResourceUtils.NAME, 365, 30, true, Labels.EMPTY, null)
                .toCompletableFuture().join());
    }

    @Test
    public void testCaCertSecretMissingCaCrtKeyThrowsException() {
        CertManagerCertificateOperator certManagerOp = mock(CertManagerCertificateOperator.class);
        SecretOperator secretOp = mock(SecretOperator.class);

        Secret caCertSecretWithoutCaCrt = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.CA_CERT_NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .addToData("some-other-key", "some-value")
                .build();

        Secret userSecret = new SecretBuilder()
                .withNewMetadata()
                    .withName(ResourceUtils.NAME)
                    .withNamespace(ResourceUtils.NAMESPACE)
                .endMetadata()
                .withData(Map.of())
                .build();

        CertManagerCaUserCertIssuer issuer = new CertManagerCaUserCertIssuer(certManagerOp, secretOp, issuerRef);
        assertThrows(InvalidCertificateException.class, () -> issuer.maybeCopyOrGenerateCert(
                Reconciliation.DUMMY_RECONCILIATION, caCertSecretWithoutCaCrt, null,
                userSecret, ResourceUtils.NAME, 365, 30, true, Labels.EMPTY, null)
                .toCompletableFuture().join());
    }
}
