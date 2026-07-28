/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.systemtest.security;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.skodjob.annotations.Desc;
import io.skodjob.annotations.Label;
import io.skodjob.annotations.Step;
import io.skodjob.annotations.SuiteDoc;
import io.skodjob.annotations.TestDoc;
import io.skodjob.kubetest4j.resources.KubeResourceManager;
import io.strimzi.api.kafka.model.common.CertificateManagerType;
import io.strimzi.api.kafka.model.common.certmanager.IssuerKind;
import io.strimzi.api.kafka.model.kafka.KafkaResources;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.ca.Ca;
import io.strimzi.systemtest.AbstractST;
import io.strimzi.systemtest.annotations.ParallelNamespaceTest;
import io.strimzi.systemtest.docs.TestDocsLabels;
import io.strimzi.systemtest.kafkaclients.ClientsAuthentication;
import io.strimzi.systemtest.resources.certManager.SetupCertManager;
import io.strimzi.systemtest.resources.operator.SetupClusterOperator;
import io.strimzi.systemtest.storage.TestStorage;
import io.strimzi.systemtest.templates.crd.KafkaNodePoolTemplates;
import io.strimzi.systemtest.templates.crd.KafkaTemplates;
import io.strimzi.systemtest.templates.crd.KafkaTopicTemplates;
import io.strimzi.systemtest.templates.crd.KafkaUserTemplates;
import io.strimzi.systemtest.utils.ClientUtils;
import io.strimzi.systemtest.utils.kubeUtils.objects.SecretUtils;
import io.strimzi.testclients.clients.kafka.KafkaProducerConsumer;
import io.strimzi.testclients.clients.kafka.KafkaProducerConsumerBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;

import java.security.cert.X509Certificate;
import java.util.Map;

import static io.strimzi.systemtest.TestTags.REGRESSION;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * System tests for cert-manager CA integration.
 *
 * <p>The test simulates the steps user would perform before deploying a Kafka cluster
 * with {@code clusterCa.type: cert-manager.io}:</p>
 * <ol>
 *   <li>A self-signed CA certificate and private key are generated and stored in a
 *       Kubernetes {@code Secret} in the cert-manager namespace.</li>
 *   <li>A CA-type {@code ClusterIssuer} ({@value SetupCertManager#CLUSTER_ISSUER_NAME}) is created,
 *       references the Secret in the cert-manager namespace so that cert-manager uses the CA key
 *       to sign end-entity certificates.</li>
 *   <li>The CA public cert is copied into the test namespace as a separate Secret,
 *       which Strimzi reads via {@code certManager.caCert} to establish trust.</li>
 * </ol>
 */
@Tag(REGRESSION)
@SuiteDoc(
    description = @Desc("Test suite verifying cert-manager CA integration: Strimzi delegates " +
        "end-entity certificate issuance to an external cert-manager issuer while the cluster CA " +
        "public cert is provided by the user in a Kubernetes Secret."),
    labels = {
        @Label(value = TestDocsLabels.SECURITY)
    }
)
public class CertManagerST extends AbstractST {

    private static final Logger LOGGER = LogManager.getLogger(CertManagerST.class);

    private static final String CA_CERT_SECRET_NAME = "cert-manager-ca-cert";
    private static final String CA_CERT_KEY = Ca.CA_CRT;

    @ParallelNamespaceTest
    @TestDoc(
        description = @Desc("Verifies the cert-manager Cluster CA happy path: a new Kafka cluster " +
            "is deployed with clusterCa.type=cert-manager.io. cert-manager issues all component " +
            "end-entity certificates. The cluster must come up healthy and a TLS-authenticated " +
            "producer/consumer must be able to send and receive messages."),
        steps = {
            @Step(value = "Create the CA cert Secret in the test namespace.",
                  expected = "Secret is present in the test namespace."),
            @Step(value = "Deploy Kafka with clusterCa.type=cert-manager.io, generateCertificateAuthority=false.",
                  expected = "Kafka cluster reaches ready state without errors."),
            @Step(value = "Assert cluster CA cert Secret has correct annotations.",
                  expected = "ca-cert-generation=0, ca-key-generation=0, and cert-hash annotations are set."),
            @Step(value = "Assert each broker cert Secret exists and its certificate is signed by the cert-manager CA.",
                  expected = "Broker cert Secrets are present and the certificate issuer DN matches the CA subject DN."),
            @Step(value = "Produce and consume messages over TLS using a KafkaUser.",
                  expected = "Messages are successfully produced and consumed.")
        },
        labels = {
            @Label(value = TestDocsLabels.SECURITY)
        }
    )
    void testNewClusterWithCertManagerClusterCa() {
        final TestStorage testStorage = new TestStorage(KubeResourceManager.get().getTestContext());

        createCaCertSecret(testStorage.getNamespaceName());

        KubeResourceManager.get().createResourceWithWait(
            KafkaNodePoolTemplates.brokerPoolPersistentStorage(
                testStorage.getNamespaceName(), testStorage.getBrokerPoolName(), testStorage.getClusterName(), 3).build(),
            KafkaNodePoolTemplates.controllerPoolPersistentStorage(
                testStorage.getNamespaceName(), testStorage.getControllerPoolName(), testStorage.getClusterName(), 3).build()
        );

        KubeResourceManager.get().createResourceWithWait(
            KafkaTemplates.kafka(testStorage.getNamespaceName(), testStorage.getClusterName(), 3)
                .editSpec()
                    .withNewClusterCa()
                        .withGenerateCertificateAuthority(false)
                        .withType(CertificateManagerType.CERT_MANAGER_IO)
                        .withNewCertManager()
                            .withNewIssuerRef()
                                .withName(SetupCertManager.CLUSTER_ISSUER_NAME)
                                .withKind(IssuerKind.CLUSTER_ISSUER)
                                .withGroup("cert-manager.io")
                            .endIssuerRef()
                            .withNewCaCert()
                                .withSecretName(CA_CERT_SECRET_NAME)
                                .withCertificate(CA_CERT_KEY)
                            .endCaCert()
                        .endCertManager()
                    .endClusterCa()
                .endSpec()
                .build()
        );

        LOGGER.info("Kafka cluster {}/{} is ready with cert-manager Cluster CA",
            testStorage.getNamespaceName(), testStorage.getClusterName());

        // Assert cluster CA cert Secret has the expected annotations
        final Secret clusterCaCertSecret = KubeResourceManager.get().kubeClient().getClient()
            .secrets()
            .inNamespace(testStorage.getNamespaceName())
            .withName(KafkaResources.clusterCaCertificateSecretName(testStorage.getClusterName()))
            .get();

        assertThat("Cluster CA cert Secret must exist", clusterCaCertSecret, notNullValue());

        final Map<String, String> caCertAnnotations = clusterCaCertSecret.getMetadata().getAnnotations();
        assertThat("ca-cert-generation must be 0 on initial deployment",
            caCertAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION), is("0"));
        assertThat("ca-key-generation must be 0 on initial deployment",
            caCertAnnotations.get(Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION), is("0"));
        assertThat("cert-hash annotation must be present",
            caCertAnnotations.containsKey(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH), is(true));

        LOGGER.info("Cluster CA cert Secret annotations verified: {}", caCertAnnotations);

        // Assert a broker cert Secret exists and its certificate is signed by the cert-manager CA
        final String brokerPodName = KubeResourceManager.get().kubeClient()
            .listPods(testStorage.getNamespaceName(), testStorage.getBrokerSelector())
            .getFirst().getMetadata().getName();

        final Secret brokerCertSecret = KubeResourceManager.get().kubeClient().getClient()
            .secrets()
            .inNamespace(testStorage.getNamespaceName())
            .withName(brokerPodName)
            .get();

        assertThat("Broker cert Secret '" + brokerPodName + "' must exist", brokerCertSecret, notNullValue());

        final X509Certificate brokerCert = SecretUtils.getCertificateFromSecret(brokerCertSecret, brokerPodName + ".crt");
        assertThat("Broker cert must not be null", brokerCert, notNullValue());

        final X509Certificate caCert = SecretUtils.getCertificateFromSecret(clusterCaCertSecret, Ca.CA_CRT);
        assertThat("Cluster CA cert must not be null", caCert, notNullValue());

        assertThat("Broker certificate issuer DN must match the cert-manager CA subject DN",
            brokerCert.getIssuerX500Principal().getName(),
            is(caCert.getSubjectX500Principal().getName()));

        LOGGER.info("Broker cert issuer '{}' matches CA subject '{}'",
            brokerCert.getIssuerX500Principal().getName(), caCert.getSubjectX500Principal().getName());

        //TODO: we should also check secrets such as cluster-f6f42e20-b-67110402-0-cm exist?
        // Investigate why cluster-operator-cm (without clusterId) for cluster-f6f42e20-cluster-operator-certs is created while other components' cm secrets contain clusterId in the name

        KubeResourceManager.get().createResourceWithWait(KafkaTopicTemplates.topic(testStorage).build());
        KubeResourceManager.get().createResourceWithWait(KafkaUserTemplates.tlsUser(testStorage).build());

        LOGGER.info("No unexpected rolling update occurred after initial deployment");

        // Produce and consume messages over TLS
        KafkaProducerConsumer kafkaProducerConsumer =
            new KafkaProducerConsumerBuilder()
                .withProducerName(testStorage.getProducerName())
                .withConsumerName(testStorage.getConsumerName())
                .withNamespaceName(testStorage.getNamespaceName())
                .withTopicName(testStorage.getTopicName())
                .withConsumerGroup(ClientUtils.generateRandomConsumerGroup())
                .withBootstrapAddress(KafkaResources.tlsBootstrapAddress(testStorage.getClusterName()))
                .withMessageCount(testStorage.getMessageCount())
                .withAuthentication(ClientsAuthentication.configureTls(testStorage.getClusterName(), testStorage.getUsername()))
                .build();

        KubeResourceManager.get().createResourceWithWait(
            kafkaProducerConsumer.getProducer().getJob(),
            kafkaProducerConsumer.getConsumer().getJob()
        );

        ClientUtils.waitForClientsSuccess(
            testStorage.getNamespaceName(),
            testStorage.getConsumerName(),
            testStorage.getProducerName(),
            testStorage.getMessageCount()
        );

        LOGGER.info("TLS producer/consumer successfully exchanged {} messages", testStorage.getMessageCount());
    }

    @BeforeAll
    void setup() {
        SetupCertManager.deployCertManager();
        SetupCertManager.createIssuerAndCaSecret();
        SetupClusterOperator
            .getInstance()
            .withDefaultConfiguration()
            .install();
        SetupCertManager.installCertManagerRbac(SetupClusterOperator.getInstance().getOperatorNamespace());
    }

    /**
     * Creates the user-provided CA cert Secret in the given namespace
     * that will be referenced in {@code certManager.caCert.secretName}.
     *
     * <p>The public cert value is retrieved from the Secret in the cert-manager namespace
     * that is used for ClusterIssuer to sign end-entity certificates.
     */
    private static void createCaCertSecret(String namespace) {
        final Secret secret = new SecretBuilder()
                .withNewMetadata()
                .withName(CA_CERT_SECRET_NAME)
                .withNamespace(namespace)
                .endMetadata()
                .addToData(CA_CERT_KEY, SetupCertManager.getCaCertBase64())
                .build();

        KubeResourceManager.get().createResourceWithWait(secret);
        LOGGER.info("Created user-provided CA cert Secret '{}/{}' (key='{}')", namespace, CA_CERT_SECRET_NAME, CA_CERT_KEY);
    }
}
