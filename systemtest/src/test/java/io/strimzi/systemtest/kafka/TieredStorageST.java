/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.systemtest.kafka;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.strimzi.api.kafka.model.kafka.KafkaResources;
import io.strimzi.systemtest.AbstractST;
import io.strimzi.systemtest.Environment;
import io.strimzi.systemtest.TestConstants;
import io.strimzi.systemtest.annotations.MicroShiftNotSupported;
import io.strimzi.systemtest.annotations.ParallelTest;
import io.strimzi.systemtest.kafkaclients.internalClients.KafkaClients;
import io.strimzi.systemtest.kafkaclients.internalClients.admin.AdminClient;
import io.strimzi.systemtest.resources.NamespaceManager;
import io.strimzi.systemtest.resources.NodePoolsConverter;
import io.strimzi.systemtest.resources.ResourceManager;
import io.strimzi.systemtest.resources.crd.KafkaTopicResource;
import io.strimzi.systemtest.resources.imageBuild.ImageBuild;
import io.strimzi.systemtest.resources.minio.SetupMinio;
import io.strimzi.systemtest.storage.TestStorage;
import io.strimzi.systemtest.templates.crd.KafkaNodePoolTemplates;
import io.strimzi.systemtest.templates.crd.KafkaTemplates;
import io.strimzi.systemtest.templates.crd.KafkaTopicTemplates;
import io.strimzi.systemtest.templates.specific.AdminClientTemplates;
import io.strimzi.systemtest.utils.AdminClientUtils;
import io.strimzi.systemtest.utils.ClientUtils;
import io.strimzi.systemtest.utils.specific.MinioUtils;
import io.strimzi.test.TestUtils;
import org.apache.kafka.common.requests.ListOffsetsRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;

import java.io.IOException;
import java.util.Collections;

import static io.strimzi.systemtest.TestTags.REGRESSION;
import static io.strimzi.systemtest.TestTags.TIERED_STORAGE;

/**
 * @description This test suite covers scenarios for Tiered Storage integration implemented within Strimzi.
 *
 * @steps
 *  1. - Create test namespace
 *  2. - Build Kafka image based on passed parameters like image full name, base image, Dockerfile path (via Kaniko or OpenShift build)
 *  3. - Deploy Minio in test namespace and init the client inside the Minio pod
 *  4. - Init bucket in Minio for purposes of these tests
 *  5. - Deploy Strimzi Cluster Operator
 *
 * @usecase
 *  - tiered-storage-integration
 */
@MicroShiftNotSupported("We are using Kaniko and OpenShift builds to build Kafka image with TS. To make it working on Microshift we will invest much time with not much additional value.")
@Tag(REGRESSION)
@Tag(TIERED_STORAGE)
public class TieredStorageST extends AbstractST {
    private static final Logger LOGGER = LogManager.getLogger(TieredStorageST.class);

    private static final String IMAGE_NAME = "kafka-tiered-storage";
    private static final String TIERED_STORAGE_DOCKERFILE = TestUtils.USER_PATH + "/../systemtest/src/test/resources/tiered-storage/Dockerfile";
    private static final String BUCKET_NAME = "test-bucket";
    private static final String BUILT_IMAGE_TAG = "latest";
    private TestStorage suiteStorage;

    /**
     * @description This testcase is focused on testing of Tiered Storage integration implemented within Strimzi.
     * The tests use Aiven Tiered Storage plugin - <a href="https://github.com/Aiven-Open/tiered-storage-for-apache-kafka/tree/main">...</a>
     *
     * @steps
     *  1. - Deploys KafkaNodePool resource with Broker NodePool with PV of size 10Gi
     *  2. - Deploys Kafka resource with configuration of Tiered Storage for Aiven plugin, pointing to Minio S3, and with image built in beforeAll
     *  3. - Creates topic with enabled Tiered Storage sync with size of segments set to 10mb (this is needed for speedup the sync)
     *  4. - Starts continuous producer to send data to Kafka
     *  5. - Wait until Minio size is not empty (contains data from Kafka)
     *
     * @usecase
     *  - tiered-storage-integration
     */
    @ParallelTest
    void testTieredStorageWithAivenPlugin() {
        final TestStorage testStorage = new TestStorage(ResourceManager.getTestContext());

        resourceManager.createResourceWithWait(
            NodePoolsConverter.convertNodePoolsIfNeeded(
                KafkaNodePoolTemplates.brokerPoolPersistentStorage(suiteStorage.getNamespaceName(), testStorage.getBrokerPoolName(), testStorage.getClusterName(), 3)
                    .editSpec()
                        .withNewPersistentClaimStorage()
                            .withSize("10Gi")
                            .withDeleteClaim(true)
                        .endPersistentClaimStorage()
                    .endSpec()
                    .build(),
                KafkaNodePoolTemplates.controllerPoolPersistentStorage(suiteStorage.getNamespaceName(), testStorage.getControllerPoolName(), testStorage.getClusterName(), 1).build()
            )
        );

        resourceManager.createResourceWithWait(KafkaTemplates.kafkaPersistent(suiteStorage.getNamespaceName(), testStorage.getClusterName(), 3)
            .editSpec()
                .editKafka()
                    .withImage(Environment.getImageOutputRegistry(suiteStorage.getNamespaceName(), IMAGE_NAME, BUILT_IMAGE_TAG))
                    .withNewTieredStorageCustomTiered()
                        .withNewRemoteStorageManager()
                            .withClassName("io.aiven.kafka.tieredstorage.RemoteStorageManager")
                            .withClassPath("/opt/kafka/plugins/tiered-storage/*")
                            .addToConfig("storage.backend.class", "io.aiven.kafka.tieredstorage.storage.s3.S3Storage")
                            .addToConfig("chunk.size", "4194304")
                            // s3 config
                            .addToConfig("storage.s3.endpoint.url",
                                    "http://" + SetupMinio.MINIO + "." + suiteStorage.getNamespaceName() + ".svc.cluster.local:" + SetupMinio.MINIO_PORT)
                            .addToConfig("storage.s3.bucket.name", BUCKET_NAME)
                            .addToConfig("storage.s3.region", "us-east-1")
                            .addToConfig("storage.s3.path.style.access.enabled", "true")
                            .addToConfig("storage.aws.access.key.id", SetupMinio.ADMIN_CREDS)
                            .addToConfig("storage.aws.secret.access.key", SetupMinio.ADMIN_CREDS)
                        .endRemoteStorageManager()
                    .endTieredStorageCustomTiered()
                    // reduce the interval to speed up the test
                    .addToConfig("remote.log.manager.task.interval.ms", 5000)
                    .addToConfig("log.retention.check.interval.ms", 5000)
                .endKafka()
            .endSpec()
            .build());

        resourceManager.createResourceWithWait(KafkaTopicTemplates.topic(suiteStorage.getNamespaceName(), testStorage.getTopicName(), testStorage.getClusterName())
            .editSpec()
                .addToConfig("file.delete.delay.ms", 1000)
                .addToConfig("local.retention.ms", 1000)
                // Allow tiered storage sync
                .addToConfig("remote.storage.enable", true)
                // Bytes retention set to 1024mb
                .addToConfig("retention.bytes", 1073741824)
                .addToConfig("retention.ms", 86400000)
                // Segment size is set to 10mb to make it quickier to sync data to Minio
                .addToConfig("segment.bytes", 1048576)
            .endSpec()
            .build());

        final KafkaClients clients = ClientUtils.getInstantPlainClientBuilder(testStorage)
            .withMessageCount(10000)
            .withDelayMs(1)
            .withMessage(String.join("", Collections.nCopies(5000, "#")))
            .build();

        resourceManager.createResourceWithWait(clients.producerStrimzi());

        MinioUtils.waitForDataInMinio(suiteStorage.getNamespaceName(), BUCKET_NAME);

        // Create admin-client to check offsets
        resourceManager.createResourceWithWait(
            AdminClientTemplates.plainAdminClient(
                testStorage.getNamespaceName(),
                testStorage.getAdminName(),
                KafkaResources.plainBootstrapAddress(testStorage.getClusterName())
            ).build()
        );
        final AdminClient adminClient = AdminClientUtils.getConfiguredAdminClient(testStorage.getNamespaceName(), testStorage.getAdminName());

        TestUtils.waitFor("earliest-local offset to be higher than 0",
            TestConstants.GLOBAL_POLL_INTERVAL_5_SECS, TestConstants.GLOBAL_TIMEOUT_LONG,
            () -> {
                // Fetch earliest-local offsets
                // Check that data are not present locally, earliest-local offset should be higher than 0
                String offsetData = adminClient.fetchOffsets(testStorage.getTopicName(), String.valueOf(ListOffsetsRequest.EARLIEST_LOCAL_TIMESTAMP));
                long earliestLocalOffset = 0;
                try {
                    earliestLocalOffset = AdminClientUtils.getPartitionsOffset(offsetData, "0");
                    LOGGER.info("earliest-local offset for topic {} is {}", testStorage.getTopicName(), earliestLocalOffset);
                } catch (JsonProcessingException e) {
                    return false;
                }
                return earliestLocalOffset > 0;
            });

        ClientUtils.waitForInstantProducerClientSuccess(testStorage);

        resourceManager.createResourceWithWait(clients.consumerStrimzi());
        ClientUtils.waitForInstantConsumerClientSuccess(testStorage);

        // Delete data
        KafkaTopicResource.replaceTopicResourceInSpecificNamespace(
            testStorage.getNamespaceName(), testStorage.getTopicName(), topic -> topic.getSpec().getConfig().put("retention.ms", 10000)
        );

        MinioUtils.waitForNoDataInMinio(suiteStorage.getNamespaceName(), BUCKET_NAME);
    }

    @BeforeAll
    void setup() throws IOException {
        suiteStorage = new TestStorage(ResourceManager.getTestContext());
        
        NamespaceManager.getInstance().createNamespaceAndPrepare(suiteStorage.getNamespaceName());
        cluster.setNamespace(suiteStorage.getNamespaceName());

        ImageBuild.buildImage(suiteStorage.getNamespaceName(), IMAGE_NAME, TIERED_STORAGE_DOCKERFILE, BUILT_IMAGE_TAG, Environment.KAFKA_TIERED_STORAGE_BASE_IMAGE);

        SetupMinio.deployMinio(suiteStorage.getNamespaceName());
        SetupMinio.createBucket(suiteStorage.getNamespaceName(), BUCKET_NAME);

        this.clusterOperator = this.clusterOperator
            .defaultInstallation()
            .createInstallation()
            .runInstallation();
    }
}
