/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.systemtest.upgrade;

import io.strimzi.systemtest.utils.TestKafkaVersion;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Class for representing Kafka version, with LMFV and IBPV for our upgrade/downgrade tests
 * Represents "procedures" which should be done after upgrade of operator/before downgrade of operator
 */
public class UpgradeKafkaVersion {

    private String version;
    private String logMessageVersion;
    private String interBrokerVersion;
    private String metadataVersion;

    public UpgradeKafkaVersion(TestKafkaVersion testKafkaVersion) {
        this(testKafkaVersion.version(), testKafkaVersion.messageVersion(), testKafkaVersion.protocolVersion());
    }

    public UpgradeKafkaVersion(String version, String desiredMetadataVersion) {
        this.version = version;
        this.metadataVersion = desiredMetadataVersion;
    }

    public UpgradeKafkaVersion(String version) {
        String shortVersion = version;

        if (version != null && !version.equals("")) {
            String[] versionSplit = version.split("\\.");
            shortVersion = String.format("%s.%s", versionSplit[0], versionSplit[1]);
        }

        this.version = version;
        this.logMessageVersion = shortVersion;
        this.interBrokerVersion = shortVersion;
        this.metadataVersion = shortVersion;
    }

    /**
     * Leaving empty, so original Kafka version in `kafka-persistent.yaml` will be used
     * LMFV and IBPV should be null, so the test steps will for updating the config will be skipped
     */
    public UpgradeKafkaVersion() {
        this("", null, null);
    }

    public UpgradeKafkaVersion(String version, String logMessageVersion, String interBrokerVersion) {
        this.version = version;
        this.logMessageVersion = logMessageVersion;
        this.interBrokerVersion = interBrokerVersion;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public void setLogMessageVersion(String logMessageVersion) {
        this.logMessageVersion = logMessageVersion;
    }

    public void setMetadataVersion(String metadataVersion) {
        this.metadataVersion = metadataVersion;
    }

    public String getVersion() {
        return version;
    }

    public String getLogMessageVersion() {
        return this.logMessageVersion;
    }

    public String getInterBrokerVersion() {
        return this.interBrokerVersion;
    }

    public String getMetadataVersion() {
        return this.metadataVersion;
    }

    public static UpgradeKafkaVersion getKafkaWithVersionFromUrl(String kafkaVersionsUrl, String kafkaVersion) {
        if (kafkaVersionsUrl.equals("HEAD")) {
            return new UpgradeKafkaVersion(TestKafkaVersion.getSpecificVersion(kafkaVersion));
        } else {
            try {
                TestKafkaVersion testKafkaVersion = TestKafkaVersion.getSpecificVersionFromList(
                    TestKafkaVersion.parseKafkaVersionsFromUrl(kafkaVersionsUrl), kafkaVersion
                );
                return new UpgradeKafkaVersion(testKafkaVersion);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    public static Optional<UpgradeKafkaVersion> getKafkaVersionSupportedBeforeUnsupportedAfterUpgrade(String fromKafkaVersionsUrl) {
        List<TestKafkaVersion> supportedKafkaVersionsBeforeUpgrade = getSupportedKafkaVersions(fromKafkaVersionsUrl);
        List<String> supportedKafkaVersionsAfterUpgrade = getSupportedKafkaVersions("HEAD")
                .stream()
                .map(TestKafkaVersion::version)
                .collect(Collectors.toList());

        return supportedKafkaVersionsBeforeUpgrade
                .stream()
                .filter(version -> !supportedKafkaVersionsAfterUpgrade.contains(version.version()))
                .map(UpgradeKafkaVersion::new)
                .findFirst();
    }

    private static List<TestKafkaVersion> getSupportedKafkaVersions(String kafkaVersionsUrl) {
        if (kafkaVersionsUrl.equals("HEAD")) {
            return TestKafkaVersion.getSupportedKafkaVersions();
        } else {
            try {
                List<TestKafkaVersion> kafkaVersions = TestKafkaVersion.parseKafkaVersionsFromUrl(kafkaVersionsUrl);
                return TestKafkaVersion.getSupportedKafkaVersionsFromAllVersions(kafkaVersions);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }
}
