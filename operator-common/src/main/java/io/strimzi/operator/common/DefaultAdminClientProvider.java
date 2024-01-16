/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common;

import io.strimzi.operator.common.model.PemAuthIdentity;
import io.strimzi.operator.common.model.PemTrustSet;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.common.config.SslConfigs;

import java.util.Properties;

/**
 * Provides the default Kafka Admin client
 */
public class DefaultAdminClientProvider implements AdminClientProvider {
    @Override
    public Admin createAdminClient(String bootstrapHostnames, PemTrustSet pemTrustSet, PemAuthIdentity pemAuthIdentity) {
        return createAdminClient(bootstrapHostnames, pemTrustSet, pemAuthIdentity, new Properties());
    }

    /**
     * Create a Kafka Admin interface instance handling the following different scenarios:
     *
     * 1. No TLS connection, no TLS client authentication:
     *
     * If {@code clusterCaCertSecret}, {@code keyCertSecret} and {@code keyCertName} are null, the returned Admin Client instance
     * is configured to connect to the Apache Kafka bootstrap (defined via {@code hostname}) on plain connection with no
     * TLS encryption and no TLS client authentication.
     *
     * 2. TLS connection, no TLS client authentication
     *
     * If only {@code clusterCaCertSecret} is provided as not null, the returned Admin Client instance is configured to
     * connect to the Apache Kafka bootstrap (defined via {@code hostname}) on TLS encrypted connection but with no
     * TLS authentication.
     *
     * 3. TLS connection and TLS client authentication
     *
     * If {@code clusterCaCertSecret}, {@code keyCertSecret} and {@code keyCertName} are provided as not null, the returned
     * Admin Client instance is configured to connect to the Apache Kafka bootstrap (defined via {@code hostname}) on
     * TLS encrypted connection and with TLS client authentication.
     */
    @Override
    public Admin createAdminClient(String bootstrapHostnames, PemTrustSet pemTrustSet, PemAuthIdentity pemAuthIdentity, Properties config) {
        String trustedCertificates = pemTrustSet.trustedCertificatesString();
        String privateKey = pemAuthIdentity.pemPrivateKeyString();
        String certificateChain = pemAuthIdentity.pemCertificateChainString();

        config.setProperty(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapHostnames);

        // configuring TLS encryption if requested
        if (trustedCertificates != null) {
            config.setProperty(AdminClientConfig.SECURITY_PROTOCOL_CONFIG, "SSL");
            config.setProperty(SslConfigs.SSL_TRUSTSTORE_TYPE_CONFIG, "PEM");
            config.setProperty(SslConfigs.SSL_TRUSTSTORE_CERTIFICATES_CONFIG, trustedCertificates);
        }

        // configuring TLS client authentication
        if (certificateChain != null && privateKey != null) {
            config.setProperty(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG, "PEM");
            config.setProperty(SslConfigs.SSL_KEYSTORE_CERTIFICATE_CHAIN_CONFIG, certificateChain);
            config.setProperty(SslConfigs.SSL_KEYSTORE_KEY_CONFIG, privateKey);
        }

        config.putIfAbsent(AdminClientConfig.METADATA_MAX_AGE_CONFIG, "30000");
        config.putIfAbsent(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, "10000");
        config.putIfAbsent(AdminClientConfig.RETRIES_CONFIG, "3");
        config.putIfAbsent(AdminClientConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, "40000");

        return Admin.create(config);
    }
}
