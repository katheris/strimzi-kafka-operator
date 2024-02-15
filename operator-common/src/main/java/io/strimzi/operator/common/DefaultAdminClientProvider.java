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
    private final Properties tlsConfig;

    /**
     * Constructor for connecting to Kafka without TLS enabled
     */
    public DefaultAdminClientProvider() {
        this.tlsConfig = new Properties();
    }

    /**
     * Constructor for TLS connection to Kafka
     *
     * @param pemTrustSet       Trust set for connecting to Kafka
     */
    public DefaultAdminClientProvider(PemTrustSet pemTrustSet) {
        if (pemTrustSet == null) {
            throw new RuntimeException("ahh");
        }
        this.tlsConfig = addTlsEncryptionProps(new Properties(), pemTrustSet);
    }

    /**
     * Constructor for TLS connection to Kafka, using TLS client authentication
     *
     * @param pemTrustSet       Trust set for connecting to Kafka
     * @param pemAuthIdentity   Identity for TLS client authentication for connecting to Kafka
     */
    public DefaultAdminClientProvider(PemTrustSet pemTrustSet, PemAuthIdentity pemAuthIdentity) {
        if (pemTrustSet == null) {
            throw new RuntimeException("ahh");
        }
        if (pemAuthIdentity == null) {
            throw new RuntimeException("ahh");
        }
        Properties config = new Properties();
        addTlsEncryptionProps(config, pemTrustSet);
        addTlsClientAuthProps(config, pemAuthIdentity);
        this.tlsConfig = config;
    }

    private static Properties addTlsEncryptionProps(Properties config, PemTrustSet pemTrustSet) {
        config.setProperty(AdminClientConfig.SECURITY_PROTOCOL_CONFIG, "SSL");
        config.setProperty(SslConfigs.SSL_TRUSTSTORE_TYPE_CONFIG, "PEM");
        config.setProperty(SslConfigs.SSL_TRUSTSTORE_CERTIFICATES_CONFIG, pemTrustSet.trustedCertificatesString());
        return config;
    }

    private static Properties addTlsClientAuthProps(Properties config, PemAuthIdentity pemAuthIdentity) {
        config.setProperty(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG, "PEM");
        config.setProperty(SslConfigs.SSL_KEYSTORE_CERTIFICATE_CHAIN_CONFIG, pemAuthIdentity.pemCertificateChainString());
        config.setProperty(SslConfigs.SSL_KEYSTORE_KEY_CONFIG, pemAuthIdentity.pemPrivateKeyString());
        return config;
    }

    @Override
    public Admin createAdminClient(String bootstrapHostnames) {
        return createAdminClient(bootstrapHostnames, new Properties());
    }

    /**
     * Create a Kafka Admin interface instance handling the following different scenarios:
     *
     * 1. No TLS connection, no TLS client authentication:
     *
     * If {@code pemTrustSet} and {@code pemAuthIdentity} are null, the returned Admin Client instance
     * is configured to connect to the Apache Kafka bootstrap (defined via {@code hostname}) on plain connection with no
     * TLS encryption and no TLS client authentication.
     *
     * 2. TLS connection, no TLS client authentication
     *
     * If only {@code pemTrustSet} is provided as not null, the returned Admin Client instance is configured to
     * connect to the Apache Kafka bootstrap (defined via {@code hostname}) on TLS encrypted connection but with no
     * TLS authentication.
     *
     * 3. TLS connection and TLS client authentication
     *
     * If {@code pemTrustSet} and {@code pemAuthIdentity} are provided as not null, the returned
     * Admin Client instance is configured to connect to the Apache Kafka bootstrap (defined via {@code hostname}) on
     * TLS encrypted connection and with TLS client authentication.
     */
    @Override
    public Admin createAdminClient(String bootstrapHostnames, Properties customConfig) {
        customConfig.setProperty(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapHostnames);
        customConfig.putAll(tlsConfig);

        customConfig.putIfAbsent(AdminClientConfig.METADATA_MAX_AGE_CONFIG, "30000");
        customConfig.putIfAbsent(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, "10000");
        customConfig.putIfAbsent(AdminClientConfig.RETRIES_CONFIG, "3");
        customConfig.putIfAbsent(AdminClientConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, "40000");

        return Admin.create(customConfig);
    }
}
