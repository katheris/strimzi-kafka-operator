/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common;

import io.strimzi.operator.common.model.PemKeyStoreSupplier;
import io.strimzi.operator.common.model.PemTrustStoreSupplier;
import org.apache.kafka.clients.admin.Admin;

import java.util.Properties;

/**
 * Interface to be implemented for returning an instance of Kafka Admin interface
 */
public interface AdminClientProvider {

    /**
     * Create a Kafka Admin interface instance
     *
     * @param bootstrapHostnames Kafka hostname to connect to for administration operations
     * @param pemTrustStoreSupplier Supplier for fetching the truststore for TLS encryption
     * @param pemKeyStoreSupplier Supplier for fetching the keystore for TLS client authentication
     * @return Instance of Kafka Admin interface
     */
    Admin createAdminClient(String bootstrapHostnames, PemTrustStoreSupplier pemTrustStoreSupplier, PemKeyStoreSupplier pemKeyStoreSupplier);

    /**
     * Create a Kafka Admin interface instance
     *
     * @param bootstrapHostnames Kafka hostname to connect to for administration operations
     * @param pemTrustStoreSupplier Supplier for fetching the truststore for TLS encryption
     * @param pemKeyStoreSupplier Supplier for fetching the keystore for TLS client authentication
     * @param config Additional configuration for the Kafka Admin Client
     *
     * @return Instance of Kafka Admin interface
     */
    Admin createAdminClient(String bootstrapHostnames, PemTrustStoreSupplier pemTrustStoreSupplier, PemKeyStoreSupplier pemKeyStoreSupplier, Properties config);
}
