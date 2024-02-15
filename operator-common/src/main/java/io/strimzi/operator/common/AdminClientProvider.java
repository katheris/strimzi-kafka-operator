/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common;

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
     * @return Instance of Kafka Admin interface
     */
    Admin createAdminClient(String bootstrapHostnames);

    /**
     * Create a Kafka Admin interface instance
     *
     * @param bootstrapHostnames Kafka hostname to connect to for administration operations
     * @param config Additional configuration for the Kafka Admin Client
     *
     * @return Instance of Kafka Admin interface
     */
    Admin createAdminClient(String bootstrapHostnames, Properties config);
}
