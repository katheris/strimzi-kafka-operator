/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.resource;

import io.strimzi.operator.cluster.model.ClusterOperatorPKCS12AuthIdentity;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.model.PemTrustSet;
import io.vertx.core.Vertx;

import java.util.function.Function;

/**
 * Class to provide the real ZookeeperScaler which connects to actual Zookeeper
 */
public class DefaultZookeeperScalerProvider implements ZookeeperScalerProvider {
    private static final ZooKeeperAdminProvider ZOO_ADMIN_PROVIDER = new DefaultZooKeeperAdminProvider();
    private final PemTrustSet pemTrustSet;
    private final ClusterOperatorPKCS12AuthIdentity pksc12AuthIdentity;

    /**
     * Constructor
     *
     * @param pemTrustSet           Trust set to use to connect Kafka
     * @param pksc12AuthIdentity    Identity for TLS client authentication to use to connect to Kafka for clients that require the PKSC12 format
     */
    public DefaultZookeeperScalerProvider(PemTrustSet pemTrustSet, ClusterOperatorPKCS12AuthIdentity pksc12AuthIdentity) {
        this.pemTrustSet = pemTrustSet;
        this.pksc12AuthIdentity = pksc12AuthIdentity;
    }

    /**
     * Creates an instance of ZookeeperScaler
     *
     * @param reconciliation                The reconciliation
     * @param vertx                         Vertx instance
     * @param zookeeperConnectionString     Connection string to connect to the right Zookeeper
     * @param zkNodeAddress                 Function for generating the Zookeeper node addresses
     * @param operationTimeoutMs            Operation timeout
     *
     * @return  ZookeeperScaler instance
     */
    public ZookeeperScaler createZookeeperScaler(Reconciliation reconciliation, Vertx vertx, String zookeeperConnectionString,
                                                 Function<Integer, String> zkNodeAddress, long operationTimeoutMs, int zkAdminSessionTimeoutMs) {
        return new ZookeeperScaler(reconciliation, vertx, ZOO_ADMIN_PROVIDER, zookeeperConnectionString, zkNodeAddress,
                pemTrustSet, pksc12AuthIdentity, operationTimeoutMs, zkAdminSessionTimeoutMs);
    }
}
