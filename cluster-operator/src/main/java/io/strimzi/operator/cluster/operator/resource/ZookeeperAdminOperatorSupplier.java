/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.resource;

import io.strimzi.operator.cluster.model.ClusterOperatorPKCS12AuthIdentity;
import io.strimzi.operator.common.BackOff;
import io.strimzi.operator.common.model.PemAuthIdentity;
import io.strimzi.operator.common.model.PemTrustSet;
import io.vertx.core.Vertx;

/**
 * Holds the providers for ZooKeeper admin operations
 */
public class ZookeeperAdminOperatorSupplier {
    /**
     * ZooKeeper Leader finder
     */
    public final ZookeeperLeaderFinder zookeeperLeaderFinder;

    /**
     * ZooKeeper Scaler provider
     */
    public final ZookeeperScalerProvider zkScalerProvider;

    /**
     * Constructor
     *
     * @param vertx                             Vert.x instance
     * @param pemTrustSet                       Trust set to use to connect Kafka
     * @param pemAuthIdentity                   Identity for TLS client authentication to use to connect to Kafka
     * @param clusterOperatorPKCS12AuthIdentity Identity for TLS client authentication to use to connect to Kafka for clients that require the PKSC12 format
     */
    public ZookeeperAdminOperatorSupplier(Vertx vertx, PemTrustSet pemTrustSet, PemAuthIdentity pemAuthIdentity, ClusterOperatorPKCS12AuthIdentity clusterOperatorPKCS12AuthIdentity) {
        this.zookeeperLeaderFinder = new ZookeeperLeaderFinder(vertx,
                        // Retry up to 3 times (4 attempts), with overall max delay of 35000ms
                        () -> new BackOff(5_000, 2, 4), pemTrustSet, pemAuthIdentity);
        this.zkScalerProvider = new DefaultZookeeperScalerProvider(pemTrustSet, clusterOperatorPKCS12AuthIdentity);
    }

    /**
     * Constructor
     *
     * @param zookeeperLeaderFinder     ZooKeeper Leader Finder
     * @param zkScalerProvider          ZooKeeper Scaler Provider
     */
    public ZookeeperAdminOperatorSupplier(ZookeeperLeaderFinder zookeeperLeaderFinder, ZookeeperScalerProvider zkScalerProvider) {
        this.zookeeperLeaderFinder = zookeeperLeaderFinder;
        this.zkScalerProvider = zkScalerProvider;
    }
}
