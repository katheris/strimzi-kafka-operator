/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.assembly;

import io.strimzi.api.kafka.model.kafka.Kafka;
import io.strimzi.api.kafka.model.nodepool.KafkaNodePool;
import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.Subject;
import io.strimzi.operator.cluster.ClusterOperatorConfig;
import io.strimzi.operator.cluster.PlatformFeaturesAvailability;
import io.strimzi.operator.cluster.model.ClusterCa;
import io.strimzi.operator.cluster.model.KafkaCluster;
import io.strimzi.operator.cluster.model.NodeRef;
import io.strimzi.operator.cluster.operator.resource.ResourceOperatorSupplier;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.ReconciliationLogger;
import io.strimzi.operator.common.model.ClientsCa;
import io.vertx.core.Future;
import io.vertx.core.Vertx;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

public abstract class ClusterCaCertificateReconciler {
    private static final ReconciliationLogger LOGGER = ReconciliationLogger.create(ClusterCaCertificateReconciler.class.getName());
    protected final Reconciliation reconciliation;
    protected final ClusterCa clusterCa;
    protected final ResourceOperatorSupplier resourceOperatorSupplier;

    public ClusterCaCertificateReconciler(Reconciliation reconciliation,
                                          Kafka kafkaCr,
                                          KafkaCluster kafka,
                                          ClusterCa clusterCa,
                                          ClientsCa clientsCa,
                                          ClusterOperatorConfig config,
                                          ResourceOperatorSupplier supplier,
                                          PlatformFeaturesAvailability pfa,
                                          Vertx vertx
    ) {
        this.reconciliation = reconciliation;
        this.clusterCa = clusterCa;
        this.resourceOperatorSupplier = supplier;
    }

    public Future<Void> reconcileServerCerts(
            Set<NodeRef> nodes,
            Function<NodeRef, Subject> subjectFn,
            Map<String, CertAndKey> existingCertificates,
            boolean isMaintenanceTimeWindowsSatisfied,
            boolean includeCaChain
    ) {
        return switch (clusterCa.getType()) {
            case CERT_MANAGER_IO ->
                //reconcile Cert Manager
                    Future.succeededFuture();
            case STRIMZI_IO ->
                //reconcile Strimzi
                    Future.succeededFuture();
        };
    }
}
