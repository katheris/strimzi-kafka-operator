/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.assembly;

import io.strimzi.api.kafka.model.common.CertificateManagerType;
import io.strimzi.api.kafka.model.kafka.Kafka;
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

public class CertManagerClusterCaCertificateReconciler extends ClusterCaCertificateReconciler {
    private static final ReconciliationLogger LOGGER = ReconciliationLogger.create(CertManagerClusterCaCertificateReconciler.class.getName());

    public CertManagerClusterCaCertificateReconciler(Reconciliation reconciliation, Kafka kafkaCr, KafkaCluster kafka, ClusterCa clusterCa, ClientsCa clientsCa, ClusterOperatorConfig config, ResourceOperatorSupplier supplier, PlatformFeaturesAvailability pfa, Vertx vertx) {
        super(reconciliation, kafkaCr, kafka, clusterCa, clientsCa, config, supplier, pfa, vertx);
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

    /**
     * Manages the Certificate objects that are used when cert-manager is the Certificate issuer
     *
     * @return Completes when the Certificate objects were successfully created, deleted or updated
     */
    private Future<Void> reconcileCertManagerCertificates() {
        List<Future<Void>> futures = kafka.generateKafkaNodeCertificateResources(clusterCa, listenerReconciliationResults.bootstrapDnsNames, listenerReconciliationResults.brokerDnsNames)
                .stream()
                .map(certificate -> {
                    String certificateName = certificate.getMetadata().getName();
                    return resourceOperatorSupplier.certManagerCertificateOperator.reconcile(reconciliation, reconciliation.namespace(), certificateName, certificate)
                            .compose(v -> resourceOperatorSupplier.certManagerCertificateOperator.waitForReady(reconciliation, reconciliation.namespace(), certificateName));
                }).toList();
        return Future.join(futures).mapEmpty();
    }
}
