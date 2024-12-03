/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.assembly;

import io.fabric8.kubernetes.api.model.OwnerReference;
import io.fabric8.kubernetes.api.model.OwnerReferenceBuilder;
import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.strimzi.api.kafka.model.common.CertificateAuthority;
import io.strimzi.api.kafka.model.kafka.Kafka;
import io.strimzi.api.kafka.model.kafka.KafkaResources;
import io.strimzi.api.kafka.model.kafka.cruisecontrol.CruiseControlResources;
import io.strimzi.api.kafka.model.kafka.exporter.KafkaExporterResources;
import io.strimzi.api.kafka.model.podset.StrimziPodSet;
import io.strimzi.certs.CertManager;
import io.strimzi.operator.cluster.ClusterOperatorConfig;
import io.strimzi.operator.cluster.model.AbstractModel;
import io.strimzi.operator.cluster.model.CertUtils;
import io.strimzi.operator.cluster.model.ClusterCa;
import io.strimzi.operator.cluster.model.ModelUtils;
import io.strimzi.operator.cluster.model.NodeRef;
import io.strimzi.operator.cluster.model.RestartReason;
import io.strimzi.operator.cluster.model.RestartReasons;
import io.strimzi.operator.cluster.model.WorkloadUtils;
import io.strimzi.operator.cluster.operator.resource.KafkaAgentClientProvider;
import io.strimzi.operator.cluster.operator.resource.KafkaRoller;
import io.strimzi.operator.cluster.operator.resource.ResourceOperatorSupplier;
import io.strimzi.operator.cluster.operator.resource.ZooKeeperRoller;
import io.strimzi.operator.cluster.operator.resource.ZookeeperLeaderFinder;
import io.strimzi.operator.cluster.operator.resource.events.KubernetesRestartEventPublisher;
import io.strimzi.operator.cluster.operator.resource.kubernetes.DeploymentOperator;
import io.strimzi.operator.cluster.operator.resource.kubernetes.PodOperator;
import io.strimzi.operator.cluster.operator.resource.kubernetes.SecretOperator;
import io.strimzi.operator.cluster.operator.resource.kubernetes.StrimziPodSetOperator;
import io.strimzi.operator.common.AdminClientProvider;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.BackOff;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.ReconciliationLogger;
import io.strimzi.operator.common.Util;
import io.strimzi.operator.common.auth.PemAuthIdentity;
import io.strimzi.operator.common.auth.PemTrustSet;
import io.strimzi.operator.common.auth.TlsPemIdentity;
import io.strimzi.operator.common.model.Ca;
import io.strimzi.operator.common.model.ClientsCa;
import io.strimzi.operator.common.model.Labels;
import io.strimzi.operator.common.model.PasswordGenerator;
import io.strimzi.operator.common.operator.resource.ReconcileResult;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;

import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static io.strimzi.operator.common.model.Ca.INIT_GENERATION;

/**
 * Class used for reconciliation of Cluster and Client CAs. This class contains both the steps of the CA reconciliation
 * pipeline and is also used to store the state between them.
 */
public class CaReconciler {
    private static final ReconciliationLogger LOGGER = ReconciliationLogger.create(CaReconciler.class.getName());

    /* test */ final Reconciliation reconciliation;
    private final Vertx vertx;
    private final long operationTimeoutMs;

    /* test */ final DeploymentOperator deploymentOperator;
    private final StrimziPodSetOperator strimziPodSetOperator;
    private final SecretOperator secretOperator;
    /* test */ final PodOperator podOperator;
    private final AdminClientProvider adminClientProvider;
    private final KafkaAgentClientProvider kafkaAgentClientProvider;
    private final ZookeeperLeaderFinder zookeeperLeaderFinder;
    private final CertManager certManager;
    private final PasswordGenerator passwordGenerator;
    private final KubernetesRestartEventPublisher eventPublisher;

    // Fields based on the Kafka CR required for the reconciliation
    private final List<String> maintenanceWindows;
    private final OwnerReference ownerRef;
    private final CertificateAuthority clusterCaConfig;
    private final CertificateAuthority clientsCaConfig;
    private final Map<String, String> caLabels;
    private final Labels clusterOperatorSecretLabels;
    private final Map<String, String> clusterCaCertLabels;
    private final Map<String, String> clusterCaCertAnnotations;

    // Fields used to store state during the reconciliation
    private ClusterCa clusterCa;
    private ClientsCa clientsCa;
    private Secret coSecret;
    private Secret clusterCaCertSecret;

    /* test */ boolean isClusterCaNeedFullTrust;
    /* test */ boolean isClusterCaFullyUsed;

    /**
     * Constructs the CA reconciler which reconciles the Cluster and Client CAs
     *
     * @param reconciliation    Reconciliation marker
     * @param kafkaCr           The Kafka custom resource
     * @param config            Cluster Operator Configuration
     * @param supplier          Supplier with Kubernetes Resource Operators
     * @param vertx             Vert.x instance
     * @param certManager       Certificate Manager for managing certificates
     * @param passwordGenerator Password generator for generating passwords
     */
    public CaReconciler(
            Reconciliation reconciliation,
            Kafka kafkaCr,
            ClusterOperatorConfig config,
            ResourceOperatorSupplier supplier,
            Vertx vertx,
            CertManager certManager,
            PasswordGenerator passwordGenerator
    ) {
        this.reconciliation = reconciliation;
        this.vertx = vertx;
        this.operationTimeoutMs = config.getOperationTimeoutMs();

        this.deploymentOperator = supplier.deploymentOperations;
        this.strimziPodSetOperator = supplier.strimziPodSetOperator;
        this.secretOperator = supplier.secretOperations;
        this.podOperator = supplier.podOperations;

        this.adminClientProvider = supplier.adminClientProvider;
        this.kafkaAgentClientProvider = supplier.kafkaAgentClientProvider;
        this.zookeeperLeaderFinder = supplier.zookeeperLeaderFinder;
        this.certManager = certManager;
        this.passwordGenerator = passwordGenerator;

        this.eventPublisher = supplier.restartEventsPublisher;

        // Extract required information from the Kafka CR
        this.maintenanceWindows = kafkaCr.getSpec().getMaintenanceTimeWindows();
        this.ownerRef = new OwnerReferenceBuilder()
                .withApiVersion(kafkaCr.getApiVersion())
                .withKind(kafkaCr.getKind())
                .withName(kafkaCr.getMetadata().getName())
                .withUid(kafkaCr.getMetadata().getUid())
                .withBlockOwnerDeletion(false)
                .withController(false)
                .build();
        this.clusterCaConfig = kafkaCr.getSpec().getClusterCa();
        this.clientsCaConfig = kafkaCr.getSpec().getClientsCa();
        this.caLabels = Labels.generateDefaultLabels(kafkaCr, Labels.APPLICATION_NAME, "certificate-authority", AbstractModel.STRIMZI_CLUSTER_OPERATOR_NAME).toMap();
        this.clusterOperatorSecretLabels = Labels.generateDefaultLabels(kafkaCr, Labels.APPLICATION_NAME, Labels.APPLICATION_NAME, AbstractModel.STRIMZI_CLUSTER_OPERATOR_NAME);
        this.clusterCaCertLabels = clusterCaCertLabels(kafkaCr);
        this.clusterCaCertAnnotations = clusterCaCertAnnotations(kafkaCr);
    }

    /**
     * Utility method to extract the template labels from the Kafka CR.
     *
     * @param kafkaCr   Kafka CR
     *
     * @return  Map with the labels from the Kafka CR or empty map if the template is not set
     */
    private static Map<String, String> clusterCaCertLabels(Kafka kafkaCr)    {
        if (kafkaCr.getSpec().getKafka() != null
                && kafkaCr.getSpec().getKafka().getTemplate() != null
                && kafkaCr.getSpec().getKafka().getTemplate().getClusterCaCert() != null
                && kafkaCr.getSpec().getKafka().getTemplate().getClusterCaCert().getMetadata() != null
                && kafkaCr.getSpec().getKafka().getTemplate().getClusterCaCert().getMetadata().getLabels() != null) {
            return kafkaCr.getSpec().getKafka().getTemplate().getClusterCaCert().getMetadata().getLabels();
        } else {
            return Map.of();
        }
    }

    /**
     * Utility method to extract the template annotations from the Kafka CR.
     *
     * @param kafkaCr   Kafka CR
     *
     * @return  Map with the annotation from the Kafka CR or empty map if the template is not set
     */
    private static Map<String, String> clusterCaCertAnnotations(Kafka kafkaCr)    {
        if (kafkaCr.getSpec().getKafka() != null
                && kafkaCr.getSpec().getKafka().getTemplate() != null
                && kafkaCr.getSpec().getKafka().getTemplate().getClusterCaCert() != null
                && kafkaCr.getSpec().getKafka().getTemplate().getClusterCaCert().getMetadata() != null
                && kafkaCr.getSpec().getKafka().getTemplate().getClusterCaCert().getMetadata().getAnnotations() != null) {
            return kafkaCr.getSpec().getKafka().getTemplate().getClusterCaCert().getMetadata().getAnnotations();
        } else {
            return Map.of();
        }
    }

    /**
     * The main reconciliation method which triggers the whole reconciliation pipeline. This is the method which is
     * expected to be called from the outside to trigger the reconciliation.
     *
     * @param clock     The clock for supplying the reconciler with the time instant of each reconciliation cycle.
     *                  That time is used for checking maintenance windows
     *
     * @return  Future with the CA reconciliation result containing the Cluster and Clients CAs
     */
    public Future<CaReconciliationResult> reconcile(Clock clock)    {
        return reconcileCas(clock)
                .compose(i -> verifyClusterCaFullyTrustedAndUsed())
                .compose(i -> reconcileClusterOperatorSecret(clock))
                .compose(i -> maybeRollingUpdateForNewClusterCaKey())
                .compose(i -> maybeRemoveOldClusterCaCertificates())
                .map(i -> new CaReconciliationResult(clusterCa, clientsCa));
    }

    /**
     * Asynchronously reconciles the cluster and clients CA secrets.
     * The cluster CA secret has to have the name determined by {@link AbstractModel#clusterCaCertSecretName(String)}.
     * The clients CA secret has to have the name determined by {@link KafkaResources#clientsCaCertificateSecretName(String)}.
     * Within both the secrets the current certificate is stored under the key {@code ca.crt}
     * and the current key is stored under the key {@code ca.key}.
     *
     * @param clock     The clock for supplying the reconciler with the time instant of each reconciliation cycle.
     *                  That time is used for checking maintenance windows
     */
    @SuppressWarnings({"checkstyle:CyclomaticComplexity", "checkstyle:NPathComplexity"})
    Future<Void> reconcileCas(Clock clock) {
        String clusterCaCertName = AbstractModel.clusterCaCertSecretName(reconciliation.name());
        String clusterCaKeyName = AbstractModel.clusterCaKeySecretName(reconciliation.name());
        String clientsCaCertName = KafkaResources.clientsCaCertificateSecretName(reconciliation.name());
        String clientsCaKeyName = KafkaResources.clientsCaKeySecretName(reconciliation.name());

        return secretOperator.listAsync(reconciliation.namespace(), Labels.EMPTY.withStrimziKind(reconciliation.kind()).withStrimziCluster(reconciliation.name()))
                .compose(clusterSecrets -> vertx.executeBlocking(() -> {
                    Secret existingClusterCaCertSecret = null;
                    Secret existingClusterCaKeySecret = null;
                    Secret existingClientsCaCertSecret = null;
                    Secret existingClientsCaKeySecret = null;

                    for (Secret secret : clusterSecrets) {
                        String secretName = secret.getMetadata().getName();
                        if (secretName.equals(clusterCaCertName)) {
                            existingClusterCaCertSecret = secret;
                        } else if (secretName.equals(clusterCaKeyName)) {
                            existingClusterCaKeySecret = secret;
                        } else if (secretName.equals(clientsCaCertName)) {
                            existingClientsCaCertSecret = secret;
                        } else if (secretName.equals(clientsCaKeyName)) {
                            existingClientsCaKeySecret = secret;
                        }
                    }

                    Map<String, Secret> updatedSecrets = new HashMap<>(4);

                    //TODO initialize these, need to deal with Secret being null and either pass null record or extract data and init generation if missing
                    clusterCa = new ClusterCa(reconciliation, certManager, passwordGenerator,
                            existingClusterCaCertSecret != null ? existingClusterCaCertSecret.getData() : null,
                            existingClusterCaCertSecret != null ? Annotations.intAnnotation(existingClusterCaCertSecret, Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION, INIT_GENERATION) : INIT_GENERATION,
                            existingClusterCaKeySecret != null ? existingClusterCaKeySecret.getData() : null,
                            existingClusterCaKeySecret != null ? Annotations.intAnnotation(existingClusterCaKeySecret, Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION, INIT_GENERATION) : INIT_GENERATION,
                            ModelUtils.getCertificateValidity(clusterCaConfig),
                            ModelUtils.getRenewalDays(clusterCaConfig),
                            clusterCaConfig == null || clusterCaConfig.isGenerateCertificateAuthority(), clusterCaConfig != null ? clusterCaConfig.getCertificateExpirationPolicy() : null);
                    clusterCa.createRenewOrReplace(
                            Util.isMaintenanceTimeWindowsSatisfied(reconciliation, maintenanceWindows, clock.instant()),
                            existingClusterCaCertSecret != null && Annotations.booleanAnnotation(existingClusterCaCertSecret, Annotations.ANNO_STRIMZI_IO_FORCE_RENEW, false),
                            existingClusterCaKeySecret != null && Annotations.booleanAnnotation(existingClusterCaKeySecret, Annotations.ANNO_STRIMZI_IO_FORCE_REPLACE, false));

                    clusterCaCertSecret = CertUtils.createCaCertSecret(clusterCa, reconciliation.namespace(), clusterCaCertName, existingClusterCaCertSecret,
                            caLabels, clusterCaCertLabels, clusterCaCertAnnotations, clusterCaConfig != null && !clusterCaConfig.isGenerateSecretOwnerReference() ? null : ownerRef);
                    updatedSecrets.put(clusterCaCertName, clusterCaCertSecret);
                    updatedSecrets.put(clusterCaKeyName,
                            CertUtils.createCaKeySecret(clusterCa, reconciliation.namespace(), clusterCaKeyName, existingClusterCaKeySecret,
                                    caLabels, clusterCaConfig != null && !clusterCaConfig.isGenerateSecretOwnerReference() ? null : ownerRef)
                    );
                    clientsCa = new ClientsCa(reconciliation, certManager, passwordGenerator,
                            existingClientsCaCertSecret != null ? existingClientsCaCertSecret.getData() : null,
                            existingClientsCaCertSecret != null ? Annotations.intAnnotation(existingClientsCaCertSecret, Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION, INIT_GENERATION) : INIT_GENERATION,
                            existingClientsCaKeySecret != null ? existingClientsCaKeySecret.getData() : null,
                            existingClientsCaKeySecret != null ? Annotations.intAnnotation(existingClientsCaKeySecret, Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION, INIT_GENERATION) : INIT_GENERATION,
                            ModelUtils.getCertificateValidity(clientsCaConfig),
                            ModelUtils.getRenewalDays(clientsCaConfig),
                            clientsCaConfig == null || clientsCaConfig.isGenerateCertificateAuthority(),
                            clientsCaConfig != null ? clientsCaConfig.getCertificateExpirationPolicy() : null);
                    clientsCa.createRenewOrReplace(
                            Util.isMaintenanceTimeWindowsSatisfied(reconciliation, maintenanceWindows, clock.instant()),
                            existingClientsCaCertSecret != null && Annotations.booleanAnnotation(existingClientsCaCertSecret, Annotations.ANNO_STRIMZI_IO_FORCE_RENEW, false),
                            existingClientsCaKeySecret != null && Annotations.booleanAnnotation(existingClientsCaKeySecret, Annotations.ANNO_STRIMZI_IO_FORCE_REPLACE, false));

                    updatedSecrets.put(clientsCaCertName,
                            CertUtils.createCaCertSecret(clientsCa, reconciliation.namespace(), clientsCaCertName, existingClientsCaCertSecret,
                                    caLabels, Map.of(), Map.of(), clientsCaConfig != null && !clientsCaConfig.isGenerateSecretOwnerReference() ? null : ownerRef)
                    );
                    updatedSecrets.put(clientsCaKeyName,
                            CertUtils.createCaKeySecret(clientsCa, reconciliation.namespace(), clientsCaKeyName, existingClientsCaKeySecret,
                                    caLabels, clientsCaConfig != null && !clientsCaConfig.isGenerateSecretOwnerReference() ? null : ownerRef)
                    );

                    return updatedSecrets;
                }))
                .compose(secretMap -> {
                    Promise<Void> caUpdatePromise = Promise.promise();

                    List<Future<ReconcileResult<Secret>>> secretReconciliations = new ArrayList<>(2);

                    if (clusterCaConfig == null || clusterCaConfig.isGenerateCertificateAuthority())   {
                        //TODO add new methods to create the Secret keeping the annotations and labels etc in this class and not bleeding them into Ca
                        LOGGER.infoCr(Reconciliation.DUMMY_RECONCILIATION, "KATE: entry CaReconciler");
                        String ca_crt = secretMap.get(clusterCaCertName).getData().get("ca.crt");
                        String ca_123_crt = secretMap.get(clusterCaCertName).getData().entrySet().stream().filter(entry -> entry.getKey().startsWith("ca-")).map(Map.Entry::getValue).findFirst().orElse("NOT_FOUND");
                        LOGGER.infoCr(Reconciliation.DUMMY_RECONCILIATION, "    ca-123.crt present? " + !ca_123_crt.equals("NOT_FOUND"));
                        LOGGER.infoCr(Reconciliation.DUMMY_RECONCILIATION, "    ca.crt == ca-123.crt? " + ca_crt.equals(ca_123_crt));
                        LOGGER.infoCr(Reconciliation.DUMMY_RECONCILIATION, "KATE: exit CaReconciler");

                        Future<ReconcileResult<Secret>> clusterSecretReconciliation = secretOperator.reconcile(reconciliation, reconciliation.namespace(), clusterCaCertName, secretMap.get(clusterCaCertName))
                                .compose(ignored -> secretOperator.reconcile(reconciliation, reconciliation.namespace(), clusterCaKeyName, secretMap.get(clusterCaKeyName)));
                        secretReconciliations.add(clusterSecretReconciliation);
                    }

                    if (clientsCaConfig == null || clientsCaConfig.isGenerateCertificateAuthority())   {
                        Future<ReconcileResult<Secret>> clientsSecretReconciliation = secretOperator.reconcile(reconciliation, reconciliation.namespace(), clientsCaCertName, secretMap.get(clientsCaCertName))
                                .compose(ignored -> secretOperator.reconcile(reconciliation, reconciliation.namespace(), clientsCaKeyName, secretMap.get(clientsCaKeyName)));
                        secretReconciliations.add(clientsSecretReconciliation);
                    }

                    Future.join(secretReconciliations).onComplete(res -> {
                        if (res.succeeded())    {
                            caUpdatePromise.complete();
                        } else {
                            caUpdatePromise.fail(res.cause());
                        }
                    });

                    return caUpdatePromise.future();
                });
    }

    /**
     * Asynchronously reconciles the cluster operator Secret used to connect to Kafka and ZooKeeper.
     * This only updates the Secret if the latest Cluster CA is fully trusted across the cluster, otherwise if
     * something goes wrong during reconciliation when the next loop starts it won't be able to connect to
     * Kafka and ZooKeeper anymore.
     *
     * @param clock    The clock for supplying the reconciler with the time instant of each reconciliation cycle.
     *                 That time is used for checking maintenance windows
     */
    Future<Void> reconcileClusterOperatorSecret(Clock clock) {
        return secretOperator.getAsync(reconciliation.namespace(), KafkaResources.clusterOperatorCertsSecretName(reconciliation.name()))
                .compose(oldSecret -> {
                    coSecret = oldSecret;
                    if (oldSecret != null && this.isClusterCaNeedFullTrust) {
                        LOGGER.warnCr(reconciliation, "Cluster CA needs to be fully trusted across the cluster, keeping current CO secret and certs");
                        return Future.succeededFuture();
                    }

                    coSecret = CertUtils.buildTrustedCertificateSecret(
                            reconciliation,
                            clusterCa,
                            coSecret,
                            reconciliation.namespace(),
                            KafkaResources.clusterOperatorCertsSecretName(reconciliation.name()),
                            "cluster-operator",
                            "cluster-operator",
                            clusterOperatorSecretLabels,
                            ownerRef,
                            Util.isMaintenanceTimeWindowsSatisfied(reconciliation, maintenanceWindows, clock.instant())
                    );

                    return secretOperator.reconcile(reconciliation, reconciliation.namespace(), KafkaResources.clusterOperatorCertsSecretName(reconciliation.name()), coSecret)
                            .map((Void) null);
                });
    }

    /**
     * Maybe perform a rolling update of the cluster to update the CA certificates in component truststores.
     * This is only necessary when the Cluster CA certificate has changed due to a new CA key.
     * It is not necessary when the CA certificate is renewed while retaining the existing key.
     *
     * If Strimzi did not replace the CA key during the current reconciliation, {@code isClusterCaNeedFullTrust} is used to:
     *      * continue from a previous CA key replacement which didn't end successfully (i.e. CO stopped)
     *      * track key replacements when the user is managing the CA
     *
     * @return Future which completes when this step is done, either by rolling the cluster or by deciding
     *         that no rolling is needed.
     */
    Future<Void> maybeRollingUpdateForNewClusterCaKey() {
        if (clusterCa.keyReplaced() || isClusterCaNeedFullTrust) {
            RestartReason restartReason = RestartReason.CLUSTER_CA_CERT_KEY_REPLACED;
            TlsPemIdentity coTlsPemIdentity = new TlsPemIdentity(new PemTrustSet(clusterCaCertSecret), PemAuthIdentity.clusterOperator(coSecret));
            return getZooKeeperReplicas()
                    .compose(replicas -> rollZookeeper(replicas, restartReason, coTlsPemIdentity))
                    .compose(i -> patchClusterCaKeyGenerationAndReturnNodes())
                    .compose(nodes -> rollKafkaBrokers(nodes, RestartReasons.of(restartReason), coTlsPemIdentity))
                    .compose(i -> rollDeploymentIfExists(KafkaResources.entityOperatorDeploymentName(reconciliation.name()), restartReason))
                    .compose(i -> rollDeploymentIfExists(KafkaExporterResources.componentName(reconciliation.name()), restartReason))
                    .compose(i -> rollDeploymentIfExists(CruiseControlResources.componentName(reconciliation.name()), restartReason));
        } else {
            return Future.succeededFuture();
        }
    }

    /**
     * Gather the Kafka related components pods for checking Cluster CA key trust and Cluster CA certificate usage to sign servers certificate.
     *
     * Verify that all the pods are already trusting the new CA certificate signed by a new CA key.
     * It checks each pod's CA key generation, compared with the new CA key generation.
     * When the trusting phase is not completed (i.e. because CO stopped), it needs to be recovered from where it was left.
     *
     * Verify that all pods are already using the new CA certificate to sign server certificates.
     * It checks each pod's CA certificate generation, compared with the new CA certificate generation.
     * When the new CA certificate is used everywhere, the old CA certificate can be removed.
     */
    /* test */ Future<Void> verifyClusterCaFullyTrustedAndUsed() {
        isClusterCaNeedFullTrust = false;
        isClusterCaFullyUsed = true;

        // Building the selector for Kafka related components
        Labels labels =  Labels.forStrimziCluster(reconciliation.name()).withStrimziKind(Kafka.RESOURCE_KIND);

        return podOperator.listAsync(reconciliation.namespace(), labels)
                .compose(pods -> {

                    // still no Pods, a new Kafka cluster is under creation
                    if (pods.isEmpty()) {
                        isClusterCaFullyUsed = false;
                        return Future.succeededFuture();
                    }

                    int clusterCaCertGeneration = clusterCa.caCertGeneration();
                    int clusterCaKeyGeneration = clusterCa.caKeyGeneration();

                    LOGGER.debugCr(reconciliation, "Current cluster CA cert generation {}", clusterCaCertGeneration);
                    LOGGER.debugCr(reconciliation, "Current cluster CA key generation {}", clusterCaKeyGeneration);


                    for (Pod pod : pods) {
                        // with "RollingUpdate" strategy on Deployment(s) (i.e. the Cruise Control one),
                        // while the Deployment is reported to be ready, the old pod is still alive but terminating
                        // this condition is for skipping "Terminating" pods for checks on the CA key and old certificates
                        if (pod.getMetadata().getDeletionTimestamp() == null) {
                            int podClusterCaCertGeneration = Annotations.intAnnotation(pod, Ca.ANNO_STRIMZI_IO_CLUSTER_CA_CERT_GENERATION, clusterCaCertGeneration);
                            LOGGER.debugCr(reconciliation, "Pod {} has cluster CA cert generation {}", pod.getMetadata().getName(), podClusterCaCertGeneration);

                            int podClusterCaKeyGeneration = Annotations.intAnnotation(pod, Ca.ANNO_STRIMZI_IO_CLUSTER_CA_KEY_GENERATION, clusterCaKeyGeneration);
                            LOGGER.debugCr(reconciliation, "Pod {} has cluster CA key generation {} compared to the Secret CA key generation {}",
                                    pod.getMetadata().getName(), podClusterCaKeyGeneration, clusterCaKeyGeneration);

                            // only if all Kafka related components pods are updated to the new cluster CA cert generation,
                            // there is the possibility that we should remove the older cluster CA from the Secret and stores
                            if (clusterCaCertGeneration != podClusterCaCertGeneration) {
                                this.isClusterCaFullyUsed = false;
                            }

                            if (clusterCaKeyGeneration != podClusterCaKeyGeneration) {
                                this.isClusterCaNeedFullTrust = true;
                            }

                        } else {
                            LOGGER.debugCr(reconciliation, "Skipping CA key generation check on pod {}, it's terminating", pod.getMetadata().getName());
                        }

                        if (isClusterCaNeedFullTrust) {
                            LOGGER.debugCr(reconciliation, "The new Cluster CA is not yet trusted by all pods");
                        }
                        if (!isClusterCaFullyUsed) {
                            LOGGER.debugCr(reconciliation, "The old Cluster CA is still used by some server certificates and cannot be removed");
                        }
                    }
                    return Future.succeededFuture();
                });
    }

    /**
     * If we need to roll the ZooKeeper cluster to roll out the trust to a new CA certificate when a CA private key is
     * being replaced, we need to know what the current number of ZooKeeper nodes is. Getting it from the Kafka custom
     * resource might not be good enough if a scale-up /scale-down is happening at the same time. So we get the
     * StrimziPodSet and find out the correct number of ZooKeeper nodes from it.
     *
     * @return  Current number of ZooKeeper replicas
     */
    /* test */ Future<Integer> getZooKeeperReplicas() {
        return strimziPodSetOperator.getAsync(reconciliation.namespace(), KafkaResources.zookeeperComponentName(reconciliation.name()))
                .compose(podSet -> {
                    if (podSet != null
                            && podSet.getSpec() != null
                            && podSet.getSpec().getPods() != null) {
                        return Future.succeededFuture(podSet.getSpec().getPods().size());
                    } else {
                        return Future.succeededFuture(0);
                    }
                });
    }

    /**
     * Rolls the ZooKeeper cluster to trust the new Cluster CA private key.
     *
     * @param replicas              Current number of ZooKeeper replicas
     * @param podRestartReason      Reason to restart the pods
     * @param coTlsPemIdentity      Trust set and identity for TLS client authentication for connecting to ZooKeeper
     *
     * @return  Future which completes when the ZooKeeper cluster has been rolled.
     */
    /* test */ Future<Void> rollZookeeper(int replicas, RestartReason podRestartReason, TlsPemIdentity coTlsPemIdentity) {
        Labels zkSelectorLabels = Labels.EMPTY
                .withStrimziKind(reconciliation.kind())
                .withStrimziCluster(reconciliation.name())
                .withStrimziName(KafkaResources.zookeeperComponentName(reconciliation.name()));

        Function<Pod, List<String>> rollZkPodAndLogReason = pod -> {
            List<String> reason = List.of(podRestartReason.getDefaultNote());
            LOGGER.debugCr(reconciliation, "Rolling Pod {} to {}", pod.getMetadata().getName(), reason);
            return reason;
        };
        return new ZooKeeperRoller(podOperator, zookeeperLeaderFinder, operationTimeoutMs)
                .maybeRollingUpdate(reconciliation, replicas, zkSelectorLabels, rollZkPodAndLogReason, coTlsPemIdentity);
    }

    /**
     * Patches the Kafka StrimziPodSets to update the Cluster CA key generation annotation and returns the nodes.
     *
     * @return Future containing the set of Kafka nodes which completes when the StrimziPodSets have been patched.
     */
    /* test */ Future<Set<NodeRef>> patchClusterCaKeyGenerationAndReturnNodes() {
        Labels selectorLabels = Labels.EMPTY
                .withStrimziKind(reconciliation.kind())
                .withStrimziCluster(reconciliation.name())
                .withStrimziName(KafkaResources.kafkaComponentName(reconciliation.name()));

        return strimziPodSetOperator.listAsync(reconciliation.namespace(), selectorLabels)
                .compose(podSets -> {
                    if (podSets != null) {
                        List<StrimziPodSet> updatedPodSets = podSets
                                .stream()
                                .map(podSet -> WorkloadUtils.patchAnnotations(
                                        podSet,
                                        Map.of(Ca.ANNO_STRIMZI_IO_CLUSTER_CA_KEY_GENERATION, String.valueOf(clusterCa.caKeyGeneration()))
                                )).toList();
                        return strimziPodSetOperator.batchReconcile(reconciliation, reconciliation.namespace(), updatedPodSets, selectorLabels)
                                .map(i -> updatedPodSets.stream().flatMap(podSet -> ReconcilerUtils.nodesFromPodSet(podSet).stream())
                                .collect(Collectors.toSet()));
                    } else {
                        return Future.succeededFuture(Set.of());
                    }
                });
    }

    /* test */ Future<Void> rollKafkaBrokers(Set<NodeRef> nodes, RestartReasons podRollReasons, TlsPemIdentity coTlsPemIdentity) {
        return createKafkaRoller(nodes, coTlsPemIdentity).rollingRestart(pod -> {
            int clusterCaKeyGeneration = clusterCa.caKeyGeneration();
            int podClusterCaKeyGeneration = Annotations.intAnnotation(pod, Ca.ANNO_STRIMZI_IO_CLUSTER_CA_KEY_GENERATION, clusterCaKeyGeneration);
            if (clusterCaKeyGeneration == podClusterCaKeyGeneration) {
                LOGGER.debugCr(reconciliation, "Not rolling Pod {} since the Cluster CA cert key generation is correct.", pod.getMetadata().getName());
                return RestartReasons.empty();
            } else {
                LOGGER.debugCr(reconciliation, "Rolling Pod {} due to {}", pod.getMetadata().getName(), podRollReasons.getReasons());
                return podRollReasons;
            }
        });
    }

    /* test */ KafkaRoller createKafkaRoller(Set<NodeRef> nodes, TlsPemIdentity coTlsPemIdentity) {
        return new KafkaRoller(reconciliation,
                vertx,
                podOperator,
                1_000,
                operationTimeoutMs,
                () -> new BackOff(250, 2, 10),
                nodes,
                coTlsPemIdentity,
                adminClientProvider,
                kafkaAgentClientProvider,
                brokerId -> null,
                null,
                null,
                false,
                eventPublisher);
    }

    /**
     * Rolls deployments when they exist. This method is used by the CA renewal to roll deployments.
     *
     * @param deploymentName    Name of the deployment which should be rolled if it exists
     * @param reason            Reason for which it is being rolled
     *
     * @return  Succeeded future if it succeeded, failed otherwise.
     */
    /* test */ Future<Void> rollDeploymentIfExists(String deploymentName, RestartReason reason)  {
        return deploymentOperator.getAsync(reconciliation.namespace(), deploymentName)
                .compose(dep -> {
                    if (dep != null) {
                        LOGGER.infoCr(reconciliation, "Rolling Deployment {} due to {}", deploymentName, reason.getDefaultNote());
                        return deploymentOperator.singlePodDeploymentRollingUpdate(reconciliation, reconciliation.namespace(), deploymentName, operationTimeoutMs);
                    } else {
                        return Future.succeededFuture();
                    }
                });
    }

    /**
     * Remove older cluster CA certificates if present in the corresponding Secret after a renewal by replacing the
     * corresponding CA private key.
     */
    /* test */ Future<Void> maybeRemoveOldClusterCaCertificates() {
        // if the new CA certificate is used to sign all server certificates
        if (isClusterCaFullyUsed) {
            LOGGER.debugCr(reconciliation, "Maybe there are old cluster CA certificates to remove");
            clusterCa.maybeDeleteOldCerts();
            clusterCaCertSecret = new SecretBuilder(clusterCaCertSecret)
                    .withData(clusterCa.caCertData())
                    .build();
            if (clusterCa.certsRemoved()) {
                return secretOperator.reconcile(reconciliation, reconciliation.namespace(), AbstractModel.clusterCaCertSecretName(reconciliation.name()), clusterCaCertSecret)
                        .map((Void) null);
            } else {
                return Future.succeededFuture();
            }
        } else {
            return Future.succeededFuture();
        }
    }

    /**
     * Helper class to pass both Cluster and Clients CA as a result of the reconciliation
     *
     * @param clusterCa     The Cluster CA instance
     * @param clientsCa     The Clients CA instance
     */
    public record CaReconciliationResult(ClusterCa clusterCa, ClientsCa clientsCa) { }
}
