/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.assembly;

import io.fabric8.kubernetes.api.model.OwnerReferenceBuilder;
import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.api.kafka.model.common.CertificateAuthority;
import io.strimzi.api.kafka.model.common.certmanager.CertManager;
import io.strimzi.api.kafka.model.common.certmanager.IssuerRef;
import io.strimzi.api.kafka.model.kafka.Kafka;
import io.strimzi.api.kafka.model.kafka.KafkaResources;
import io.strimzi.operator.cluster.model.AbstractModel;
import io.strimzi.operator.cluster.model.CertUtils;
import io.strimzi.operator.cluster.operator.resource.kubernetes.SecretOperator;
import io.strimzi.operator.common.Annotations;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.Util;
import io.strimzi.operator.common.model.Ca;
import io.strimzi.operator.common.model.CaConfig;
import io.strimzi.operator.common.model.CaUtils;
import io.strimzi.operator.common.model.CertManagerCa;
import io.strimzi.operator.common.model.InvalidResourceException;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import static io.strimzi.operator.common.model.Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION;
import static io.strimzi.operator.common.model.Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION;
import static io.strimzi.operator.common.model.Ca.CA_CRT;
import static io.strimzi.operator.common.model.Ca.DATE_TIME_FORMATTER;
import static io.strimzi.operator.common.model.Ca.INIT_GENERATION;

public class CertManagerCaSecretProvider extends CaSecretProvider {
    private final SecretOperator secretOperator;
    private final Secret cluserOperatorSecret;
    private final CertManager certManagerConfig;
    private final CertificateAuthority certificateAuthority;

    public CertManagerCaSecretProvider(Reconciliation reconciliation, Ca.CaRole caRole, CaConfig caConfig, Kafka kafkaCr,
                                       Secret existingCaCertSecret, Secret existingCaKeySecret, SecretOperator secretOperator,
                                       Secret clusterOperatorSecret, CertManager certManagerConfig) {
        super(reconciliation, caRole, caConfig, kafkaCr, existingCaCertSecret, existingCaKeySecret);
        this.secretOperator = secretOperator;
        this.cluserOperatorSecret = clusterOperatorSecret;
        this.certManagerConfig = certManagerConfig;
        this.certificateAuthority = switch (caRole) {
            case CLUSTER_CA -> kafkaCr.getSpec().getClusterCa();
            case CLIENTS_CA -> kafkaCr.getSpec().getClientsCa();
        };
    }

    @Override
    public CompletionStage<Ca> createCa() {
        return getCertManagerCaCert()
                .thenCompose(newCertManagerCertSecret -> {
                    caCertSecret = updateOrCreateCaSecret(newCertManagerCertSecret);
                    return secretOperator.reconcile(reconciliation, reconciliation.namespace(), caCertSecret.getMetadata().getName(), caCertSecret).toCompletionStage();
                }).thenCompose(result -> {
                    IssuerRef issuerRef = certificateAuthority != null && certificateAuthority.getCertManager() != null
                            ? certificateAuthority.getCertManager().getIssuerRef() : null;
                    ca = new CertManagerCa(reconciliation, Ca.CaRole.CLUSTER_CA,
                            existingCaCertSecret,
                            existingCaKeySecret,
                            caConfig,
                            null,
                            null,
                            caConfig.isGenerateSecretOwnerRef() ? new OwnerReferenceBuilder()
                                    .withApiVersion(kafkaCr.getApiVersion())
                                    .withKind(kafkaCr.getKind())
                                    .withName(kafkaCr.getMetadata().getName())
                                    .withUid(kafkaCr.getMetadata().getUid())
                                    .withBlockOwnerDeletion(true)
                                    .withController(false)
                                    .build()
                                    : null,
                            null,
                            issuerRef);
                    return CompletableFuture.completedFuture(ca);
                });
    }

    @Override
    public CompletionStage<Secret> reconcileCaSecrets() {
        //TODO
        return CompletableFuture.completedStage(null);
    }

    private CompletionStage<String> getCertManagerCaCert() {
        String certManagerSecretName = certManagerConfig.getCaCert().getSecretName();
        String certManagerSecretKey = certManagerConfig.getCaCert().getCertificate();
        return secretOperator.getAsync(reconciliation.namespace(), certManagerSecretName).toCompletionStage()
                .thenApply(secret -> {
                    if (secret == null) {
                        throw new InvalidResourceException("CA public certificate Secret " + certManagerSecretName + " missing.");
                    } else if (secret.getData().get(certManagerSecretKey) == null) {
                        throw new InvalidResourceException("CA public certificate Secret " + certManagerSecretName + " missing key " + certManagerSecretKey);
                    } else {
                        return secret.getData().get(certManagerSecretKey);
                    }
                });
    }

    private Secret updateOrCreateCaSecret(String newCertManagerCert) {
        Ca.RenewalType renewalType = shouldRenewOrReplace(newCertManagerCert);
        int caCertGeneration;
        int caKeyGeneration;
        Map<String, String> caCertData;
        switch (renewalType) {
            case NOOP -> {
                caCertData = existingCaCertSecret.getData();
                caCertGeneration = Annotations.intAnnotation(caCertSecret, ANNO_STRIMZI_IO_CA_CERT_GENERATION, INIT_GENERATION);
                caKeyGeneration = Annotations.intAnnotation(caCertSecret, ANNO_STRIMZI_IO_CA_KEY_GENERATION, INIT_GENERATION);
            }
            case CREATE -> {
                // No data, so we add it
                caCertData = new HashMap<>();
                caCertData.put(CA_CRT, Util.encodeToBase64(newCertManagerCert));
                caCertGeneration = INIT_GENERATION;
                caKeyGeneration = INIT_GENERATION;
            }
            case RENEW_CERT -> {
                caCertData = new HashMap<>();
                caCertData.put(CA_CRT, Util.encodeToBase64(newCertManagerCert));
                caCertGeneration = Annotations.intAnnotation(caCertSecret, ANNO_STRIMZI_IO_CA_CERT_GENERATION, INIT_GENERATION) + 1;
                caKeyGeneration = Annotations.intAnnotation(caCertSecret, ANNO_STRIMZI_IO_CA_KEY_GENERATION, INIT_GENERATION);
            }
            case REPLACE_KEY -> {
                X509Certificate existingCert = CaUtils.cert(existingCaCertSecret, CA_CRT);
                String notAfterDate = DATE_TIME_FORMATTER.format(existingCert.getNotAfter().toInstant().atZone(ZoneId.of("Z")));
                caCertData = new HashMap<>();
                caCertData.put(Ca.SecretEntry.CRT.asKey("ca-" + notAfterDate), existingCaCertSecret.getData().get(CA_CRT));
                caCertData.put(CA_CRT, Util.encodeToBase64(newCertManagerCert));
                caCertGeneration = Annotations.intAnnotation(caCertSecret, ANNO_STRIMZI_IO_CA_CERT_GENERATION, INIT_GENERATION) + 1;
                caKeyGeneration = Annotations.intAnnotation(caCertSecret, ANNO_STRIMZI_IO_CA_KEY_GENERATION, INIT_GENERATION) + 1;
            }
            default -> throw new RuntimeException("Unsupported renewal type: " + renewalType);
        }
        return createCertManagerCaCertSecret(caRole, caCertData,
                caCertGeneration, caKeyGeneration);
    }

    private Ca.RenewalType shouldRenewOrReplace(String newCertManagerCert) {
        if (existingCaCertSecret.getData().isEmpty()) {
            return Ca.RenewalType.CREATE;
        }

        X509Certificate x509CaCert;
        String newCaCertHash;
        try {
            x509CaCert = CaUtils.x509Certificate(Util.decodeBytesFromBase64(newCertManagerCert));
            newCaCertHash = String.format("%040x", new BigInteger(1, Util.sha1Digest(x509CaCert.getEncoded())));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        String existingCaCertHash = Annotations.stringAnnotation(existingCaCertSecret, Annotations.ANNO_STRIMZI_SERVER_CERT_HASH, "");
        X509Certificate endEntityCertificate = CaUtils.cert(cluserOperatorSecret, "cluster-operator.crt");
        if (!existingCaCertHash.equals(newCaCertHash)) {
            if (endEntityCertificate == null) {
                // Cluster operator certificate is missing, so no cert path validation to perform
                // Don't update - wait for operator cert to be available
                LOGGER.warnCr(reconciliation, "Cluster CA cert has changed, but operator certificate is missing - cannot determine if key changed. Will retry in next reconciliation.");
                return  Ca.RenewalType.NOOP;
            }
            if (CaUtils.certIsTrusted(reconciliation, List.of(endEntityCertificate), x509CaCert)) {
                // No key replacement
                return Ca.RenewalType.RENEW_CERT;
            } else {
                // key replacement
                return Ca.RenewalType.REPLACE_KEY;
            }
        } else {
            return Ca.RenewalType.NOOP;
        }
    }

    private Secret createCertManagerCaCertSecret(Ca.CaRole caRole, Map<String, String> caCertData, int caCertGeneration, int caKeyGeneration) {
        Map<String, String> certAnnotations = new HashMap<>(2);

        try {
            certAnnotations.put(Annotations.ANNO_STRIMZI_SERVER_CERT_HASH, CertUtils.getCertificateThumbprint(CaUtils.x509Certificate(Util.decodeBytesFromBase64(caCertData.get(CA_CRT)))));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        String secretName = switch (caRole) {
            case CLUSTER_CA -> {
                certAnnotations.put(ANNO_STRIMZI_IO_CA_KEY_GENERATION, String.valueOf(caKeyGeneration));
                yield AbstractModel.clusterCaCertSecretName(reconciliation.name());
            }
            case CLIENTS_CA -> KafkaResources.clientsCaCertificateSecretName(reconciliation.name());
        };

        return createCaCertSecret(caRole, secretName, caCertData, certAnnotations, caCertGeneration);
    }
}
