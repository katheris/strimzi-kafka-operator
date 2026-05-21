/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.api.kafka.model.kafka.KafkaResources;
import io.strimzi.api.kafka.model.kafka.cruisecontrol.CruiseControlResources;
import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.CertManager;
import io.strimzi.certs.IpAndDnsValidation;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.model.Ca;
import io.strimzi.operator.common.model.CaConfig;
import io.strimzi.operator.common.model.PasswordGenerator;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Represents the Cluster CA
 */
public class ClusterCa extends Ca {
    /**
     * Constructor
     *
     * @param reconciliation        Reconciliation marker
     * @param certManager           Certificate manager instance
     * @param passwordGenerator     Password generator instance
     * @param caCertSecret          Name of the CA public key secret
     * @param caKeySecret           Name of the CA private key secret
     */
    public ClusterCa(Reconciliation reconciliation, CertManager certManager, PasswordGenerator passwordGenerator, Secret caCertSecret, Secret caKeySecret) {
        this(reconciliation, certManager, passwordGenerator, caCertSecret, caKeySecret, CaConfig.createDefault());
    }

    /**
     * Constructor
     *
     * @param reconciliation        Reconciliation marker
     * @param certManager           Certificate manager instance
     * @param passwordGenerator     Password generator instance
     * @param clusterCaCert         Secret with the public key
     * @param clusterCaKey          Secret with the private key
     * @param caConfig              Certificate Authority configuration
     */
    public ClusterCa(Reconciliation reconciliation,
                     CertManager certManager,
                     PasswordGenerator passwordGenerator,
                     Secret clusterCaCert,
                     Secret clusterCaKey,
                     CaConfig caConfig) {
        super(reconciliation, certManager, passwordGenerator,
                "cluster-ca",
                clusterCaCert,
                clusterCaKey,
                caConfig);
    }

    @Override
    public String toString() {
        return "cluster-ca";
    }

    @Override
    public String caName() {
        return "Cluster CA";
    }

    /**
     * Prepares the Cruise Control certificate. It either reuses the existing certificate, renews it or generates new
     * certificate if needed.
     *
     * @param namespace                             Namespace of the Kafka cluster
     * @param clusterName                           Name of the Kafka cluster
     * @param existingCertificate                   Existing certificate (or null if they do not exist yet)
     * @param isMaintenanceTimeWindowsSatisfied     Flag indicating whether we can do maintenance tasks or not
     *
     * @return Map with CertAndKey object containing the public and private key
     *
     * @throws IOException IOException is thrown when it is raised while working with the certificates
     */
    protected Map<String, CertAndKey> generateCcCerts(
            String namespace,
            String clusterName,
            CertAndKey existingCertificate,
            boolean isMaintenanceTimeWindowsSatisfied
    ) throws IOException {
        DnsNameGenerator ccDnsGenerator = DnsNameGenerator.of(namespace, CruiseControlResources.serviceName(clusterName));

        Subject.Builder subject = new Subject.Builder()
                .withOrganizationName("io.strimzi")
                .withCommonName(CruiseControlResources.serviceName(clusterName));

        subject.addDnsName(CruiseControlResources.serviceName(clusterName));
        subject.addDnsName(String.format("%s.%s", CruiseControlResources.serviceName(clusterName), namespace));
        subject.addDnsName(ccDnsGenerator.serviceDnsNameWithoutClusterDomain());
        subject.addDnsName(ccDnsGenerator.serviceDnsName());
        subject.addDnsName(CruiseControlResources.serviceName(clusterName));
        subject.addDnsName("localhost");

        Map<String, Subject> subjectMap = Map.of(CruiseControl.COMPONENT_TYPE, subject.build());

        LOGGER.debugCr(reconciliation, "{}: Reconciling Cruise Control certificates", this);
        return maybeCopyOrGenerateServerCerts(
            reconciliation,
            subjectMap,
            existingCertificate == null ? Map.of() : Map.of(CruiseControl.COMPONENT_TYPE, existingCertificate),
            isMaintenanceTimeWindowsSatisfied,
            false
        );
    }

    /**
     * Prepares the Kafka broker certificates. It either reuses the existing certificates, renews them or generates new
     * certificates if needed.
     *
     * @param namespace                             Namespace of the Kafka cluster
     * @param clusterName                           Name of the Kafka cluster
     * @param existingCertificates                  Existing certificates (or null if they do not exist yet)
     * @param nodes                                 Nodes that are part of the Kafka cluster
     * @param externalBootstrapAddresses            List of external bootstrap addresses (used for certificate SANs)
     * @param externalAddresses                     Map with external listener addresses for the different nodes (used for certificate SANs)
     * @param isMaintenanceTimeWindowsSatisfied     Flag indicating whether we can do maintenance tasks or not
     *
     * @return Map with CertAndKey objects containing the public and private keys for the different brokers
     *
     * @throws IOException IOException is thrown when it is raised while working with the certificates
     */
    protected Map<String, CertAndKey> generateBrokerCerts(
            String namespace,
            String clusterName,
            Map<String, CertAndKey> existingCertificates,
            Set<NodeRef> nodes,
            Set<String> externalBootstrapAddresses,
            Map<Integer, Set<String>> externalAddresses,
            boolean isMaintenanceTimeWindowsSatisfied
    ) throws IOException {
        Map<String, Subject> subjectMap = new HashMap<>();
        List<String> bootstrapDnsNames = ModelUtils.generateAllServiceDnsNames(namespace, KafkaResources.bootstrapServiceName(clusterName));
        List<String> brokersDnsNames = ModelUtils.generateAllServiceDnsNames(namespace, KafkaResources.brokersServiceName(clusterName));
        for (NodeRef node : nodes) {
            Subject.Builder subject = new Subject.Builder()
                    .withOrganizationName("io.strimzi")
                    .withCommonName(KafkaResources.kafkaComponentName(clusterName));

            subject.addDnsNames(bootstrapDnsNames);
            subject.addDnsNames(brokersDnsNames);

            subject.addDnsName(DnsNameGenerator.podDnsName(namespace, KafkaResources.brokersServiceName(clusterName), node.podName()));
            subject.addDnsName(DnsNameGenerator.podDnsNameWithoutClusterDomain(namespace, KafkaResources.brokersServiceName(clusterName), node.podName()));

            // Controller-only nodes do not have the SANs for external listeners.
            // That helps us to avoid unnecessary rolling updates when the SANs change
            if (node.broker())    {
                if (externalBootstrapAddresses != null) {
                    for (String dnsName : externalBootstrapAddresses) {
                        if (IpAndDnsValidation.isValidIpAddress(dnsName)) {
                            subject.addIpAddress(dnsName);
                        } else {
                            subject.addDnsName(dnsName);
                        }
                    }
                }

                if (externalAddresses.get(node.nodeId()) != null) {
                    for (String dnsName : externalAddresses.get(node.nodeId())) {
                        if (IpAndDnsValidation.isValidIpAddress(dnsName)) {
                            subject.addIpAddress(dnsName);
                        } else {
                            subject.addDnsName(dnsName);
                        }
                    }
                }
            }
            subjectMap.put(clusterName, subject.build());
        }

        LOGGER.debugCr(reconciliation, "{}: Reconciling kafka broker certificates", this);

        return maybeCopyOrGenerateServerCerts(
            reconciliation,
            subjectMap,
            existingCertificates,
            isMaintenanceTimeWindowsSatisfied,
            true
        );
    }

    @Override
    protected String caCertGenerationAnnotation() {
        return ANNO_STRIMZI_IO_CLUSTER_CA_CERT_GENERATION;
    }

    /**
     * Checks if the CA chain is contained at the end of the certificate.
     *
     * @param cert      The server certificate as a byte array
     * @param caChain   The CA chain as a byte array
     *
     * @return  True if the CA chain is included at the end of the certificate, false otherwise.
     */
    //Tested by ClusterCaTest
    /* test */ static boolean includesCaChain(byte[] cert, byte[] caChain) {
        if (cert == null || caChain == null || cert.length < caChain.length) {
            // The CA chain is definitely not included
            return false;
        } else {
            return Arrays.equals(Arrays.copyOfRange(cert, cert.length - caChain.length, cert.length), caChain);
        }
    }
}
